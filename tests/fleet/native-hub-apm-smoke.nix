# tests/fleet/native-hub-apm-smoke.nix -- Native Hub/APM production smoke test.
#
# Three independent AOS machines exercise the production boundary:
#
#   hub       native aos-hub systemd service, SQLite, local-fs placement
#   publisher APR authoring plus the managed Hub publication transaction
#   consumer  APM install/update/rollback and a system-scope OS upgrade
#
# The Hub is initialized without `--dev` or `--seed`. Its topology is created
# through authenticated, reviewed `aos hub` plans. Host-built fixture closures
# reach only the publisher through a read-only 9p store mount; they are absent
# from the consumer until APM downloads them from the Hub.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  upgradeToplevel = fixture.consumerUpgradeSystem.config.system.build.toplevel;
  upgradeImage = fixture.consumerUpgradeSystem.config.system.build.image.raw;
  upgradeImageDisk = fixture.consumerUpgradeSystem.config.system.build.imageArtifacts.raw.disk;
  upgradeImageInfo = fixture.consumerUpgradeSystem.config.system.build.imageArtifacts.raw.info;
  upgradeUki = fixture.consumerUpgradeSystem.config.system.build.uki;
  documentationBaseLib = fixture.consumerSystem.config.aos.config.evalAtBoot.baseLib;
  publisherClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = [
      fixture.toolV1
      fixture.toolV2
      upgradeToplevel
      upgradeImage
      upgradeImageDisk
      upgradeImageInfo
      upgradeUki
      pkgs.nginx
      pkgs.nginx.config
      pkgs.nginx.expose
      documentationBaseLib
      pkgs.binutils
      pkgs.sbsigntools
      pkgs.systemd
    ];
    pname = "native-hub-publisher-closure-info";
  };
in {
  name = "native-hub-apm-smoke";
  # Fresh native-Hub publication intentionally transfers the complete raw
  # disk plus its A/B update payload directory. Slow KVM or 9p hosts can spend
  # well over twenty minutes in that one production-sized transaction before
  # the reboot/rollback checks begin.
  timeout = 5400;

  machines = {
    consumer = {
      system = fixture.consumerSystem;
      bootMode = "image";
      imageDiskMiB = 12288;
      varProvisioning = "repart";
    };
    hub = {
      system = fixture.hubSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      varProvisioning = "repart";
    };
    publisher = {
      system = fixture.publisherSystem;
      bootMode = "image";
      hostStoreMount = true;
      # A production release host retains its APR checkout/cache while staging
      # another complete upload tree. Keep both on the writable data disk and
      # leave headroom for a full AOS closure plus its A/B image payload.
      imageDiskMiB = 32768;
      # Nix's canonical NAR writer can transiently exceed 6 GiB while hashing
      # the production-sized raw disk and A/B payload imported over 9p.
      memoryMiB = 8192;
      varProvisioning = "repart";
    };
  };

  testScript =
    # python
    ''
      import json
      import shlex
      import textwrap

      HUB = "${fixture.hubUrl}"
      REGISTRY = "${fixture.registryUrl}"
      AOS = "${pkgs.aos}/bin/aos"
      APM = "${pkgs.aos}/bin/apm"
      APR = "${pkgs.aos}/bin/apr"
      JQ = "${pkgs.jq}/bin/jq"
      CURL = "${pkgs.curl}/bin/curl"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      FINDMNT = "${pkgs.util-linux}/bin/findmnt"
      TOOL_V1 = "${fixture.toolV1}"
      HELPER_V1 = "${fixture.helperV1}"
      TOOL_V2 = "${fixture.toolV2}"
      HELPER_V2 = "${fixture.helperV2}"
      NGINX = "${pkgs.nginx}"
      NGINX_CONFIG = "${pkgs.nginx.config}"
      NGINX_EXPOSE = "${pkgs.nginx.expose}"
      DOCUMENTATION_BASE_LIB = "${documentationBaseLib}"
      UPGRADE_TOPLEVEL = "${upgradeToplevel}"
      UPGRADE_IMAGE = "${upgradeImage}"
      UPGRADE_IMAGE_DISK = "${upgradeImageDisk}"
      UPGRADE_IMAGE_INFO = "${upgradeImageInfo}"
      UPGRADE_UKI = "${upgradeUki}"
      CLOSURE_INFO = "${publisherClosureInfo}"
      OPERATOR_PATH = ":".join(
          [
              "${pkgs.coreutils}/bin",
              "${pkgs.gawk}/bin",
              "${pkgs.grep}/bin",
              "${pkgs.sed}/bin",
          ]
      )


      def add_operator_path(machine):
          """Run guest commands with the qualification's explicit tool set."""
          execute = machine.execute

          def execute_with_operator_path(command, timeout=300):
              prefix = f"export PATH={shlex.quote(OPERATOR_PATH)}:$PATH\n"
              return execute(prefix + command, timeout=timeout)

          machine.execute = execute_with_operator_path


      for guest in (hub, publisher, consumer):
          add_operator_path(guest)


      def hub_command(subcommand, token, mutation=""):
          """Build one authenticated machine-readable Hub CLI command."""
          return (
              f"{AOS} --json hub {subcommand} "
              f"--hub {shlex.quote(HUB)} --token {shlex.quote(token)} {mutation}"
          )


      def reviewed(machine, label, subcommand, token, timeout=120):
          """Plan and apply one Hub mutation through the public CLI."""
          planned = machine.succeed(
              hub_command(
                  subcommand,
                  token,
                  f"--plan --idempotency-key {shlex.quote(label + '-plan')}",
              ),
              timeout=timeout,
          )
          envelope = json.loads(planned)
          assert envelope["schema_version"] == "aos.hub.cli/v1", envelope
          plan = envelope["data"]["plan"]
          assert plan["effects"], plan
          applied = machine.succeed(
              hub_command(
                  subcommand,
                  token,
                  " ".join(
                      [
                          "--plan-id",
                          shlex.quote(plan["plan_id"]),
                          "--confirm-hash",
                          shlex.quote(plan["confirmation_hash"]),
                          "--yes --idempotency-key",
                          shlex.quote(label + "-apply"),
                      ]
                  ),
              ),
              timeout=timeout,
          )
          return json.loads(applied)


      def reviewed_control(machine, label, plan_command, apply_command, token, timeout=120):
          """Plan and apply retained-control porcelain with explicit subcommands."""
          planned = machine.succeed(
              hub_command(
                  plan_command,
                  token,
                  f"--idempotency-key {shlex.quote(label + '-plan')}",
              ),
              timeout=timeout,
          )
          envelope = json.loads(planned)
          assert envelope["schema_version"] == "aos.hub.cli/v1", envelope
          plan = envelope["data"]["plan"]
          assert plan["effects"], plan
          applied = machine.succeed(
              hub_command(
                  apply_command,
                  token,
                  " ".join(
                      [
                          "--plan-id",
                          shlex.quote(plan["plan_id"]),
                          "--confirm-hash",
                          shlex.quote(plan["confirmation_hash"]),
                          "--yes --idempotency-key",
                          shlex.quote(label + "-apply"),
                      ]
                  ),
              ),
              timeout=timeout,
          )
          return json.loads(applied)


      # The native service must boot under its hardened unit before any local
      # recovery/bootstrap action is taken. The database starts empty.
      hub.succeed(textwrap.dedent("""
          systemctl is-active --quiet aos-hub.service || {
            systemctl status --no-pager --full aos-hub.service || true
            journalctl --no-pager -u aos-hub.service -n 100 || true
            exit 1
          }
      """))
      hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)
      hub.succeed("systemctl show aos-hub.service -p User --value | grep -qx aos-hub")
      hub.succeed("systemctl show aos-hub.service -p ProtectSystem --value | grep -qx strict")
      hub.succeed("test ! -e /var/lib/aos-hub/seeded")

      # Initialize as the service account while the sole SQLite writer is
      # stopped, matching the native deployment runbook.
      hub.succeed(textwrap.dedent(f"""
          set -eu
          systemctl stop aos-hub.service
          printf '%s\\n' 'fleet-root-password' | \\
            ${pkgs.systemd}/bin/systemd-run --pipe --wait --collect \\
              --uid=aos-hub --gid=aos-hub \\
              ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \\
                --root-email fleet-root@example.test --root-password-stdin
          install -d -o aos-hub -g aos-hub -m 0750 \\
            /var/lib/aos-hub/storage/acme
          systemctl start aos-hub.service
      """), timeout=180)
      hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)

      # Authenticate the root browser identity, then exchange its same-origin
      # session for the short-lived API bearer used for reviewed setup.
      token = hub.succeed(textwrap.dedent(f"""
          set -eu
          headers=/tmp/hub-login.headers
          page=/tmp/hub-console.html
          {CURL} -sS -D "$headers" -o /dev/null -X POST \\
            --data-urlencode 'email=fleet-root@example.test' \\
            --data-urlencode 'password=fleet-root-password' \\
            {HUB}/login/password
          cookie=$(sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' "$headers" | head -n1)
          test -n "$cookie"
          {CURL} -sS -H "Cookie: $cookie" {HUB}/-/instance > "$page"
          csrf=$(sed -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' "$page" | head -n1)
          test -n "$csrf"
          {CURL} -fsS -X POST \\
            -H "Cookie: $cookie" \\
            -H 'Origin: {HUB}' \\
            -H "x-aos-csrf: $csrf" \\
            -H 'x-aos-console-route: /-/instance' \\
            {HUB}/-/auth/session-token | {JQ} -er .accessToken
      """), timeout=120).strip()
      assert token.startswith("ey"), "browser session did not mint a JWT"

      identity = json.loads(publisher.succeed(hub_command("whoami", token)))
      assert identity["schema_version"] == "aos.hub.cli/v1", identity
      assert identity["kind"] == "who_am_i_response", identity
      assert identity["data"]["principal_kind"] == "user", identity
      assert identity["data"]["principal_ref"] == "fleet-root@example.test", identity
      assert identity["data"]["email"] == "fleet-root@example.test", identity
      assert identity["data"]["access_scope"] == "instance", identity
      assert identity["data"]["grants"] == [
          {"scope": "instance", "role": "owner"}
      ], identity

      empty_orgs = json.loads(publisher.succeed(hub_command("org list", token)))
      assert empty_orgs["schema_version"] == "aos.hub.cli/v1", empty_orgs
      assert empty_orgs["kind"] == "list_organizations_response", empty_orgs
      # Connect-JSON omits repeated fields at their protobuf empty default.
      assert empty_orgs["data"].get("organizations", []) == [], empty_orgs

      # The publisher receives host-built paths through 9p, then makes only
      # that closure visible at its canonical paths and in its local Nix DB.
      # No store bytes are copied into this VM image.
      publisher.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p /run/aos-host-store
          {MOUNT} -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \\
            aos-host-store /run/aos-host-store
          test -r /run/aos-host-store/$(basename {CLOSURE_INFO})/registration
          while IFS= read -r store_path; do
            if [ ! -e "$store_path" ]; then
              source_path="/run/aos-host-store/$(basename "$store_path")"
              if [ -L "$source_path" ]; then
                ln -s "$(readlink "$source_path")" "$store_path"
              elif [ -d "$source_path" ]; then
                mkdir "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              elif [ -f "$source_path" ]; then
                touch "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              else
                printf 'unsupported store object: %s\n' "$source_path" >&2
                exit 1
              fi
            fi
          done < "/run/aos-host-store/$(basename {CLOSURE_INFO})/store-paths"
          {NIX_STORE} --load-db \\
            < "/run/aos-host-store/$(basename {CLOSURE_INFO})/registration"
          {NIX_STORE} --check-validity {TOOL_V1}
          {NIX_STORE} --check-validity {HELPER_V1}
          {NIX_STORE} --check-validity {TOOL_V2}
          {NIX_STORE} --check-validity {HELPER_V2}
          {NIX_STORE} --check-validity {UPGRADE_TOPLEVEL}
          {NIX_STORE} --check-validity {UPGRADE_IMAGE}
          {NIX_STORE} --check-validity {UPGRADE_IMAGE_DISK}
          {NIX_STORE} --check-validity {UPGRADE_IMAGE_INFO}
          {NIX_STORE} --check-validity {UPGRADE_UKI}
          {FINDMNT} -rn -t 9p -o OPTIONS /run/aos-host-store | grep -qw ro
          ! touch {TOOL_V1}/share/hub-tool/host-store-write-must-fail
      """), timeout=180)

      # Generate the real publisher signing identity before creating its Hub
      # registry, just as an organization would establish its trust root.
      trust = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-fleet-publisher USER=publisher
          mkdir -p "$HOME"
          keygen=$({APR} keys generate initial --registry production 2>&1)
          printf '%s\\n' "$keygen" >&2
          printf '%s\\n' "$keygen" | awk '/Public key:/ {{print $NF; exit}}'
      """), timeout=120).strip()
      assert trust.startswith("production:Ed25519:"), trust

      # A real tenant builds its organization and delivery topology through
      # reviewed public API operations. No database or storage-tree mutation
      # is used as a control-plane shortcut.
      reviewed(
          publisher,
          "org-create",
          "org create --slug acme --display-name 'Acme production qualification'",
          token,
      )
      org = json.loads(
          publisher.succeed(hub_command("org show acme", token))
      )["data"]["organization"]
      org_scope = org["stable_id"]
      public_boundary = json.loads(
          publisher.succeed(
              hub_command("network-policy show instance:public", token)
          )
      )["data"]["network_policy"]
      assert any(
          grant["consumer_scope_key"] == org_scope
          for grant in public_boundary["grants"]
      ), public_boundary

      # A production topology controller is a scoped machine principal, not a
      # human administrator. Provision its account, role, and short-lived token
      # through the same reviewed IAM surface an operator uses.
      reviewed_control(
          publisher,
          "controller-account-create",
          "org service-account create plan acme fleet-controller",
          "org service-account create apply",
          token,
      )
      reviewed_control(
          publisher,
          "controller-membership-create",
          "org member set-role plan --principal-kind service_account "
          f"--principal acme/fleet-controller --scope {shlex.quote(org_scope)} "
          "--role owner --if-version absent",
          "org member set-role apply",
          token,
      )
      controller_token_response = reviewed_control(
          publisher,
          "controller-token-issue",
          f"access-token issue plan {shlex.quote(org_scope)} "
          "--owner service_account:acme/fleet-controller "
          "--permission endpoint.read --permission endpoint.manage "
          "--ttl-secs 3600 --comment 'fleet topology controller'",
          "access-token issue apply",
          token,
      )
      controller_secret = controller_token_response["data"]["result"]["secret"]
      assert controller_secret.startswith("aos_"), controller_token_response
      controller_grant = json.loads(publisher.succeed(
          f"{CURL} -fsS -X POST "
          "-H 'Content-Type: application/x-www-form-urlencoded' "
          f"-H 'Authorization: Bearer {controller_secret}' "
          "--data-urlencode "
          "'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
          f"{HUB}/oauth2/token"
      ))
      controller_token = controller_grant["access_token"]
      assert controller_grant["token_type"] == "Bearer", controller_grant

      bindings = json.loads(
          publisher.succeed(hub_command("binding list", token))
      )["data"]["bindings"]
      assert len(bindings) == 1, bindings
      instance_binding = bindings[0]
      assert instance_binding["stable_id"] == "instance-default", instance_binding
      assert instance_binding["owner_scope_key"] == "instance", instance_binding
      assert instance_binding["spec"]["name"] == "default", instance_binding
      assert instance_binding["spec"]["local_filesystem"]["root_path"] == \
          "/var/lib/aos-hub/storage", instance_binding
      assert instance_binding["capabilities"]["reads_supported"], instance_binding
      assert instance_binding["capabilities"]["writes_supported"], instance_binding
      assert instance_binding["health"]["state"] == "valid", instance_binding
      assert any(
          grant["consumer_scope_key"] == org_scope
          for grant in instance_binding["grants"]
      ), instance_binding
      reviewed(
          publisher,
          "registry-create",
          "registry create --org acme --name production --visibility public "
          f"--trust-key {shlex.quote(trust)}",
          token,
      )
      reviewed(
          publisher,
          "placement-create",
          "placement add registry:acme/production primary --binding instance-default "
          "--prefix registries/production --kind complete "
          "--desired-state active --read enabled",
          token,
      )
      placement = json.loads(
          publisher.succeed(
              hub_command("placement show registry:acme/production primary", token)
          )
      )["data"]["placement"]
      reviewed(
          publisher,
          "placement-scan",
          "placement scan registry:acme/production primary --wait --timeout 2m "
          f"--if-version {shlex.quote(placement['resource_version'])}",
          token,
          timeout=180,
      )
      placement = json.loads(
          publisher.succeed(
              hub_command("placement show registry:acme/production primary", token)
          )
      )["data"]["placement"]
      assert placement["observation"]["state"] == "ready", placement
      reviewed(
          publisher,
          "placement-promote",
          "placement promote registry:acme/production primary "
          f"--if-version {shlex.quote(placement['resource_version'])}",
          token,
      )

      # The first layer deliberately records the native cleartext listener and
      # requires the explicit acknowledgement. A separate TLS test can front
      # the same native service without changing this data-plane coverage.
      reviewed(
          publisher,
          "endpoint-create",
          "endpoint add http://192.168.50.11:8420 "
          "--stable-id fleet-native-hub --org acme --acknowledge-cleartext "
          "--network-policy instance:public@1 --ingress hub "
          "--listener-provider hub-native --listener-resource-id aos-hub.service "
          "--probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 "
          "--probe-public-key ${fixture.probePublicKey}",
          token,
      )
      endpoint = json.loads(
          publisher.succeed(hub_command("endpoint show fleet-native-hub", token))
      )["data"]["endpoint"]
      endpoint_generation = int(endpoint["desired_generation"])
      assert endpoint_generation > 0, endpoint

      # Emulate the deployment controller's independent listener check, then
      # report its exact generation-fenced observation with machine authority.
      publisher.succeed(
          f"{CURL} -sS -o /dev/null http://192.168.50.11:8420/healthz"
      )
      endpoint_observation = {
          "stableId": "fleet-native-hub",
          "expectedObservationVersion": endpoint["resource_version"],
          "controllerLeaseId": "fleet-controller-lease",
          "controllerGeneration": 1,
          "observation": {
              "observedGeneration": endpoint_generation,
              "boundaryRevision": endpoint["desired"]["boundary_revision"],
              "state": "healthy",
              "listenerObserved": True,
              "tlsObserved": False,
          },
      }
      observed_endpoint = json.loads(publisher.succeed(
          f"{CURL} -fsS -X POST "
          "-H 'Content-Type: application/json' "
          "-H 'Connect-Protocol-Version: 1' "
          f"-H 'Authorization: Bearer {controller_token}' "
          f"--data {shlex.quote(json.dumps(endpoint_observation))} "
          f"{HUB}/aos.hub.v1.DeliveryControllerService/ReportEndpoint"
      ))["endpoint"]
      assert observed_endpoint["observed"]["state"] == "healthy", observed_endpoint
      assert observed_endpoint["observed"]["listenerObserved"], observed_endpoint

      reviewed(
          publisher,
          "route-create",
          "route add registry:acme/production --stable-id fleet-production "
          f"--endpoint fleet-native-hub@{endpoint_generation} "
          "--base-path /acme/production "
          "--mode hub-proxy --placement primary --serves git --serves cache "
          "--serves web --access public",
          token,
      )
      routes = json.loads(
          publisher.succeed(
              hub_command("route list registry:acme/production", token)
          )
      )["data"]["routes"]
      route = next(
          candidate
          for candidate in routes
          if candidate["stable_id"] == "fleet-production"
      )
      reviewed(
          publisher,
          "route-enable",
          "route enable fleet-production "
          f"--if-version {shlex.quote(route['resource_version'])}",
          token,
      )
      publisher.wait_until_succeeds(
          hub_command("route list registry:acme/production", token)
          + f" | {JQ} -e '.data.routes[] "
          "| select(.stable_id == \"fleet-production\") "
          "| .observation.state == \"healthy\"'",
          timeout=180,
      )
      for audience in ("git", "nix_cache", "web"):
          reviewed(
              publisher,
              f"route-canonical-{audience}",
              "route canonical registry:acme/production fleet-production "
              f"--audience {audience}",
              token,
          )

      # Author and release a signed surface locally, then cross only the
      # managed-publication API into the Hub.
      publication = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-fleet-publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR="$HOME/.config/nix"
          mkdir -p "$NIX_CONF_DIR" /var/tmp/aos-publication-v1
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"
          git config --global user.name 'Fleet Publisher'
          git config --global user.email 'publisher@example.test'
          key="$HOME/.config/apm/keys/production-initial.key"
          {APR} create production --trust-key {shlex.quote(trust)} \\
            --trust-key-id initial --key "$key"
          registry="$HOME/.local/share/apm/registries/production"
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/production.toml" <<EOF
          [registry]
          name = "production"
          url = "file://$registry"

          [registry.signing_keys]
          initial = "$key"
          EOF
          {APR} publish {HELPER_V1} --registry production \\
            --name hub-helper --version 1.0.0 \\
            --description 'Native Hub helper fixture' --license MIT \\
            --maintainer publisher@example.test \\
            --key-id initial
          {APR} publish {NGINX} --registry production \\
            --name nginx --version '${pkgs.nginx.version}' \\
            --description 'Typed virtual hosts, upstreams, TLS credentials, validation, and reload behavior.' \\
            --license BSD-2-Clause --maintainer publisher@example.test \\
            --expose-manifest {shlex.quote(NGINX_EXPOSE + "/manifest.json")} \\
            --config-module {shlex.quote(NGINX_CONFIG)} \\
            --config-base-lib {shlex.quote(DOCUMENTATION_BASE_LIB)} \\
            --key-id initial
          {APR} release 1.0.0 --registry production \\
            --store-path {TOOL_V1} --name hub-tool \\
            --description 'Native Hub production fixture' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --init-channel --cache-url {REGISTRY} \\
            --upload-url file:///var/tmp/aos-publication-v1
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /var/tmp/aos-publication-v1
      """), timeout=900)
      publication_data = json.loads(publication)["data"]
      assert publication_data["state"] == "ready", publication_data

      # Hub indexing and every anonymous delivery capability must be live
      # before the consumer proceeds.
      publisher.wait_until_succeeds(
          hub_command(
              "registry package show acme/production hub-tool",
              token,
          ) + f" | {JQ} -e '.data | tostring | contains(\"1.0.0\")'",
          timeout=180,
      )
      publisher.wait_until_succeeds(
          hub_command(
              "docs search virtual --registry acme/production --kind option",
              token,
          ) + f" | {JQ} -e '.data.results | length > 0'",
          timeout=180,
      )
      publisher.succeed(
          hub_command(
              "docs package nginx --registry acme/production",
              token,
          ) + f" | {JQ} -e '.package.name == \"nginx\" and (.options | length > 0)'"
      )
      publisher.succeed(
          hub_command(
              "docs option nginx --registry acme/production --prefix nginx.virtualHosts",
              token,
          ) + f" | {JQ} -e '.data.options | length > 0'"
      )
      publisher.succeed(
          hub_command(
              "docs compare nginx --registry acme/production "
              "--from '${pkgs.nginx.version}' --to '${pkgs.nginx.version}' "
              "--platform x86_64-linux",
              token,
          ) + f" | {JQ} -e '.data.semantic_changed == false'"
      )
      publisher.succeed(
          hub_command(
              "docs open nginx --registry acme/production",
              token,
          ) + " | grep -q '/acme/production/-/docs/nginx/'"
      )
      publisher.succeed(
          hub_command(
              "docs fetch nginx --registry acme/production "
              "--output /var/tmp/nginx-documentation.json",
              token,
          )
      )
      publisher.succeed(
          f"{JQ} -e '.schema == \"aos.package-documentation/v1\" "
          "and .package.name == \"nginx\" and (.options | length > 0)' "
          "/var/tmp/nginx-documentation.json"
      )

      # Exercise the anonymous, content-bearing browser and stable API aliases
      # served by the same native Hub process. The selected endpoint publishes
      # a strong ETag that addresses the immutable documentation object.
      consumer.succeed(
          f"{CURL} -fsS '{REGISTRY}-/docs?q=virtual' "
          "| grep -q 'Package documentation'"
      )
      consumer.succeed(
          f"{CURL} -fsS {REGISTRY}-/docs/nginx/${pkgs.nginx.version}/x86_64-linux "
          "| grep -q 'Typed virtual hosts'"
      )
      consumer.succeed(
          f"{CURL} -fsS '{REGISTRY}-/api/v1/packages/nginx/options?prefix=nginx.virtualHosts' "
          f"| {JQ} -e '.options | length > 0'"
      )
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          {CURL} -fsS -D /tmp/nginx-doc.headers \
            -o /tmp/nginx-doc.json \
            '{REGISTRY}-/api/v1/packages/nginx/documentation'
          grep -qi '^cache-control:.*immutable' /tmp/nginx-doc.headers
          etag=$(sed -n 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*"\\([^"[:space:]]*\\)".*/\\1/p' \
            /tmp/nginx-doc.headers | tr -d '\\r')
          test -n "$etag"
          {CURL} -fsS -D /tmp/nginx-doc-immutable.headers \
            -o /tmp/nginx-doc-immutable.json \
            "{REGISTRY}-/api/v1/documentation/$etag"
          cmp /tmp/nginx-doc.json /tmp/nginx-doc-immutable.json
          grep -qi '^cache-control:.*immutable' /tmp/nginx-doc-immutable.headers
      """))
      consumer.wait_until_succeeds(f"{CURL} -fsS {REGISTRY}HEAD", timeout=120)

      # Strong network precondition: neither closure member exists or is valid
      # on the independently built consumer before APM runs.
      for path in (TOOL_V1, HELPER_V1):
          consumer.fail(
              f"{NIX_STORE} --check-validity {shlex.quote(path)} "
              ">/tmp/expected-store-miss 2>&1"
          )

      # Trust-on-first-use is never implicit. A syntactically valid but
      # unrelated key must fail closed before the normal user config is made.
      wrong_trust = consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/wrong-trust USER=consumer
          mkdir -p "$HOME"
          keygen=$({APR} keys generate wrong --registry production 2>&1)
          printf '%s\\n' "$keygen" | awk '/Public key:/ {{print $NF; exit}}'
      """), timeout=120).strip()
      consumer.fail(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/untrusted-consumer USER=consumer
          {APM} registry add {REGISTRY} --name production \
            --channel stable --trust-key {shlex.quote(wrong_trust)}
          {APM} update --registry production >/tmp/wrong-trust.out 2>&1
      """), timeout=180)

      # Exercise normal discovery, install, verification, dependency, file,
      # reinstall, removal, orphan and cleanup porcelain as one user profile.
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          mkdir -p "$HOME"
          {APM} registry add {REGISTRY} --name production --priority 900 \\
            --channel stable --trust-key {shlex.quote(trust)}
          {APM} registry list 2>&1 | grep production >/dev/null
          {APM} update --registry production
          {APM} install nginx --registry production --yes
      """), timeout=600)
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} docs show nginx | grep -q 'Typed virtual hosts'
          {APM} options search virtual | grep -q 'nginx.virtualHosts'
          {APM} options show nginx.enable --package nginx | grep -q 'nginx.enable'
          man_path=$({APM} docs man nginx --install --print-path)
          test -s "$man_path"
          {APM} docs cache status | grep -q nginx
          {APM} docs schema | {JQ} -e '.title | contains("AOS")' >/dev/null
          {APM} options compare nginx --from '${pkgs.nginx.version}' \
            --to '${pkgs.nginx.version}' --platform x86_64-linux \
            --hub {HUB} --registry acme/production --token {shlex.quote(token)} \
            | grep -q 'semantic'
      """), timeout=300)
      install_status, install_stdout, install_stderr = consumer.execute(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} search hub-tool --registry production 2>&1 | grep hub-tool >/dev/null
          {APM} search hub --names-only --registry production 2>&1 | grep hub-tool >/dev/null
          {APM} show hub-tool --registry production 2>&1 | grep 1.0.0 >/dev/null
          {APM} info hub-tool --registry production 2>&1 | grep hub-tool >/dev/null
          {APM} policy hub-tool 2>&1 | grep 1.0.0 >/dev/null
          {APM} install hub-tool --registry production --dry-run
          {APM} install hub-tool --registry production --download-only --yes
          {APM} install hub-tool --registry production --yes 2>&1
      """), timeout=600)
      assert install_status == 0, (install_status, install_stdout, install_stderr)
      install_output = install_stdout + install_stderr
      assert b"Downloading" in install_output, install_output
      lifecycle_commands = (
          f"{APM} verify hub-tool",
          f"{APM} list --installed 2>&1 | grep hub-tool >/dev/null",
          f"{APM} search hub-tool --installed 2>&1 | grep hub-tool >/dev/null",
          f"{APM} depends hub-tool >/dev/null 2>&1",
          f"{APM} rdepends hub-helper 2>&1 | grep hub-tool >/dev/null",
          f"{NIX_STORE} -q --references {TOOL_V1} "
          f"| grep {shlex.quote(HELPER_V1.rsplit('/', 1)[-1])} >/dev/null",
          f"{APM} files hub-tool 2>&1 | grep 'bin/hub-tool' >/dev/null",
          "/var/lib/profiles/per-user/consumer/current/bin/hub-tool "
          "> /tmp/hub-tool.out",
          "grep -qx 'hub-helper 1.0.0' /tmp/hub-tool.out",
          "grep -qx 'hub-tool 1.0.0' /tmp/hub-tool.out",
          f"{APM} reinstall hub-tool --yes",
          f"{APM} remove hub-tool --dry-run",
          f"{APM} remove hub-tool --autoremove --yes",
          f"! {APM} list --installed 2>&1 | grep hub-tool >/dev/null",
          f"{APM} orphans",
          f"{APM} clean --generations --keep 1",
          f"{APM} gc --dry-run",
      )
      for lifecycle_command in lifecycle_commands:
          status, stdout, stderr = consumer.execute(textwrap.dedent(f"""
              export HOME=/tmp/consumer USER=consumer
              export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
              {lifecycle_command}
          """), timeout=600)
          assert status == 0, (lifecycle_command, status, stdout, stderr)

      # Reinstall for persistence checks and prove all closure members arrived
      # via the data plane.
      consumer.succeed(
          f"HOME=/tmp/consumer USER=consumer PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          f"{APM} install hub-tool --registry production --yes",
          timeout=300,
      )
      for path in (TOOL_V1, HELPER_V1):
          consumer.succeed(f"{NIX_STORE} --check-validity {shlex.quote(path)}")

      # Once installed, documentation and editor metadata are exact retained
      # profile inputs rather than a Hub cache. Prove every offline surface
      # works while the native Hub is unavailable.
      hub.succeed("systemctl stop aos-hub.service")
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} docs show nginx | grep -q 'Typed virtual hosts'
          {APM} options complete nginx.virtual | grep -q 'nginx.virtualHosts'

          {APM} docs serve --listen 127.0.0.1:18080 --once \
            >/tmp/apm-docs-serve.log 2>&1 &
          docs_pid=$!
          served=0
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if {CURL} -fsS http://127.0.0.1:18080/packages/nginx \
              | grep -q 'Typed virtual hosts'; then
              served=1
              break
            fi
            sleep 1
          done
          wait "$docs_pid"
          test "$served" = 1

          payload='{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}'
          printf 'Content-Length: %s\\r\\n\\r\\n%s' "''${{#payload}}" "$payload" \
            | {APM} docs lsp >/tmp/aos-doc-lsp.out
          grep -q 'completionProvider' /tmp/aos-doc-lsp.out
          grep -q 'hoverProvider' /tmp/aos-doc-lsp.out
          {APM} docs cache gc
      """), timeout=180)

      # SQLite topology, publication metadata, and local surface bytes survive
      # a process restart. Anonymous package consumption stays available.
      hub.succeed("systemctl restart aos-hub.service")
      hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)
      restarted_identity = json.loads(
          publisher.succeed(hub_command("whoami", token))
      )
      assert restarted_identity["data"]["principal_ref"] == \
          "fleet-root@example.test", restarted_identity
      consumer.succeed(textwrap.dedent(f"""
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} update --registry production
          {APM} show hub-tool --registry production 2>&1 | grep 1.0.0 >/dev/null
          /var/lib/profiles/per-user/consumer/current/bin/hub-tool \\
            | grep -q 'hub-tool 1.0.0'
      """), timeout=180)

      # The organization ships an ordinary package update through the same
      # signed producer and managed Hub boundary.
      publication_v2 = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-fleet-publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR="$HOME/.config/nix"
          key="$HOME/.config/apm/keys/production-initial.key"
          rm -rf /var/tmp/aos-publication-v2
          mkdir -p /var/tmp/aos-publication-v2
          {APR} publish {HELPER_V2} --registry production \\
            --name hub-helper --version 2.0.0 --previous 1.0.0 \\
            --description 'Native Hub helper fixture update' --license MIT \\
            --maintainer publisher@example.test --key "$key"
          {APR} release 2.0.0 --registry production \\
            --store-path {TOOL_V2} --name hub-tool --version 2.0.0 \\
            --previous 1.0.0 \\
            --description 'Native Hub production fixture update' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --count 256 --cache-url {REGISTRY} \\
            --upload-url file:///var/tmp/aos-publication-v2
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /var/tmp/aos-publication-v2
      """), timeout=900)
      publication_v2_data = json.loads(publication_v2)["data"]
      assert publication_v2_data["state"] == "ready", publication_v2_data
      publisher.wait_until_succeeds(
          hub_command("registry package show acme/production hub-tool", token)
          + f" | {JQ} -e '.data | tostring | contains(\"2.0.0\")'",
          timeout=180,
      )

      for path in (TOOL_V2, HELPER_V2):
          consumer.fail(
              f"{NIX_STORE} --check-validity {shlex.quote(path)} "
              ">/tmp/expected-v2-store-miss 2>&1"
          )

      # Holds must survive metadata refresh and suppress a targeted upgrade.
      # Unholding then exercises plan, download, activation, rollback and an
      # explicit roll-forward to the already-created generation.
      upgrade_status, upgrade_stdout, upgrade_stderr = consumer.execute(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          profile=/var/lib/profiles/per-user/consumer
          {APM} hold hub-tool
          {APM} held 2>&1 | grep hub-tool >/dev/null
          {APM} update --registry production
          {APM} upgrade hub-tool --yes
          "$profile/current/bin/hub-tool" | grep -q 'hub-tool 1.0.0'
          {APM} unhold hub-tool
          ! {APM} held 2>&1 | grep hub-tool >/dev/null
          {APM} list --upgradable 2>&1 | grep 2.0.0 >/dev/null
          {APM} upgrade hub-tool --dry-run 2>&1 | grep 2.0.0 >/dev/null
          {APM} upgrade hub-tool --yes 2>&1
      """), timeout=600)
      assert upgrade_status == 0, (upgrade_status, upgrade_stdout, upgrade_stderr)
      upgrade_output = upgrade_stdout + upgrade_stderr
      assert b"Downloading" in upgrade_output, upgrade_output
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          profile=/var/lib/profiles/per-user/consumer
          "$profile/current/bin/hub-tool" > /tmp/hub-tool-v2.out
          grep -qx 'hub-helper 2.0.0' /tmp/hub-tool-v2.out
          grep -qx 'hub-tool 2.0.0' /tmp/hub-tool-v2.out
          {APM} verify hub-tool
          upgraded=$(basename "$(readlink "$profile/current")" | sed 's/^gen-//')
          {APM} rollback
          "$profile/current/bin/hub-tool" | grep -q 'hub-tool 1.0.0'
          {APM} rollback --generation "$upgraded"
          "$profile/current/bin/hub-tool" | grep -q 'hub-tool 2.0.0'
          {APM} full-upgrade --dry-run
          {APM} registry disable production
          {APM} registry list 2>&1 | grep production >/dev/null
          {APM} registry enable production
          {APM} update --registry production
      """), timeout=600)
      for path in (TOOL_V2, HELPER_V2):
          consumer.succeed(f"{NIX_STORE} --check-validity {shlex.quote(path)}")

      # Finally publish a locally built AOS toplevel and its authenticated raw
      # OTA image as a sysroot package. Stage it over the Hub, boot it through
      # UEFI, then exercise durable image rollback and roll-forward.
      publication_system = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-fleet-publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR="$HOME/.config/nix"
          export TMPDIR=/var/tmp/apr-release
          mkdir -p "$TMPDIR"
          available_mib=$(df -Pm "$HOME" | awk 'NR == 2 {{ print $4 }}')
          if [ "$available_mib" -lt 12288 ]; then
            printf 'publisher data disk has only %s MiB free; 12288 MiB required\\n' \
              "$available_mib" >&2
            exit 1
          fi
          key="$HOME/.config/apm/keys/production-initial.key"
          rm -rf /var/tmp/aos-publication-system
          mkdir -p /var/tmp/aos-publication-system
          set -- {UPGRADE_UKI}/*.efi
          test "$#" -eq 1
          candidate_uki="$1"
          {APR} release 3.0.0 --registry production \\
            --store-path {UPGRADE_TOPLEVEL} --name aos --version test-2 \\
            --sysroot --previous 0.1.0 \\
            --image-payload {UPGRADE_IMAGE} \\
            --image-disk {UPGRADE_IMAGE_DISK} \\
            --image-info {UPGRADE_IMAGE_INFO} --image-format raw \\
            --image-uki "$candidate_uki" \\
            --description 'AOS native Hub system upgrade fixture' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --count 256 --cache-url {REGISTRY} \\
            --upload-url file:///var/tmp/aos-publication-system
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /var/tmp/aos-publication-system
      """), timeout=1800)
      publication_system_data = json.loads(publication_system)["data"]
      assert publication_system_data["state"] == "ready", publication_system_data
      publisher.wait_until_succeeds(
          hub_command("registry package show acme/production aos", token)
          + f" | {JQ} -e '.data | tostring | contains(\"test-2\")'",
          timeout=240,
      )
      consumer.fail(
          f"{NIX_STORE} --check-validity {shlex.quote(UPGRADE_TOPLEVEL)} "
          ">/tmp/expected-system-store-miss 2>&1"
      )

      system_status, system_stdout, system_stderr = consumer.execute(textwrap.dedent(f"""
          set -eu
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} registry --system add {REGISTRY} --name production \\
            --priority 900 --channel stable --trust-key {shlex.quote(trust)}
          {APM} update --system --registry production
          {APM} show aos --system --registry production 2>&1 | grep test-2 >/dev/null
          {APM} list --system --upgradable 2>&1 | grep test-2 >/dev/null
          {APM} upgrade --system --dry-run 2>&1 | grep test-2 >/dev/null
          {APM} upgrade --system --yes 2>&1
      """), timeout=1200)
      assert system_status == 0, (system_status, system_stdout, system_stderr)
      system_upgrade = system_stdout + system_stderr
      assert b"Downloading" in system_upgrade, system_upgrade
      assert b"staged in slot" in system_upgrade, system_upgrade
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          {NIX_STORE} --check-validity {UPGRADE_TOPLEVEL}
          grep -q 'VERSION_ID=0.1.0' /etc/os-release
          {JQ} -e '.running == 1 and .default == 2 and .pending == 2' \\
            /var/lib/profiles/image/state.json >/dev/null
      """), timeout=1200)
      consumer.reboot(timeout=600)
      consumer.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service",
          timeout=420,
      )
      consumer.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target",
          timeout=420,
      )
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          grep -q 'VERSION_ID=test-2' /etc/os-release
          grep -qx 'marker = 1' /etc/aos/upgrade-test/marker.conf
          systemctl is-active --quiet aos-upgrade-test-marker.service
          ! systemctl is-active --quiet aos-upgrade-removed.service
          {JQ} -e '.running == 2 and .default == 2 and .pending == null' \\
            /var/lib/profiles/image/state.json >/dev/null
          {APM} rollback --system --image --generation 1
      """), timeout=1200)
      consumer.reboot(timeout=600)
      consumer.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service",
          timeout=420,
      )
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          grep -q 'VERSION_ID=0.1.0' /etc/os-release
          test ! -e /etc/aos/upgrade-test/marker.conf
          systemctl is-active --quiet aos-upgrade-removed.service
          {JQ} -e '.running == 1 and .default == 1 and .pending == null' \\
            /var/lib/profiles/image/state.json >/dev/null
          {APM} rollback --system --image --generation 2
      """), timeout=1200)
      consumer.reboot(timeout=600)
      consumer.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service",
          timeout=420,
      )
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          grep -q 'VERSION_ID=test-2' /etc/os-release
          grep -qx 'marker = 1' /etc/aos/upgrade-test/marker.conf
          {JQ} -e '.running == 2 and .default == 2 and .pending == null' \\
            /var/lib/profiles/image/state.json >/dev/null
      """), timeout=1200)
    '';
}
