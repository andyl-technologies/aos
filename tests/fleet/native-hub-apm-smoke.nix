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
  publisherClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = [
      fixture.toolV1
      fixture.toolV2
      upgradeToplevel
    ];
    pname = "native-hub-publisher-closure-info";
  };
in {
  name = "native-hub-apm-smoke";
  timeout = 3600;

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
      imageDiskMiB = 16384;
      memoryMiB = 4096;
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
      UPGRADE_TOPLEVEL = "${upgradeToplevel}"
      CLOSURE_INFO = "${publisherClosureInfo}"


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
      publisher.succeed(hub_command("whoami", token) + " | grep -q fleet-root")
      empty_orgs = json.loads(publisher.succeed(hub_command("org list", token)))
      assert empty_orgs["data"]["organizations"] == [], empty_orgs

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
              mkdir "$store_path"
              {MOUNT} --bind "/run/aos-host-store/$(basename "$store_path")" "$store_path"
            fi
          done < "/run/aos-host-store/$(basename {CLOSURE_INFO})/store-paths"
          {NIX_STORE} --load-db \\
            < "/run/aos-host-store/$(basename {CLOSURE_INFO})/registration"
          {NIX_STORE} --check-validity {TOOL_V1}
          {NIX_STORE} --check-validity {HELPER_V1}
          {NIX_STORE} --check-validity {TOOL_V2}
          {NIX_STORE} --check-validity {HELPER_V2}
          {NIX_STORE} --check-validity {UPGRADE_TOPLEVEL}
          {FINDMNT} -rn -t 9p -o OPTIONS /run/aos-host-store | grep -qw ro
      """), timeout=180)

      # Generate the real publisher signing identity before creating its Hub
      # registry, just as an organization would establish its trust root.
      trust = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/publisher USER=publisher
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
      reviewed(
          publisher,
          "public-boundary-grant",
          "network-policy grant instance:public "
          f"--consumer-scope {shlex.quote(org_scope)}",
          token,
      )
      reviewed(
          publisher,
          "binding-create",
          "binding create --org acme --name primary --kind local-fs "
          "--root /var/lib/aos-hub/storage/acme",
          token,
      )
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
          "placement add registry:acme/production primary --binding primary "
          "--prefix registries/production --kind complete "
          "--desired-state active --read enabled",
          token,
      )
      reviewed(
          publisher,
          "placement-scan",
          "placement scan registry:acme/production primary --wait --timeout 2m",
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
      reviewed(
          publisher,
          "route-create",
          "route add registry:acme/production --stable-id fleet-production "
          "--endpoint fleet-native-hub --base-path /acme/production "
          "--mode hub-proxy --placement primary --serves git --serves cache "
          "--serves web --access public",
          token,
      )
      reviewed(publisher, "route-enable", "route enable fleet-production", token)
      publisher.wait_until_succeeds(
          hub_command(
              "route explain fleet-production --access-class nix_cache",
              token,
          ) + f" | {JQ} -e '.data | tostring | test(\"healthy\")'",
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
          export HOME=/tmp/publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR" /tmp/publication-v1
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"
          git config --global user.name 'Fleet Publisher'
          git config --global user.email 'publisher@example.test'
          key="$HOME/.config/apm/keys/production-initial.key"
          {APR} create production --trust-key {shlex.quote(trust)} \\
            --trust-key-id initial --key "$key"
          {APR} release 1.0.0 --registry production \\
            --store-path {TOOL_V1} --name hub-tool \\
            --description 'Native Hub production fixture' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --init-channel --cache-url {REGISTRY} \\
            --upload-url file:///tmp/publication-v1
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /tmp/publication-v1
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
          HOME=/tmp/untrusted-consumer USER=consumer \
            {APM} registry add {REGISTRY} --name production \
              --channel stable --trust-key {shlex.quote(wrong_trust)} \
              >/tmp/wrong-trust.out 2>&1
      """), timeout=180)

      # Exercise normal discovery, install, verification, dependency, file,
      # reinstall, removal, orphan and cleanup porcelain as one user profile.
      install_output = consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          mkdir -p "$HOME"
          {APM} registry add {REGISTRY} --name production --priority 900 \\
            --channel stable --trust-key {shlex.quote(trust)}
          {APM} registry list | grep -q production
          {APM} update --registry production
          {APM} search hub-tool --registry production | grep -q hub-tool
          {APM} search hub --names-only --registry production | grep -q hub-tool
          {APM} show hub-tool --registry production | grep -q 1.0.0
          {APM} info hub-tool --registry production | grep -q hub-tool
          {APM} policy hub-tool | grep -q 1.0.0
          {APM} install hub-tool --registry production --dry-run
          {APM} install hub-tool --registry production --download-only --yes
          {APM} install hub-tool --registry production --yes 2>&1
      """), timeout=600)
      assert "Downloading" in install_output, install_output
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} verify hub-tool
          {APM} list --installed | grep -q hub-tool
          {APM} search hub-tool --installed | grep -q hub-tool
          {APM} depends hub-tool | grep -q hub-helper
          {APM} rdepends hub-helper | grep -q hub-tool
          {APM} files hub-tool | grep -q /bin/hub-tool
          /var/lib/profiles/per-user/consumer/current/bin/hub-tool > /tmp/hub-tool.out
          grep -qx 'hub-helper 1.0.0' /tmp/hub-tool.out
          grep -qx 'hub-tool 1.0.0' /tmp/hub-tool.out
          {APM} reinstall hub-tool --yes
          {APM} remove hub-tool --dry-run
          {APM} remove hub-tool --autoremove --yes
          ! {APM} list --installed | grep -q hub-tool
          {APM} orphans
          {APM} clean --generations --keep 1
          {APM} gc --dry-run
      """), timeout=600)

      # Reinstall for persistence checks and prove all closure members arrived
      # via the data plane.
      consumer.succeed(
          f"HOME=/tmp/consumer USER=consumer PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          f"{APM} install hub-tool --registry production --yes",
          timeout=300,
      )
      for path in (TOOL_V1, HELPER_V1):
          consumer.succeed(f"{NIX_STORE} --check-validity {shlex.quote(path)}")

      # SQLite topology, publication metadata, and local surface bytes survive
      # a process restart. Anonymous package consumption stays available.
      hub.succeed("systemctl restart aos-hub.service")
      hub.wait_until_succeeds(f"{CURL} -fsS {HUB}/healthz", timeout=120)
      consumer.succeed(textwrap.dedent(f"""
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} update --registry production
          {APM} show hub-tool --registry production | grep -q 1.0.0
          /var/lib/profiles/per-user/consumer/current/bin/hub-tool \\
            | grep -q 'hub-tool 1.0.0'
      """), timeout=180)

      # The organization ships an ordinary package update through the same
      # signed producer and managed Hub boundary.
      publication_v2 = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          key="$HOME/.config/apm/keys/production-initial.key"
          rm -rf /tmp/publication-v2
          mkdir -p /tmp/publication-v2
          {APR} release 2.0.0 --registry production \\
            --store-path {TOOL_V2} --name hub-tool --version 2.0.0 \\
            --previous 1.0.0 \\
            --description 'Native Hub production fixture update' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --count 256 --cache-url {REGISTRY} \\
            --upload-url file:///tmp/publication-v2
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /tmp/publication-v2
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
      upgrade_output = consumer.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/consumer USER=consumer
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          profile=/var/lib/profiles/per-user/consumer
          {APM} hold hub-tool
          {APM} held | grep -q hub-tool
          {APM} update --registry production
          {APM} upgrade hub-tool --yes
          "$profile/current/bin/hub-tool" | grep -q 'hub-tool 1.0.0'
          {APM} unhold hub-tool
          ! {APM} held | grep -q hub-tool
          {APM} list --upgradable | grep -q 2.0.0
          {APM} upgrade hub-tool --dry-run | grep -q 2.0.0
          {APM} upgrade hub-tool --yes 2>&1
      """), timeout=600)
      assert "Downloading" in upgrade_output, upgrade_output
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
          {APM} registry list | grep -q production
          {APM} registry enable production
          {APM} update --registry production
      """), timeout=600)
      for path in (TOOL_V2, HELPER_V2):
          consumer.succeed(f"{NIX_STORE} --check-validity {shlex.quote(path)}")

      # Finally publish a locally built AOS toplevel as a sysroot package.
      # This is a real system-scope APM upgrade over the Hub, followed by a
      # live rollback and a final roll-forward.
      publication_system = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/publisher USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          key="$HOME/.config/apm/keys/production-initial.key"
          rm -rf /tmp/publication-system
          mkdir -p /tmp/publication-system
          {APR} release 3.0.0 --registry production \\
            --store-path {UPGRADE_TOPLEVEL} --name aos --version test-2 \\
            --sysroot --previous 0.1.0 \\
            --description 'AOS native Hub system upgrade fixture' --license MIT \\
            --maintainer publisher@example.test --key "$key" \\
            --channel stable --count 256 --cache-url {REGISTRY} \\
            --upload-url file:///tmp/publication-system
          {APR} verify --registry production
          {AOS} --json hub registry publish upload acme/production \\
            --hub {HUB} --token {shlex.quote(token)} \\
            --root /tmp/publication-system
      """), timeout=1200)
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

      system_upgrade = consumer.succeed(textwrap.dedent(f"""
          set -eu
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          {APM} registry --system add {REGISTRY} --name production \\
            --priority 900 --channel stable --trust-key {shlex.quote(trust)}
          {APM} update --system --registry production
          {APM} show aos --system --registry production | grep -q test-2
          {APM} list --system --upgradable | grep -q test-2
          {APM} upgrade --system --dry-run | grep -q test-2
          {APM} upgrade --system --live --yes 2>&1
      """), timeout=1200)
      assert "Downloading" in system_upgrade, system_upgrade
      consumer.succeed(textwrap.dedent(f"""
          set -eu
          {NIX_STORE} --check-validity {UPGRADE_TOPLEVEL}
          grep -q 'VERSION_ID=test-2' /etc/os-release
          grep -qx 'marker = 1' /etc/aos/upgrade-test/marker.conf
          systemctl is-active --quiet aos-upgrade-test-marker.service
          ! systemctl is-active --quiet aos-upgrade-removed.service
          {APM} rollback --system --live
          grep -q 'VERSION_ID=0.1.0' /etc/os-release
          test ! -e /etc/aos/upgrade-test/marker.conf
          systemctl is-active --quiet aos-upgrade-removed.service
          {APM} upgrade --system --live --yes
          grep -q 'VERSION_ID=test-2' /etc/os-release
          grep -qx 'marker = 1' /etc/aos/upgrade-test/marker.conf
      """), timeout=1200)
    '';
}
