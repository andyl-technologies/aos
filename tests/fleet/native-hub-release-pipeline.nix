# Native Hub canonical release-pipeline acceptance.
#
# Two independently keyed native Hub instances terminate TLS for the canonical
# staging and production names. A third machine receives four prebuilt package
# closures only through the fleet's read-only 9p store mount, turns them into
# release NARs, and drives every online `aos release` transition.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  releaseTool = pkgs.aos.testSupport;
  caCertificate = builtins.readFile ../fixtures/release-fleet-ca.crt;

  mkMatrixPackage = platform:
    pkgs.mkDerivation {
      pname = "release-fleet-${platform}";
      version = "1.0.0";
      src = null;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/aos-release-fleet"
            printf '%s\n' '${platform}' > "$out/share/aos-release-fleet/platform"
          '';
        }
      ];
    };
  matrixPackages = builtins.map mkMatrixPackage [
    "x86_64-linux"
    "aarch64-linux"
    "x86_64-darwin"
    "aarch64-darwin"
  ];
  publisherClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = matrixPackages ++ [releaseTool];
    pname = "native-hub-release-publisher-closure-info";
  };

  credentialFile = name: text:
    pkgs.writeTextFile {
      inherit name text;
      destination = "/value";
    };
  publicationKeys = credentialFile "release-fleet-publication-keys.json" (builtins.toJSON {
    "staging-publication-v1" = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
  });
  qualificationKeys = credentialFile "release-fleet-qualification-keys.json" (builtins.toJSON {
    "qualification-v1" = "E5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8o=";
  });
  serverCertificate = credentialFile "release-fleet-server-certificate" (builtins.readFile ../fixtures/release-fleet-server.crt);
  serverPrivateKey = credentialFile "release-fleet-server-private-key" (builtins.readFile ../fixtures/release-fleet-server.key);

  mkHubSystem = {
    deploymentId,
    externalUrl,
    publicationKeyId,
    publicationSeed,
    channelKeyId,
    channelSeed,
    endpointId,
  }:
    fixture.hubSystem.extendModules {
      modules = [
        ({lib, ...}: {
          aos.registry-hub = {
            inherit deploymentId externalUrl;
            releaseReceiptKeyId = publicationKeyId;
            channelReceiptKeyId = channelKeyId;
            credentials = {
              releaseReceiptKey = "release-fleet-publication-seed";
              channelReceiptKey = "release-fleet-channel-seed";
              releasePublicationKeys = "release-fleet-publication-keys";
              qualificationKeys = "release-fleet-qualification-keys";
              domainProbeSignerManifest = lib.mkForce "release-fleet-probe-signers";
            };
          };
          aos.security.pki.certificates = [caCertificate];
          aos.firewall.allowedTCP = [443];
          environment.systemPackages = [releaseTool];
          environment.etc."tmpfiles.d/native-hub-credentials.conf".text = ''
            C /run/credentials/@system/release-fleet-publication-seed 0600 root root - ${credentialFile "release-fleet-publication-seed" publicationSeed}/value
            C /run/credentials/@system/release-fleet-channel-seed 0600 root root - ${credentialFile "release-fleet-channel-seed" channelSeed}/value
            C /run/credentials/@system/release-fleet-publication-keys 0600 root root - ${publicationKeys}/value
            C /run/credentials/@system/release-fleet-qualification-keys 0600 root root - ${qualificationKeys}/value
            C /run/credentials/@system/release-fleet-probe-signers 0600 root root - ${credentialFile "release-fleet-probe-signers" (builtins.toJSON [
              {
                endpointId = endpointId;
                endpointGeneration = 1;
                signerSecretRef = "fleet-probe-v1";
                signingSeed = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
              }
            ])}/value
          '';
          systemd.services.release-fleet-tls = {
            description = "Test-only TLS edge for the native Hub release fleet";
            after = ["aos-hub.service"];
            serviceConfig = {
              Type = "simple";
              ExecStart = "${releaseTool}/bin/aos-release-fleet-fixture tls-proxy 0.0.0.0:443 127.0.0.1:8420 /run/credentials/release-fleet-tls.service/certificate /run/credentials/release-fleet-tls.service/private-key";
              LoadCredential = [
                "certificate:${serverCertificate}/value"
                "private-key:${serverPrivateKey}/value"
              ];
              DynamicUser = true;
              Restart = "on-failure";
              NoNewPrivileges = true;
              AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
              CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];
              PrivateTmp = true;
              ProtectSystem = "strict";
              ProtectHome = true;
              RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
            };
          };
        })
      ];
    };

  stagingSystem = mkHubSystem {
    deploymentId = "fleet-staging-v1";
    externalUrl = "https://aos.staging.andyl.org";
    publicationKeyId = "staging-publication-v1";
    publicationSeed = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";
    channelKeyId = "staging-channel-v1";
    channelSeed = "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=";
    endpointId = "fleet-staging-endpoint";
  };
  productionSystem = mkHubSystem {
    deploymentId = "fleet-production-v1";
    externalUrl = "https://aos.andyl.org";
    publicationKeyId = "production-publication-v1";
    publicationSeed = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=";
    channelKeyId = "production-channel-v1";
    channelSeed = "DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw=";
    endpointId = "fleet-production-endpoint";
  };
  publisherSystem = fixture.publisherSystem.extendModules {
    modules = [
      {
        # The canonical release publisher exercises the complete AOS CLI and
        # APR surface. Keep the closure audit enforced with narrow headroom
        # above this branch's measured 917.2 MiB publisher closure.
        aos.image.budgets.maxRuntimeClosureMiB = lib.mkForce 920;
        aos.security.pki.certificates = [caCertificate];
      }
    ];
  };
in {
  name = "native-hub-release-pipeline";
  timeout = 5400;
  bootTimeout = 600;

  machines = {
    production = {
      system = productionSystem;
      bootMode = "image";
      hostAliases = ["aos.andyl.org"];
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      varProvisioning = "repart";
    };
    publisher = {
      system = publisherSystem;
      bootMode = "image";
      hostStoreMount = true;
      imageDiskMiB = 24576;
      memoryMiB = 6144;
      varProvisioning = "repart";
    };
    staging = {
      system = stagingSystem;
      bootMode = "image";
      hostAliases = ["aos.staging.andyl.org"];
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

      AOS = "${pkgs.aos}/bin/aos"
      APR = "${pkgs.aos.apr}/bin/apr"
      CURL = "${pkgs.curl}/bin/curl"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      FINDMNT = "${pkgs.util-linux}/bin/findmnt"
      FIXTURE = "${releaseTool}/bin/aos-release-fleet-fixture"
      CLOSURE_INFO = "${publisherClosureInfo}"
      PACKAGES = ${builtins.toJSON (builtins.map toString matrixPackages)}
      STAGING = "https://aos.staging.andyl.org"
      PRODUCTION = "https://aos.andyl.org"
      PROBE_KEY = "${fixture.probePublicKey}"
      OPERATOR_PATH = ":".join([
          "${pkgs.coreutils}/bin", "${pkgs.gawk}/bin", "${pkgs.git}/bin",
          "${pkgs.grep}/bin", "${pkgs.sed}/bin", "${pkgs.nix}/bin",
      ])


      def add_operator_path(machine):
          execute = machine.execute
          def wrapped(command, timeout=300):
              return execute(
                  f"export PATH={shlex.quote(OPERATOR_PATH)}:$PATH\n" + command,
                  timeout=timeout,
              )
          machine.execute = wrapped


      for guest in (production, publisher, staging):
          add_operator_path(guest)


      def hub_command(url, subcommand, token, mutation=""):
          return (
              f"{AOS} --json hub {subcommand} --hub {shlex.quote(url)} "
              f"--token {shlex.quote(token)} {mutation}"
          )


      def reviewed(url, label, subcommand, token, timeout=120):
          planned = json.loads(publisher.succeed(hub_command(
              url, subcommand, token,
              f"--plan --idempotency-key {shlex.quote(label + '-plan')}",
          ), timeout=timeout))
          plan = planned["data"]["plan"]
          assert plan["effects"], plan
          return json.loads(publisher.succeed(hub_command(
              url, subcommand, token,
              " ".join([
                  "--plan-id", shlex.quote(plan["plan_id"]),
                  "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
                  "--yes --idempotency-key", shlex.quote(label + "-apply"),
              ]),
          ), timeout=timeout))


      def reviewed_control(url, label, plan_command, apply_command, token, timeout=120):
          planned = json.loads(publisher.succeed(hub_command(
              url, plan_command, token,
              f"--idempotency-key {shlex.quote(label + '-plan')}",
          ), timeout=timeout))
          plan = planned["data"]["plan"]
          return json.loads(publisher.succeed(hub_command(
              url, apply_command, token,
              " ".join([
                  "--plan-id", shlex.quote(plan["plan_id"]),
                  "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
                  "--yes --idempotency-key", shlex.quote(label + "-apply"),
              ]),
          ), timeout=timeout))


      def initialize_hub(machine, url, suffix):
          machine.succeed("systemctl is-active --quiet aos-hub.service")
          machine.wait_until_succeeds(
              f"{CURL} -fsS http://127.0.0.1:8420/healthz", timeout=120
          )
          machine.succeed(textwrap.dedent(f"""
              systemctl stop aos-hub.service
              printf '%s\\n' 'fleet-root-password' | \\
                ${pkgs.systemd}/bin/systemd-run --pipe --wait --collect \\
                  --uid=aos-hub --gid=aos-hub \\
                  ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \\
                    --root-email fleet-root@example.test --root-password-stdin
              install -d -o aos-hub -g aos-hub -m 0750 /var/lib/aos-hub/storage/andyl
              systemctl start aos-hub.service
              systemctl start release-fleet-tls.service
              sleep 1
              systemctl is-active --quiet release-fleet-tls.service
          """), timeout=180)
          machine.wait_until_succeeds(f"{CURL} -fsS {url}/healthz", timeout=120)
          machine.succeed(
              f'test "$({CURL} -fsS {url}/.well-known/aos-deployment)" = fleet-{suffix}-v1'
          )
          return machine.succeed(textwrap.dedent(f"""
              set -eu
              headers=/tmp/hub-login.headers
              page=/tmp/hub-console.html
              {CURL} -sS -D "$headers" -o /dev/null -X POST \\
                --data-urlencode 'email=fleet-root@example.test' \\
                --data-urlencode 'password=fleet-root-password' {url}/login/password
              cookie=$(sed -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' "$headers" | head -n1)
              {CURL} -sS -H "Cookie: $cookie" {url}/-/instance > "$page"
              csrf=$(sed -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' "$page" | head -n1)
              {CURL} -fsS -X POST -H "Cookie: $cookie" -H 'Origin: {url}' \\
                -H "x-aos-csrf: $csrf" -H 'x-aos-console-route: /-/instance' \\
                {url}/-/auth/session-token | {JQ} -er .accessToken
          """), timeout=120).strip()


      def configure_registry(url, token, suffix, trust):
          reviewed(url, f"{suffix}-org", "org create --slug andyl --display-name 'Andyl release fleet'", token)
          org = json.loads(publisher.succeed(hub_command(url, "org show andyl", token)))["data"]["organization"]
          scope = org["stable_id"]
          reviewed(url, f"{suffix}-network", f"network-policy grant instance:public --consumer-scope {shlex.quote(scope)}", token)
          reviewed(url, f"{suffix}-binding", f"binding grant instance:default --consumer-scope {shlex.quote(scope)}", token)
          reviewed_control(url, f"{suffix}-controller-account", "org service-account create plan andyl fleet-controller", "org service-account create apply", token)
          reviewed_control(
              url, f"{suffix}-controller-role",
              f"org member set-role plan --principal-kind service_account --principal andyl/fleet-controller --scope {shlex.quote(scope)} --role owner --if-version absent",
              "org member set-role apply", token,
          )
          issued = reviewed_control(
              url, f"{suffix}-controller-token",
              f"access-token issue plan {shlex.quote(scope)} --owner service_account:andyl/fleet-controller --permission endpoint.read --permission endpoint.manage --ttl-secs 3600 --comment fleet-release-controller",
              "access-token issue apply", token,
          )
          secret = issued["data"]["result"]["secret"]
          grant = json.loads(publisher.succeed(
              f"{CURL} -fsS -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
              f"-H 'Authorization: Bearer {secret}' --data-urlencode "
              f"'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' {url}/oauth2/token"
          ))
          controller_token = grant["access_token"]
          reviewed(url, f"{suffix}-registry", f"registry create --org andyl --name main --visibility public --trust-key {shlex.quote(trust)}", token)
          reviewed(url, f"{suffix}-placement", "placement add registry:andyl/main primary --binding instance-default --prefix registries/main --kind complete --desired-state active --read enabled", token)
          placement = json.loads(publisher.succeed(hub_command(url, "placement show registry:andyl/main primary", token)))["data"]["placement"]
          reviewed(url, f"{suffix}-scan", f"placement scan registry:andyl/main primary --wait --timeout 2m --if-version {shlex.quote(placement['resource_version'])}", token, timeout=180)
          placement = json.loads(publisher.succeed(hub_command(url, "placement show registry:andyl/main primary", token)))["data"]["placement"]
          reviewed(url, f"{suffix}-promote-placement", f"placement promote registry:andyl/main primary --if-version {shlex.quote(placement['resource_version'])}", token)
          endpoint_id = f"fleet-{suffix}-endpoint"
          reviewed(
              url, f"{suffix}-endpoint",
              f"endpoint add {url} --stable-id {endpoint_id} --org andyl --network-policy instance:public@1 --ingress hub --listener-provider hub-native --listener-resource-id aos-hub.service --probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 --probe-public-key {PROBE_KEY}",
              token,
          )
          endpoint = json.loads(publisher.succeed(hub_command(url, f"endpoint show {endpoint_id}", token)))["data"]["endpoint"]
          generation = int(endpoint["desired_generation"])
          observation = {
              "stableId": endpoint_id,
              "expectedObservationVersion": endpoint["resource_version"],
              "controllerLeaseId": f"fleet-{suffix}-lease",
              "controllerGeneration": 1,
              "observation": {
                  "observedGeneration": generation,
                  "boundaryRevision": endpoint["desired"]["boundary_revision"],
                  "state": "healthy", "listenerObserved": True, "tlsObserved": True,
              },
          }
          publisher.succeed(
              f"{CURL} -fsS -X POST -H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
              f"-H 'Authorization: Bearer {controller_token}' --data {shlex.quote(json.dumps(observation))} "
              f"{url}/aos.hub.v1.DeliveryControllerService/ReportEndpoint"
          )
          reviewed(url, f"{suffix}-route", f"route add registry:andyl/main --stable-id fleet-{suffix}-route --endpoint {endpoint_id}@{generation} --base-path /andyl/main --mode hub-proxy --placement primary --serves git --serves cache --serves web --access public", token)
          routes = json.loads(publisher.succeed(hub_command(url, "route list registry:andyl/main", token)))["data"]["routes"]
          route = next(item for item in routes if item["stable_id"] == f"fleet-{suffix}-route")
          reviewed(url, f"{suffix}-enable-route", f"route enable fleet-{suffix}-route --if-version {shlex.quote(route['resource_version'])}", token)
          for audience in ("git", "nix_cache", "web"):
              reviewed(url, f"{suffix}-canonical-{audience}", f"route canonical registry:andyl/main fleet-{suffix}-route --audience {audience}", token)


      staging_token = initialize_hub(staging, STAGING, "staging")
      production_token = initialize_hub(production, PRODUCTION, "production")

      publisher.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p /run/aos-host-store
          {MOUNT} -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro aos-host-store /run/aos-host-store
          while IFS= read -r store_path; do
            test -e "$store_path" && continue
            source_path="/run/aos-host-store/$(basename "$store_path")"
            if [ -d "$source_path" ]; then
              mkdir "$store_path"
              {MOUNT} --bind "$source_path" "$store_path"
            elif [ -f "$source_path" ]; then
              touch "$store_path"
              {MOUNT} --bind "$source_path" "$store_path"
            elif [ -L "$source_path" ]; then
              ln -s "$(readlink "$source_path")" "$store_path"
            else
              exit 1
            fi
          done < "/run/aos-host-store/$(basename {CLOSURE_INFO})/store-paths"
          {NIX_STORE} --load-db < "/run/aos-host-store/$(basename {CLOSURE_INFO})/registration"
          {FINDMNT} -rn -t 9p -o OPTIONS /run/aos-host-store | grep -qw ro
      """), timeout=180)
      for path in PACKAGES:
          publisher.succeed(f"{NIX_STORE} --check-validity {shlex.quote(path)}")
          publisher.fail(f"touch {shlex.quote(path)}/must-remain-read-only")

      trust = publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-release-publisher USER=publisher
          mkdir -p "$HOME"
          generated=$({APR} keys generate initial --registry main 2>&1)
          printf '%s\\n' "$generated" | awk '/Public key:/ {{print $NF; exit}}'
      """), timeout=120).strip()
      configure_registry(STAGING, staging_token, "staging", trust)
      configure_registry(PRODUCTION, production_token, "production", trust)

      publisher.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/aos-release-publisher USER=publisher NIX_REMOTE=""
          export NIX_CONF_DIR="$HOME/.config/nix"
          mkdir -p "$NIX_CONF_DIR" /var/tmp/base-surface /var/tmp/nars
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' > "$NIX_CONF_DIR/nix.conf"
          git config --global user.name 'Fleet Release Publisher'
          git config --global user.email 'release-publisher@example.test'
          key="$HOME/.config/apm/keys/main-initial.key"
          {APR} create main --trust-key {shlex.quote(trust)} --trust-key-id initial --key "$key"
          registry="$HOME/.local/share/apm/registries/main"
          mkdir -p "$HOME/.config/apm/registries.d"
          printf '[registry]\\nname = "main"\\nurl = "file://%s"\\n\\n[registry.signing_keys]\\ninitial = "%s"\\n' "$registry" "$key" > "$HOME/.config/apm/registries.d/main.toml"
          {APR} release 1.0.0 --registry main --store-path ${builtins.elemAt matrixPackages 0} \\
            --name fleet-base --description 'Release fleet base' --license Apache-2.0 \\
            --maintainer release@example.test --key-id initial --channel edge --init-channel \\
            --cache-url {STAGING}/andyl/main/ --upload-url file:///var/tmp/base-surface
          for path in {' '.join(PACKAGES)}; do
            {NIX_STORE} --dump "$path" > "/var/tmp/nars/$(basename "$path").nar"
          done
      """), timeout=600)
      base_commit = publisher.succeed("awk 'NR == 1 {print $1}' /var/tmp/base-surface/info/refs").strip()
      assert len(base_commit) == 64, base_commit

      for url, token in ((STAGING, staging_token), (PRODUCTION, production_token)):
          result = json.loads(publisher.succeed(
              f"{AOS} --json hub registry publish upload andyl/main --hub {url} "
              f"--token {shlex.quote(token)} --root /var/tmp/base-surface",
              timeout=600,
          ))
          assert result["data"]["state"] == "ready", result

      nar_paths = [f"/var/tmp/nars/{path.rsplit('/', 1)[1]}.nar" for path in PACKAGES]
      publisher.succeed(
          " ".join([
              FIXTURE, "prepare", "/var/tmp/base-surface", "/var/tmp/release-surface",
              "/var/tmp/release-trust", base_commit,
              *map(shlex.quote, nar_paths),
          ]),
          timeout=300,
      )
      release_key = "/var/tmp/release-trust/release.pub"
      qualification_key = "/var/tmp/release-trust/qualification.pub"
      staging_key = "/var/tmp/staging.pub"
      production_key = "/var/tmp/production.pub"
      channel_key = "/var/tmp/channel.pub"
      publisher.succeed(textwrap.dedent(f"""
          printf '%s\\n' '/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=' > {staging_key}
          printf '%s\\n' 'Zr5+Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo=' > {production_key}
          printf '%s\\n' 'C1E62bSSQBXKCQLtB5BE06xdvsIwbwaUjBDajrbjny0=' > {channel_key}
      """))

      publisher.succeed(textwrap.dedent(f"""
          {AOS} release verify /var/tmp/release-surface \\
            --trusted-key release-evidence-v1={release_key}
          {AOS} release stage --bundle /var/tmp/release-surface \\
            --journal /var/tmp/release-trust/release-journal.jsonl \\
            --trusted-key release-evidence-v1={release_key} \\
            --hub-receipt-key staging-publication-v1={staging_key} \\
            --token {shlex.quote(staging_token)} --output /var/tmp/staged
      """), timeout=900)
      publisher.succeed(textwrap.dedent(f"""
          {AOS} release qualify-run --bundle /var/tmp/release-surface \\
            --staging-receipt /var/tmp/staged/staging-receipt.json \\
            --trusted-key release-evidence-v1={release_key} \\
            --hub-receipt-key staging-publication-v1={staging_key} \\
            --executor x86_64-linux={FIXTURE} --executor aarch64-linux={FIXTURE} \\
            --executor x86_64-darwin={FIXTURE} --executor aarch64-darwin={FIXTURE} \\
            --executor-identity x86_64-linux=fleet-executor-x86_64-linux \\
            --executor-identity aarch64-linux=fleet-executor-aarch64-linux \\
            --executor-identity x86_64-darwin=fleet-executor-x86_64-darwin \\
            --executor-identity aarch64-darwin=fleet-executor-aarch64-darwin \\
            --authority-executable {FIXTURE} \\
            --authority-key qualification-v1={qualification_key} \\
            --authority-verification-identity fleet-qualification-authority \\
            --executor-nonce {'3' * 64} --authority-nonce {'4' * 64} \\
            --qualified-at 2026-09-03T12:00:00Z --output /var/tmp/qualification-run
          {AOS} release qualify --bundle /var/tmp/release-surface \\
            --journal /var/tmp/staged/release-journal.jsonl \\
            --staging-receipt /var/tmp/staged/staging-receipt.json \\
            --signed-qualification /var/tmp/qualification-run/signed-qualification.json \\
            --qualification-report /var/tmp/qualification-run/qualification-report.json \\
            --trusted-key release-evidence-v1={release_key} \\
            --hub-receipt-key staging-publication-v1={staging_key} \\
            --qualification-key qualification-v1={qualification_key} \\
            --token {shlex.quote(staging_token)} --output /var/tmp/qualified
      """), timeout=900)
      publisher.succeed(textwrap.dedent(f"""
          {AOS} release promote --bundle /var/tmp/release-surface \\
            --journal /var/tmp/qualified/release-journal.jsonl \\
            --staging-receipt /var/tmp/staged/staging-receipt.json \\
            --qualification-receipt /var/tmp/qualified/qualification-receipt.json \\
            --signed-qualification /var/tmp/qualified/signed-qualification.json \\
            --qualification-report /var/tmp/qualified/qualification-report.json \\
            --trusted-key release-evidence-v1={release_key} \\
            --staging-receipt-key staging-publication-v1={staging_key} \\
            --qualification-key qualification-v1={qualification_key} \\
            --production-receipt-key production-publication-v1={production_key} \\
            --token {shlex.quote(production_token)} --output /var/tmp/promoted
          {AOS} release channel advance --bundle /var/tmp/release-surface \\
            --journal /var/tmp/promoted/release-journal.jsonl \\
            --production-receipt /var/tmp/promoted/production-receipt.json \\
            --channel edge --prior-generation 0 --first-partition 0 --last-partition 255 \\
            --trusted-key release-evidence-v1={release_key} \\
            --production-receipt-key production-publication-v1={production_key} \\
            --channel-receipt-key production-channel-v1={channel_key} \\
            --token {shlex.quote(production_token)} --output /var/tmp/rolling
          {FIXTURE} completion /var/tmp/release-surface/release-plan.json \\
            /var/tmp/release-surface/release-manifest.json \\
            /var/tmp/promoted/production-receipt.json /var/tmp/rolling/channel-receipt.json \\
            /var/tmp/rolling/release-journal.jsonl /var/tmp/completion-receipt.json
          {AOS} release channel complete --bundle /var/tmp/release-surface \\
            --journal /var/tmp/rolling/release-journal.jsonl \\
            --production-receipt /var/tmp/promoted/production-receipt.json \\
            --channel-receipt /var/tmp/rolling/channel-receipt.json \\
            --completion-receipt /var/tmp/completion-receipt.json \\
            --trusted-key release-evidence-v1={release_key} \\
            --production-receipt-key production-publication-v1={production_key} \\
            --channel-receipt-key production-channel-v1={channel_key} \\
            --completion-key release-evidence-v1={release_key} \\
            --output /var/tmp/complete
          {AOS} release status --journal /var/tmp/complete/release-journal.jsonl | grep -q complete
      """), timeout=900)

      report = json.loads(publisher.succeed(
          f"{JQ} -c . /var/tmp/qualification-run/qualification-report.json"
      ))
      assert len(report["evidence"]) == 4, report
      assert {item["platform"] for item in report["evidence"]} == {
          "x86_64-linux", "aarch64-linux", "x86_64-darwin", "aarch64-darwin",
      }, report
      publisher.succeed(f"{CURL} -fsS {PRODUCTION}/andyl/main/channels/edge/00 >/dev/null")
    '';
}
