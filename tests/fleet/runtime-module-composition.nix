##! Runtime module-set and package configuration acceptance.
##!
##! This suite deliberately keeps the cloud-delivered platform host module
##! small, then applies two independently authored runtime fragments. The
##! fragments select and configure package-owned nginx, Envoy, and k3s
##! interfaces through the production on-host evaluator. The test also proves
##! that failed candidates do not disturb the current generation and that a
##! reboot consumes the retained immutable module set rather than the dirty
##! authoring worktree.
{
  mkSystem,
  pkgs,
  systems,
  ...
}: let
  runtimeSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages = {
        nginx = {
          package = pkgs.nginx;
          bundle = true;
          preset = false;
        };
        envoy = {
          package = pkgs.envoy;
          bundle = true;
          preset = false;
        };
        k3s-worker = {
          package = pkgs.k3s-worker;
          bundle = true;
          preset = false;
        };
      };
    }
  ];
in {
  name = "runtime-module-composition";
  timeout = 1800;
  # The full fleet umbrella boots many KVM guests concurrently. Initial host
  # evaluation can legitimately exceed the generic 180-second readiness
  # deadline under that load, before this test's own bounded apply steps begin.
  bootTimeout = 600;
  systemReadyTimeout = 0;

  machines.runtime = {
    system = runtimeSystem;
    memoryMiB = 4096;
    varSizeMiB = 2048;
    packages = [
      "aos-test-agent"
      "envoy"
      "k3s-worker"
    ];
    extraClosures = [
      pkgs.diffutils
      pkgs.git
      pkgs.grep
      pkgs.nix
    ];
    metadata."host.nix" = ''
      {
        aos.networking.hostName = "runtime-modules";

        environment.etc."runtime-modules/platform.conf" = {
          text = "authority=platform\n";
          mode = "0644";
        };

        # This fixture deliberately installs nginx through APM. Its signed
        # service manifest requests host networking and a bounded capability,
        # so exercise the production admission path with an explicit host
        # policy rather than bypassing permission checks.
        environment.etc."aos/policy.toml" = {
          text = "tier = \"privileged\"\n";
          mode = "0644";
        };
      }
    '';
  };

  testScript =
    # python
    ''
      import base64
      import json
      import textwrap

      APM = "${pkgs.aos}/bin/apm"
      APR = "${pkgs.aos}/bin/apr"
      CURL = "${pkgs.curl}/bin/curl"
      JQ = "${pkgs.jq}/bin/jq"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      SHA256SUM = "${pkgs.coreutils}/bin/sha256sum"
      XDG_CACHE_HOME = "/var/cache/aos-runtime-module-test"


      def wait_for_activation():
          runtime.wait_until_succeeds(
              "test -s /run/aos/manifest.json "
              "&& test -s /run/aos/graph.json "
              "&& test -s /run/aos/activation.json",
              timeout=300,
          )
          runtime.wait_until_succeeds(
              "systemctl is-active --quiet aos-config.target", timeout=300
          )


      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def write_file(path, contents):
          encoded = base64.b64encode(contents.encode()).decode()
          runtime.succeed(
              f"printf '%s' '{encoded}' | base64 -d > '{path}'"
          )


      def apply_worktree(eval_root, dry_run=False):
          dry_run_flag = " --dry-run" if dry_run else ""
          runtime.succeed(
              f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config apply{dry_run_flag} "
              f"--eval-root '{eval_root}'",
              timeout=600,
          )


      def wait_for_service(unit):
          try:
              runtime.wait_until_succeeds(
                  f"systemctl is-active --quiet {unit}", timeout=120
              )
          except Exception:
              print(runtime.succeed(
                  f"systemctl status --no-pager --full {unit} || true; "
                  f"journalctl --no-pager -u {unit} -n 100 || true"
              ))
              raise


      def assert_package_configuration():
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/platform.conf)\" = authority=platform"
          )
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/operator.conf)\" = authority=runtime"
          )

          wait_for_service("nginx.service")
          nginx_body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:18080/health"
          )
          assert nginx_body == "nginx-runtime", nginx_body
          runtime.succeed("grep -q 'listen 18080;' /etc/nginx/nginx.conf")

          wait_for_service("envoy.service")
          envoy_body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:18081/health"
          )
          assert envoy_body == "envoy-runtime", envoy_body
          runtime.succeed(
              f"{JQ} -e '.static_resources.listeners | length == 1' "
              "/etc/aos/packages/envoy/bootstrap.json"
          )

          # A worker without a real control plane is intentionally disabled;
          # its package target and fully rendered typed configuration still
          # exercise the k3s module/expose boundary without asserting a false
          # readiness signal.
          runtime.succeed(
              "systemctl is-active --quiet aos-pkg-k3s-worker.target"
          )
          runtime.fail("systemctl is-active --quiet k3s.service")
          runtime.succeed(
              "grep -qx 'K3S_ENABLED=false' "
              "/etc/aos/packages/k3s-worker/k3s.env"
          )
          runtime.succeed(
              "grep -qx 'K3S_NODE_NAME=runtime-worker' "
              "/etc/aos/packages/k3s-worker/k3s.env"
          )
          runtime.succeed(
              "grep -qx 'K3S_FLANNEL_BACKEND=wireguard-native' "
              "/etc/aos/packages/k3s-worker/k3s.env"
          )


      def payload_nar_hash(path):
          return runtime.succeed(
              f"{NIX_STORE} --dump '{path}' | {SHA256SUM}"
          ).split()[0]


      def assert_payloads_immutable():
          assert payload_nar_hash("${pkgs.nginx}") == payload_hashes["nginx"]
          assert payload_nar_hash("${pkgs.envoy}") == payload_hashes["envoy"]


      wait_for_activation()
      runtime.succeed("systemctl is-active --quiet multi-user.target")
      runtime.succeed(f"install -d -m 0700 {XDG_CACHE_HOME}")
      platform_hash = runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0]
      initial = current_generation()
      initial_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{initial}/manifest.json"
      ))
      platform_host_input = initial_manifest["inputs"]["host_nix"]
      platform_facts_input = initial_manifest["inputs"]["instance_facts"]
      payload_hashes = {
          "nginx": payload_nar_hash("${pkgs.nginx}"),
          "envoy": payload_nar_hash("${pkgs.envoy}"),
      }

      status = runtime.succeed(f"{APM} config status 2>&1")
      assert "active runtime modules: empty" in status, status

      # Nginx is bundled in the immutable image but deliberately absent from
      # the seeded package profile. Publish its package/expose pair into a
      # local authenticated registry and select it through public APM before
      # supplying any operator configuration module.
      runtime.fail(
          f"HOME=/tmp USER=root {APM} list --system --installed "
          "2>&1 | grep -q '^nginx'"
      )
      runtime.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp/runtime-publisher
          export USER=root
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export GIT_AUTHOR_NAME=Test
          export GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test
          export GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/runtime-nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\n' \
            > "$NIX_CONF_DIR/nix.conf"

          {APR} keys generate release --registry runtime-reg \
            > /tmp/runtime-keygen.out 2>&1
          PUBKEY=$(awk '/Public key:/ {{print $NF; exit}}' /tmp/runtime-keygen.out)
          KEY=$HOME/.config/apm/keys/runtime-reg-release.key
          {APR} create runtime-reg \
            --trust-key "$PUBKEY" \
            --trust-key-id release \
            --key "$KEY"
          mkdir -p "$HOME/.config/apm/registries.d"
          cat > "$HOME/.config/apm/registries.d/runtime-reg.toml" <<EOF
          [registry]
          name = "runtime-reg"
          url = "file://$HOME/.local/share/apm/registries/runtime-reg"

          [registry.signing_keys]
          release = "$KEY"

          [registry.signing]
          root_owner_signers = ["release"]
          EOF

          {APR} publish '${pkgs.nginx}' \
            --name nginx \
            --version '${pkgs.nginx.version}' \
            --description 'runtime module acceptance fixture' \
            --license BSD-2-Clause \
            --maintainer test \
            --expose-manifest '${pkgs.nginx.expose}/manifest.json' \
            --config-module '${pkgs.nginx.config}' \
            --config-base-lib '${runtimeSystem.config.aos.config.evalAtBoot.baseLib}' \
            --registry runtime-reg \
            --key-id release

          REG_DIR=$HOME/.local/share/apm/registries/runtime-reg
          mkdir -p /var/lib/runtime-module-registry-cache
          {APR} release '${pkgs.nginx.version}' \
            --registry runtime-reg \
            --key-id release \
            --cache-url file:///var/lib/runtime-module-registry-cache \
            --upload-url file:///var/lib/runtime-module-registry-cache

          HOME=/tmp USER=root {APM} registry --system add \
            "file://$REG_DIR" \
            --name runtime-reg \
            --version '=${pkgs.nginx.version}' \
            --trust-key "$PUBKEY"
          printf 'root_owner_signers = ["release"]\n' \
            >> /var/lib/apm/config/registries.d/runtime-reg.toml
          HOME=/tmp USER=root {APM} update \
            --system --registry runtime-reg

          cat > /run/runtime-module-desired.toml <<'EOF'
          packages = ["nginx", "envoy", "k3s-worker"]
          EOF
          HOME=/tmp USER=root {APM} install --system \
            --from /run/runtime-module-desired.toml --yes

      """), timeout=1200)
      installed = runtime.succeed(
          f"HOME=/tmp USER=root {APM} list --system --installed 2>&1"
      )
      assert "nginx" in installed, installed

      runtime.succeed("install -d -m 0700 /run/runtime-module-fixtures")
      packages_module = """{
        aos.apm.desiredPackages = [ "nginx" "envoy" "k3s-worker" ];
        environment.etc."runtime-modules/operator.conf" = {
          text = "authority=runtime\\n";
          mode = "0644";
        };
      }
      """
      services_module = """{
        nginx = {
          enable = true;
          virtualHosts.runtime = {
            listen = [ 18080 ];
            serverNames = [ "localhost" ];
            locations."/health"."return" = {
              code = 200;
              body = "nginx-runtime";
            };
          };
        };

        envoy = {
          enable = true;
          listeners.runtime = {
            address = "127.0.0.1";
            port = 18081;
            filterChains.http.virtualHosts.runtime = {
              domains = [ "*" ];
              routes.health = {
                match.path = "/health";
                match.prefix = null;
                directResponse = {
                  status = 200;
                  body = "envoy-runtime";
                };
              };
            };
          };
        };

        k3s = {
          enable = false;
          node.name = "runtime-worker";
          networking.flannelBackend = "wireguard-native";
        };
      }
      """
      write_file(
          "/run/runtime-module-fixtures/10-packages.nix", packages_module
      )
      write_file(
          "/run/runtime-module-fixtures/20-services.nix", services_module
      )
      runtime.fail(
          f"{APM} config add /run/runtime-module-fixtures/10-packages.nix "
          "--name 'bad;name.nix'"
      )
      runtime.fail(
          "test -e '/var/lib/aos/config/modules.d/bad;name.nix'"
      )
      runtime.succeed(f"""
          {APM} config add /run/runtime-module-fixtures/10-packages.nix
          {APM} config add /run/runtime-module-fixtures/20-services.nix
      """)
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert "worktree: /var/lib/aos/config/modules.d (2 entrypoints)" in status, status

      # `diff` and `apply --dry-run` use the same full fixpoint as activation
      # but must leave both the current pointer and live files untouched.
      runtime.succeed(
          f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config diff "
          "--eval-root /run/runtime-module-composition-diff",
          timeout=600,
      )
      apply_worktree("/run/runtime-module-composition-dry-run", dry_run=True)
      assert current_generation() == initial
      runtime.fail("test -e /etc/runtime-modules/operator.conf")

      apply_worktree("/run/runtime-module-composition-switch")
      configured = current_generation()
      assert configured != initial, (initial, configured)
      assert_package_configuration()
      assert_payloads_immutable()

      manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert manifest["schema"] == "aos.config-manifest/v2", manifest["schema"]
      runtime_input = manifest["inputs"]["runtime_modules"]
      assert runtime_input["schema"] == "aos.runtime-module-set/v1", runtime_input
      assert runtime_input["trust_mode"] == "local-root", runtime_input
      assert runtime_input["store_path"].startswith("/nix/store/"), runtime_input
      assert runtime_input["entrypoints"] == [
          "10-packages.nix",
          "20-services.nix",
      ], runtime_input
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "active runtime modules:" in status, status
      assert "(2 entrypoints," in status, status
      assert manifest["inputs"]["host_nix"]["store_path"].startswith(
          "/nix/store/"
      )
      assert manifest["inputs"]["host_nix"] == platform_host_input
      assert manifest["inputs"]["instance_facts"] == platform_facts_input
      assert runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0] == platform_hash

      # Ordinary switch porcelain defaults to the active retained runtime set,
      # rather than silently dropping supplemental modules. Inspect the new
      # no-op generation to prove all three input identities survive.
      previous_configured = configured
      runtime.succeed(
          f"XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} switch "
          "--eval-root /run/runtime-module-composition-no-op",
          timeout=600,
      )
      configured = current_generation()
      assert configured != previous_configured, (previous_configured, configured)
      switch_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert switch_manifest["inputs"]["runtime_modules"] == runtime_input
      assert switch_manifest["inputs"]["host_nix"] == platform_host_input
      assert switch_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert (
          switch_manifest["inputs"]["expected_current_generation"]
          == previous_configured
      )
      assert_package_configuration()
      assert_payloads_immutable()

      # A bad supplemental fragment must fail before activation and preserve
      # both the durable pointer and live package state.
      invalid_module = """{
        aos.apm.desiredPackages = [ "nginx" "envoy" "k3s-worker" ];
        aos.runtimeModules.thisOptionDoesNotExist = true;
      }
      """
      write_file(
          "/run/runtime-module-fixtures/invalid.nix", invalid_module
      )
      runtime.succeed(
          f"{APM} config replace 20-services.nix "
          "/run/runtime-module-fixtures/invalid.nix"
      )
      runtime.succeed(textwrap.dedent(f"""
          set -eu
          if XDG_CACHE_HOME={XDG_CACHE_HOME} {APM} config apply \\
            --eval-root /run/runtime-module-composition-invalid \\
            >/run/runtime-module-composition-invalid.out 2>&1; then
            echo 'invalid runtime module candidate unexpectedly succeeded' >&2
            exit 1
          fi
      """), timeout=600)
      assert current_generation() == configured
      assert_package_configuration()
      assert_payloads_immutable()
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed

      # Deliberately replace the mutable worktree with valid but hostile
      # content. Boot authority must remain the retained generation snapshot.
      dirty_module = """{
        environment.etc."runtime-modules/operator.conf".text = "DIRTY\\n";
        nginx.enable = false;
        envoy.enable = false;
      }
      """
      write_file(
          "/run/runtime-module-fixtures/dirty.nix", dirty_module
      )
      runtime.succeed(f"{APM} config replace 10-packages.nix /run/runtime-module-fixtures/dirty.nix")
      runtime.succeed(f"{APM} config remove 20-services.nix")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix"], listed
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "worktree: /var/lib/aos/config/modules.d (1 entrypoints)" in status, status

      runtime.reboot_without_metadata()
      wait_for_activation()
      rebooted = current_generation()
      assert rebooted != configured, (configured, rebooted)
      assert_package_configuration()
      assert_payloads_immutable()
      reboot_manifest = json.loads(runtime.succeed(
          "cat /run/aos/manifest.json"
      ))
      assert reboot_manifest["inputs"]["runtime_modules"] == runtime_input
      assert reboot_manifest["inputs"]["host_nix"] == platform_host_input
      assert reboot_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert reboot_manifest["inputs"]["expected_current_generation"] == configured
      configured = rebooted
      assert runtime.succeed(
          f"{SHA256SUM} /var/lib/aos-provisioning/current/host.nix"
      ).split()[0] == platform_hash
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list 2>&1").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed

      # Removing the final entrypoint is itself an ordinary compare-and-switch
      # candidate. It must durably record the absence of runtime input rather
      # than falling back to the previous retained set on the next boot.
      runtime.succeed(f"{APM} config remove 10-packages.nix")
      runtime.succeed(f"{APM} config remove 20-services.nix")
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      apply_worktree("/run/runtime-module-composition-clear")
      cleared = current_generation()
      assert cleared != configured, (configured, cleared)
      cleared_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{cleared}/manifest.json"
      ))
      cleared_runtime_input = cleared_manifest["inputs"]["runtime_modules"]
      assert cleared_runtime_input["schema"] == "aos.runtime-module-set/v1"
      assert cleared_runtime_input["trust_mode"] == "local-root"
      assert cleared_runtime_input["store_path"].startswith("/nix/store/")
      assert cleared_runtime_input["entrypoints"] == []
      assert cleared_manifest["inputs"]["expected_current_generation"] == configured
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert cleared_runtime_input["store_path"] in status, status
      assert "(0 entrypoints," in status, status
      assert "worktree: /var/lib/aos/config/modules.d (0 entrypoints)" in status, status
      runtime.fail("test -e /etc/runtime-modules/operator.conf")
      runtime.wait_until_succeeds(
          "! systemctl is-active --quiet nginx.service", timeout=120
      )
      runtime.wait_until_succeeds(
          "! systemctl is-active --quiet envoy.service", timeout=120
      )

      runtime.reboot_without_metadata()
      wait_for_activation()
      rebooted_cleared = current_generation()
      assert rebooted_cleared != cleared, (cleared, rebooted_cleared)
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert cleared_runtime_input["store_path"] in status, status
      assert "(0 entrypoints," in status, status
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      reboot_manifest = json.loads(runtime.succeed("cat /run/aos/manifest.json"))
      assert (
          reboot_manifest["inputs"]["runtime_modules"]
          == cleared_runtime_input
      )
      assert reboot_manifest["inputs"]["host_nix"] == platform_host_input
      assert reboot_manifest["inputs"]["instance_facts"] == platform_facts_input
      assert reboot_manifest["inputs"]["expected_current_generation"] == cleared
      cleared = rebooted_cleared
      runtime.fail("test -e /etc/runtime-modules/operator.conf")
      runtime.fail("systemctl is-active --quiet nginx.service")
      runtime.fail("systemctl is-active --quiet envoy.service")
      assert runtime.succeed(
          f"{SHA256SUM} /var/lib/aos-provisioning/current/host.nix"
      ).split()[0] == platform_hash

      # Same-ABI rollback must reactivate the selected generation's immutable
      # runtime module set, not the currently empty authoring worktree or the
      # runtime descriptor from the generation being left behind.
      runtime.succeed(
          f"{APM} rollback --system --generation {configured}", timeout=600
      )
      assert current_generation() == configured
      rollback_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{configured}/manifest.json"
      ))
      assert rollback_manifest["inputs"]["runtime_modules"] == runtime_input
      assert rollback_manifest["inputs"]["host_nix"] == platform_host_input
      assert rollback_manifest["inputs"]["instance_facts"] == platform_facts_input
      status = runtime.succeed(f"{APM} config status 2>&1")
      assert runtime_input["store_path"] in status, status
      assert "(2 entrypoints," in status, status
      assert "worktree: /var/lib/aos/config/modules.d (0 entrypoints)" in status, status
      assert runtime.succeed(f"{APM} config list 2>&1") == ""
      assert_package_configuration()
      assert_payloads_immutable()
    '';
}
