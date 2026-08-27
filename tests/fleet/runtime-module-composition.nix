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
  systemReadyTimeout = 0;

  machines.runtime = {
    system = runtimeSystem;
    memoryMiB = 4096;
    varSizeMiB = 2048;
    packages = [
      "aos-test-agent"
      "envoy"
      "k3s-worker"
      "nginx"
    ];
    extraClosures = [
      pkgs.diffutils
      pkgs.grep
    ];
    metadata."host.nix" = ''
      {
        aos.networking.hostName = "runtime-modules";
        aos.apm.desiredPackages = [ "aos-test-agent" ];

        environment.etc."runtime-modules/platform.conf" = {
          text = "authority=platform\n";
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
      CURL = "${pkgs.curl}/bin/curl"
      JQ = "${pkgs.jq}/bin/jq"
      SHA256SUM = "${pkgs.coreutils}/bin/sha256sum"


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
              f"{APM} config apply{dry_run_flag} --eval-root '{eval_root}'",
              timeout=600,
          )


      def assert_package_configuration():
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/platform.conf)\" = authority=platform"
          )
          runtime.succeed(
              "test \"$(cat /etc/runtime-modules/operator.conf)\" = authority=runtime"
          )

          runtime.wait_until_succeeds(
              "systemctl is-active --quiet nginx.service", timeout=120
          )
          nginx_body = runtime.succeed(
              f"{CURL} --fail --silent http://127.0.0.1:18080/health"
          )
          assert nginx_body == "nginx-runtime", nginx_body
          runtime.succeed("grep -q 'listen 18080;' /etc/nginx/nginx.conf")

          runtime.wait_until_succeeds(
              "systemctl is-active --quiet envoy.service", timeout=120
          )
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


      wait_for_activation()
      runtime.succeed("systemctl is-active --quiet multi-user.target")
      platform_hash = runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0]
      initial = current_generation()

      status = runtime.succeed(f"{APM} config status")
      assert "active runtime modules: empty" in status, status
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
      runtime.succeed(f"""
          {APM} config add /run/runtime-module-fixtures/10-packages.nix
          {APM} config add /run/runtime-module-fixtures/20-services.nix
      """)
      listed = runtime.succeed(f"{APM} config list").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed
      status = runtime.succeed(f"{APM} config status")
      assert "worktree: /var/lib/aos/config/modules.d (2 entrypoints)" in status, status

      # `diff` and `apply --dry-run` use the same full fixpoint as activation
      # but must leave both the current pointer and live files untouched.
      runtime.succeed(
          f"{APM} config diff --eval-root /run/runtime-module-composition-diff",
          timeout=600,
      )
      apply_worktree("/run/runtime-module-composition-dry-run", dry_run=True)
      assert current_generation() == initial
      runtime.fail("test -e /etc/runtime-modules/operator.conf")

      apply_worktree("/run/runtime-module-composition-switch")
      configured = current_generation()
      assert configured != initial, (initial, configured)
      assert_package_configuration()

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
      status = runtime.succeed(f"{APM} config status")
      assert runtime_input["store_path"] in status, status
      assert "active runtime modules:" in status, status
      assert "(2 entrypoints," in status, status
      assert manifest["inputs"]["host_nix"]["store_path"].startswith(
          "/nix/store/"
      )
      assert runtime.succeed(
          f"{SHA256SUM} /run/aos-metadata/host.nix"
      ).split()[0] == platform_hash

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
          if {APM} config apply \\
            --eval-root /run/runtime-module-composition-invalid \\
            >/run/runtime-module-composition-invalid.out 2>&1; then
            echo 'invalid runtime module candidate unexpectedly succeeded' >&2
            exit 1
          fi
      """), timeout=600)
      assert current_generation() == configured
      assert_package_configuration()
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list").splitlines()
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
      listed = runtime.succeed(f"{APM} config list").splitlines()
      assert listed == ["10-packages.nix"], listed
      status = runtime.succeed(f"{APM} config status")
      assert runtime_input["store_path"] in status, status
      assert "worktree: /var/lib/aos/config/modules.d (1 entrypoints)" in status, status

      runtime.reboot_without_metadata()
      wait_for_activation()
      assert current_generation() == configured
      assert_package_configuration()
      reboot_manifest = json.loads(runtime.succeed(
          "cat /run/aos/manifest.json"
      ))
      assert reboot_manifest["inputs"]["runtime_modules"] == runtime_input
      assert runtime.succeed(
          f"{SHA256SUM} /var/lib/aos-provisioning/current/host.nix"
      ).split()[0] == platform_hash
      runtime.succeed(f"{APM} config discard")
      listed = runtime.succeed(f"{APM} config list").splitlines()
      assert listed == ["10-packages.nix", "20-services.nix"], listed
    '';
}
