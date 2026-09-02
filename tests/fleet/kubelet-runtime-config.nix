##! Standalone kubelet and containerd runtime-configuration lifecycle.
{
  mkSystem,
  pkgs,
  ...
}: let
  runtimeSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages = {
        containerd = {
          package = pkgs.containerd;
          bundle = true;
          preset = false;
        };
        kubelet = {
          package = pkgs.kubelet;
          bundle = true;
          preset = false;
        };
      };
    }
  ];
in {
  name = "kubelet-runtime-config";
  timeout = 1800;
  bootTimeout = 600;
  systemReadyTimeout = 0;

  machines.node = {
    system = runtimeSystem;
    memoryMiB = 4096;
    varSizeMiB = 4096;
    packages = [
      "aos-test-agent"
      "containerd"
      "kubelet"
    ];
    extraClosures = [pkgs.crictl pkgs.curl pkgs.grep pkgs.jq];
    metadata."host.nix" = ''
      {
        aos.networking.hostName = "standalone-kubelet";
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

      APM = "${pkgs.aos.apm}/bin/apm"
      CRICTL = "${pkgs.crictl}/bin/crictl"
      CURL = "${pkgs.curl}/bin/curl"
      GREP = "${pkgs.grep}/bin/grep"
      JQ = "${pkgs.jq}/bin/jq"
      CACHE = "/var/cache/aos-kubelet-runtime-test"


      def generation():
          return int(node.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def write_file(path, contents):
          encoded = base64.b64encode(contents.encode()).decode()
          node.succeed(f"printf '%s' '{encoded}' | base64 -d > '{path}'")


      def apply(root):
          node.succeed(
              f"XDG_CACHE_HOME={CACHE} {APM} config apply --eval-root '{root}'",
              timeout=600,
          )


      def assert_running(node_name, max_pods):
          node.wait_until_succeeds(
              "systemctl is-active --quiet containerd.service", timeout=180
          )
          node.wait_until_succeeds(
              "systemctl is-active --quiet kubelet.service", timeout=180
          )
          node.wait_until_succeeds(
              f"{CURL} --fail --silent http://127.0.0.1:10248/healthz | {GREP} -qx ok",
              timeout=180,
          )
          node.succeed(
              f"{CRICTL} --runtime-endpoint unix:///run/containerd/containerd.sock "
              "--image-endpoint unix:///run/containerd/containerd.sock info >/dev/null"
          )
          node.succeed(
              f"{GREP} -qx 'KUBELET_NODE_NAME={node_name}' "
              "/etc/aos/packages/kubelet/runtime.env"
          )
          config = json.loads(node.succeed(
              "cat /etc/aos/packages/kubelet/config.json"
          ))
          assert config["maxPods"] == max_pods, config
          assert config["registerNode"] is False, config
          assert config["authentication"]["webhook"]["enabled"] is False, config
          assert config["authorization"]["mode"] == "AlwaysAllow", config
          assert config["containerRuntimeEndpoint"] == (
              "unix:///run/containerd/containerd.sock"
          ), config


      node.wait_until_succeeds(
          "systemctl is-active --quiet aos-config.target", timeout=300
      )
      node.succeed(
          f"{JQ} -s -e "
          "'map(select(.apm.name == \"kubelet\"))[0]"
          ".apm.config_module.artifacts.etc "
          "== [\"aos/packages/kubelet/config.json\"]' "
          "/var/lib/profiles/system-packages/current/meta/*.json"
      )
      node.succeed(f"install -d -m 0700 {CACHE} /run/kubelet-runtime")
      initial = generation()

      module = """{
        aos.apm.desiredPackages = [ "containerd" "kubelet" ];
        containerd = {
          enable = true;
          systemdCgroup = true;
        };
        kubelet = {
          enable = true;
          nodeName = "standalone-a";
          registerNode = false;
          failSwapOn = false;
          maxPods = 42;
        };
      }
      """
      write_file("/run/kubelet-runtime/10-runtime.nix", module)
      node.succeed(f"{APM} config add /run/kubelet-runtime/10-runtime.nix")

      node.succeed(
          f"XDG_CACHE_HOME={CACHE} {APM} config diff "
          "--eval-root /run/kubelet-runtime-diff",
          timeout=600,
      )
      node.succeed(
          f"XDG_CACHE_HOME={CACHE} {APM} config apply --dry-run "
          "--eval-root /run/kubelet-runtime-dry-run",
          timeout=600,
      )
      assert generation() == initial
      node.fail("systemctl is-active --quiet kubelet.service")

      apply("/run/kubelet-runtime-apply")
      configured = generation()
      assert configured != initial, (initial, configured)
      assert_running("standalone-a", 42)

      invalid = module.replace("maxPods = 42;", "maxPods = 0;")
      write_file("/run/kubelet-runtime/invalid.nix", invalid)
      node.succeed(
          f"{APM} config replace 10-runtime.nix /run/kubelet-runtime/invalid.nix"
      )
      node.fail(
          f"XDG_CACHE_HOME={CACHE} {APM} config apply "
          "--eval-root /run/kubelet-runtime-invalid",
          timeout=600,
      )
      assert generation() == configured
      assert_running("standalone-a", 42)
      node.succeed(f"{APM} config discard")

      replacement = module.replace("standalone-a", "standalone-b").replace(
          "maxPods = 42;", "maxPods = 64;"
      )
      write_file("/run/kubelet-runtime/replacement.nix", replacement)
      node.succeed(
          f"{APM} config replace 10-runtime.nix "
          "/run/kubelet-runtime/replacement.nix"
      )
      apply("/run/kubelet-runtime-replace")
      replaced = generation()
      assert replaced != configured, (configured, replaced)
      assert_running("standalone-b", 64)

      node.reboot_without_metadata()
      node.wait_until_succeeds(
          "systemctl is-active --quiet aos-config.target", timeout=300
      )
      assert_running("standalone-b", 64)
      rebooted = generation()
      assert rebooted != replaced, (replaced, rebooted)

      node.succeed(f"{APM} config remove 10-runtime.nix")
      apply("/run/kubelet-runtime-disable")
      node.wait_until_succeeds(
          "! systemctl is-active --quiet kubelet.service", timeout=180
      )
      node.wait_until_succeeds(
          "! systemctl is-active --quiet containerd.service", timeout=180
      )

      node.succeed(
          f"{APM} rollback --system --generation {rebooted}", timeout=600
      )
      assert generation() == rebooted
      assert_running("standalone-b", 64)
    '';
}
