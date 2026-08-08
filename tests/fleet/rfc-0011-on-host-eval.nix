# General runtime host.nix activation acceptance.
#
# This is the load-bearing on-host evaluation acceptance gate. Unlike the
# provisioning test, the machine identity exercised here is not baked into the
# image: literal metadata host.nix overrides the baked hostname and contributes
# an /etc artifact, account, service, and desired package through the production
# aos-eval -> aos-graph-compile -> aos-activate transaction.
{
  pkgs,
  systems,
  ...
}: let
  testCertificate = builtins.concatStringsSep "\n" [
    "-----BEGIN CERTIFICATE-----"
    "MIIDHzCCAgegAwIBAgIEB1vNFTANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxB"
    "T1MgVGVzdCBVbnRydXN0ZWQgUm9vdEltYWdlMB4XDTI2MDYxODEzMjgyOFoXDTM2"
    "MDYxNTEzMjgyOFowJzElMCMGA1UEAwwcQU9TIFRlc3QgVW50cnVzdGVkIFJvb3RJ"
    "bWFnZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnmzOy6TN0du3f9"
    "UPhB+QuNNNSdFsIk1q+SXyDdky1TwoqiFDhqTA8DxyirtyHCm942+lZTdiAl+CNs"
    "AW2e95ba9Mo6h63YlvjEI+194gs2K/4K2SQd8L2ca4kTEK/RzJvnnMbRdqNYrnBB"
    "4BmGdHwvwnJjvNSv8+OQosrr7g1JpOCdkvaIv0N4kC5rD6S5aIs3Pbn1EuwraPVd"
    "8jF97i/dve4/xEnbCkTtRZY5FKT6IMeVAJmdCGsl/s9ZGzsK+ETllFdakXYnQNq9"
    "3pSdIzlSjxyLr4yhOoW5S2ZipwFoaIqD5Y8M/9NUBWdtaAbwF2G0Sbstopviuzfw"
    "TtDInfUCAwEAAaNTMFEwHQYDVR0OBBYEFKbYs+MTbZpdos0cmveR4g3Iw049MB8G"
    "A1UdIwQYMBaAFKbYs+MTbZpdos0cmveR4g3Iw049MA8GA1UdEwEB/wQFMAMBAf8w"
    "DQYJKoZIhvcNAQELBQADggEBAKuo0WhnQaUUDV4pw7W8tSm4S/MMfxwf7IbhYbhN"
    "fB9QOHK4HrL5XuPtLviFe1m5tEaLT8UJxAf1MOZGtjbZrvMyM2erKJznpPYMzGuH"
    "L6OoBKpqy+jj9Tc2fWqJ++Cc3cYWYbqT3j64LxtKnXgVupPwou1vMoSbtQoL6B9X"
    "6NMDaKWEekkA9gN8gG0oQHoGJ9BuANq/6WQajWmHQSj35+BOuoBLREGCt3+boiXV"
    "VXmMO9a57Idz4SaiM7+PazqjUHY/TwzQt8wZ1XmnfF6m9DfnyJ2rHFoHPMo3siMZ"
    "Hm4HoUiqbsjn/ojh4G5jF7O52NmARcWLE+9eDRkSQ0BZdqI="
    "-----END CERTIFICATE-----"
    ""
  ];
in {
  name = "rfc-0011-on-host-eval";
  timeout = 1500;
  # This test waits for the evaluator/graph transaction explicitly and emits
  # focused unit diagnostics on failure.
  systemReadyTimeout = 0;

  machines.runtime = {
    system = systems.server-test;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent"];
    extraClosures = [
      pkgs.diffutils
      pkgs.grep
    ];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.networking.hostName = "runtime-one";
        aos.apm.desiredPackages = [ "aos-test-agent" ];

        environment.etc."rfc0011/runtime.conf" = {
          text = "generation=one\n";
          mode = "0644";
        };

        aos.users.groups.rfc0011 = {
          gid = 976;
          members = [];
        };
        aos.users.users.rfc0011 = {
          uid = 976;
          group = "rfc0011";
          home = "/var/lib/rfc0011";
          shell = "/bin/bash";
          description = "Runtime-configured host user";
          extraGroups = [];
        };

        systemd.services.rfc0011-host = {
          description = "Runtime-configured host service";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = "printf one > /run/rfc0011-host-service";
        };
      }
    '';
  };

  # A separate no-metadata machine proves that the porcelain default follows
  # the same image-authored empty-module arm as boot evaluation.
  machines.image_default = {
    system = systems.server-test;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
  };

  testScript =
    # python
    ''
      import base64
      import json

      JQ = "${pkgs.jq}/bin/jq"
      APM = "${pkgs.aos}/bin/apm"
      CMP = "${pkgs.diffutils}/bin/cmp"
      GREP = "${pkgs.grep}/bin/grep"


      def properties(unit, names):
          output = runtime.succeed(
              "systemctl show " + unit + " "
              + " ".join(f"--property={name}" for name in names)
          )
          result = {}
          for line in output.splitlines():
              key, separator, value = line.partition("=")
              assert separator, f"malformed systemctl property line: {line!r}"
              result[key] = value
          return result


      def current_generation():
          return int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def wait_for_activation(machine):
          try:
              machine.succeed(
                  "timeout --kill-after=2s 300s bash -c '"
                  "until test -s /run/aos/manifest.json "
                  "&& test -s /run/aos/graph.json "
                  "&& test -s /run/aos/activation.json; "
                  "do sleep 1; done'",
                  timeout=310,
              )
          except Exception:
              for unit in (
                  "multi-user.target",
                  "aos-provisioning-persist.service",
                  "aos-firstboot-reeval.service",
                  "aos-host-config-restore.service",
                  "aos-nix-db.service",
                  "aos-seed-baked-packages.service",
                  "aos-eval.service",
                  "aos-graph-compile.service",
                  "aos-activate.service",
              ):
                  print(machine.succeed(
                      f"systemctl status {unit} --no-pager 2>&1 || true"
                  ))
                  print(machine.succeed(
                      f"journalctl -b -u {unit} --no-pager 2>&1 || true"
                  ))
              print(machine.succeed(
                  "systemctl list-jobs --no-pager 2>&1 || true"
              ))
              for path in (
                  "/run/aos/manifest.json",
                  "/run/aos/graph.json",
                  "/run/aos/activation.json",
                  "/var/lib/profiles/system/state.json",
              ):
                  print(machine.succeed(f"cat {path} 2>&1 || true"))
              raise


      def assert_live(value):
          try:
              runtime.wait_until_succeeds(
                  f"test \"$(cat /etc/hostname)\" = runtime-{value}", timeout=60
              )
          except Exception:
              for unit in (
                  "aos-eval.service",
                  "aos-graph-compile.service",
                  "aos-activate.service",
                  "aos-image-boot-commit.service",
              ):
                  print(runtime.succeed(
                      f"systemctl status {unit} --no-pager 2>&1 || true"
                  ))
                  print(runtime.succeed(
                      f"journalctl -b -u {unit} --no-pager 2>&1 || true"
                  ))
              print(runtime.succeed(
                  "cat /var/lib/profiles/system/state.json 2>&1 || true"
              ))
              print(runtime.succeed("cat /run/aos/manifest.json 2>&1 || true"))
              print(runtime.succeed("cat /proc/mounts 2>&1 || true"))
              raise
          runtime.succeed(
              f"test \"$(cat /etc/rfc0011/runtime.conf)\" = generation={value}"
          )
          runtime.succeed("test \"$(id -u rfc0011)\" = 976")
          runtime.succeed("test \"$(id -g rfc0011)\" = 976")
          runtime.succeed("systemctl is-active --quiet rfc0011-host.service")
          runtime.succeed(f"test \"$(cat /run/rfc0011-host-service)\" = {value}")
          runtime.succeed("systemctl is-active --quiet aos-test-agent.service")


      wait_for_activation(image_default)
      image_default.succeed("test ! -e /run/aos-metadata/host.nix")
      default_preview = json.loads(image_default.succeed(f"""
          {APM} --json switch --dry-run \
            --eval-root /run/rfc0011-image-default-preview
      """, timeout=300))
      assert default_preview["etc_diff"] == [], default_preview
      assert default_preview["unit_actions"] == [], default_preview
      image_default.succeed(f"""
          {APM} switch --eval-root /run/rfc0011-image-default-switch
      """, timeout=300)
      image_default.succeed("systemctl is-active --quiet aos-config.target")


      # Reaching these units proves graph compilation synchronously awaited the
      # activation proof, rather than merely observing an eval manifest.
      wait_for_activation(runtime)
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-activate.service", timeout=300
      )
      runtime.succeed("systemctl is-active --quiet aos-config.target")
      runtime.succeed("systemctl is-active --quiet multi-user.target")

      eval_properties = properties(
          "aos-eval.service",
          [
              "Type",
              "After",
              "Before",
              "Requires",
              "MemoryMax",
              "MemoryHigh",
              "TimeoutStartUSec",
              "TasksMax",
              "ProtectSystem",
              "ProtectHome",
              "PrivateTmp",
              "NoNewPrivileges",
              "SystemCallArchitectures",
              "SystemCallFilter",
          ],
      )
      assert eval_properties["Type"] == "oneshot", eval_properties
      assert "network-online.target" in eval_properties["After"].split(), eval_properties
      assert "aos-nix-db.service" in eval_properties["After"].split(), eval_properties
      assert "aos-nix-db.service" in eval_properties["Requires"].split(), eval_properties
      assert "aos-graph-compile.service" in eval_properties["Before"].split(), eval_properties
      assert "multi-user.target" in eval_properties["Before"].split(), eval_properties
      assert eval_properties["MemoryMax"] == str(2 * 1024 * 1024 * 1024), eval_properties
      assert eval_properties["MemoryHigh"] == str(1536 * 1024 * 1024), eval_properties
      assert eval_properties["TimeoutStartUSec"] == "2min", eval_properties
      assert eval_properties["TasksMax"] == "4096", eval_properties
      assert eval_properties["ProtectSystem"] == "strict", eval_properties
      assert eval_properties["ProtectHome"] == "yes", eval_properties
      assert eval_properties["PrivateTmp"] == "yes", eval_properties
      assert eval_properties["NoNewPrivileges"] == "yes", eval_properties
      assert eval_properties["SystemCallArchitectures"] == "native", eval_properties
      assert eval_properties["SystemCallFilter"], eval_properties

      manifest_text = runtime.succeed("cat /run/aos/manifest.json")
      manifest = json.loads(manifest_text)
      assert manifest["schema"] == "aos.config-manifest/v1", manifest["schema"]
      for field, expected_type in (
          ("etc", dict),
          ("units", dict),
          ("jobScripts", dict),
          ("inputs", dict),
          ("users", list),
          ("packages", list),
      ):
          assert isinstance(manifest[field], expected_type), field
      assert manifest["etc"]["hostname"]["text"] == "runtime-one\n"
      assert manifest["etc"]["rfc0011/runtime.conf"]["text"] == "generation=one\n"
      assert "rfc0011-host.service" in manifest["units"]
      assert any(
          key.startswith("rfc0011-host.service:") for key in manifest["jobScripts"]
      ), manifest["jobScripts"].keys()
      assert any(user["name"] == "rfc0011" for user in manifest["users"])
      assert "aos-test-agent" in manifest["packages"], manifest["packages"]
      assert manifest["inputs"]["host_nix"]["trust_mode"] == "platform"
      assert manifest["inputs"]["host_nix"]["store_path"].startswith("/nix/store/")
      runtime.fail(f"{GREP} -q MIIDHzCCAgeg /etc/ssl/certs/ca-certificates.crt")

      first = current_generation()
      assert first > 0
      first_dir = f"/var/lib/profiles/system/gen-{first}"
      runtime.succeed(f"test \"$(readlink /var/lib/profiles/system/current)\" = gen-{first}")
      runtime.succeed(f"test -s {first_dir}/manifest.json")
      runtime.succeed(f"test -s {first_dir}/config-lower/etc.erofs")
      runtime.succeed(f"test -s {first_dir}/activation.json")
      activation = json.loads(runtime.succeed("cat /run/aos/activation.json"))
      assert activation["schema"] == "aos.config-activation/v1", activation
      assert activation["generation"] == first, activation
      assert activation["status"] == "complete", activation
      assert activation["activation_exit"] == 0, activation
      state = json.loads(runtime.succeed("cat /var/lib/profiles/system/state.json"))
      first_record = next(g for g in state["generations"] if g["number"] == first)
      assert first_record["manifest_hash"] == activation["generation_id"]
      assert first_record["image_gen_parent"] > 0
      assert first_record["module_abi_pinned"] == manifest["module_abi"]
      assert_live("one")

      # Equal-priority operator definitions must produce a structured conflict
      # and leave both the durable pointer and live transaction inputs intact.
      conflict_host = """{
        imports = [
          { aos.firewall.forwardPolicy = "accept"; }
          { aos.firewall.forwardPolicy = "drop"; }
        ];
      }
      """
      conflict_encoded = base64.b64encode(conflict_host.encode()).decode()
      runtime.succeed(
          f"printf '%s' {conflict_encoded} | base64 -d > /run/rfc0011-conflict.nix"
      )
      live_manifest_hash = runtime.succeed(
          "sha256sum /run/aos/manifest.json"
      ).split()[0]
      runtime.succeed("rm -rf /run/rfc0011-conflict-eval")
      runtime.succeed(f"""
          set -eu
          if {APM} switch \
            --from /run/rfc0011-conflict.nix \
            --eval-root /run/rfc0011-conflict-eval \
            > /run/rfc0011-conflict.out 2>&1; then
            echo 'conflicting host configuration unexpectedly succeeded' >&2
            exit 1
          fi
      """, timeout=300)
      conflict_output = runtime.succeed("cat /run/rfc0011-conflict.out")
      assert "config-eval.class=conflict" in conflict_output, conflict_output
      assert current_generation() == first
      assert runtime.succeed(
          "sha256sum /run/aos/manifest.json"
      ).split()[0] == live_manifest_hash
      assert_live("one")

      # The same production evaluator must be byte-deterministic when driven
      # twice with identical authenticated inputs.
      runtime.succeed(f"""
          set -eu
          base_lib=$(readlink -f /aos-toplevel/base-lib)
          module_abi=""
          while IFS='=' read -r key value; do
            if [ "$key" = AOS_MODULE_ABI ]; then module_abi="$value"; fi
          done < /aos-toplevel/os-release
          test -n "$module_abi"
          rm -rf /run/rfc0011-eval-one /run/rfc0011-eval-two
          mkdir -p /run/rfc0011-eval-one /run/rfc0011-eval-two
          {APM} __eval \
            --host-nix /run/aos-metadata/host.nix \
            --base-lib "$base_lib" \
            --facts /run/aos-metadata/facts.json \
            --module-abi "$module_abi" \
            --out /run/rfc0011-eval-one/manifest.json \
            --eval-root /run/rfc0011-eval-one
          {APM} __eval \
            --host-nix /run/aos-metadata/host.nix \
            --base-lib "$base_lib" \
            --facts /run/aos-metadata/facts.json \
            --module-abi "$module_abi" \
            --out /run/rfc0011-eval-two/manifest.json \
            --eval-root /run/rfc0011-eval-two
          {CMP} /run/rfc0011-eval-one/manifest.json /run/rfc0011-eval-two/manifest.json
      """, timeout=300)

      # Create a second same-ABI configuration through `apm switch`, then prove
      # rollback is a direct generation reactivation with no image transition.
      second_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.networking.hostName = \"runtime-two\";
        aos.apm.desiredPackages = [ \"aos-test-agent\" ];
        aos.security.pki.certificates = [ ${builtins.toJSON testCertificate} ];
        environment.etc.\"rfc0011/runtime.conf\" = {
          text = \"generation=two\\n\";
          mode = \"0644\";
        };
        aos.users.groups.rfc0011 = { gid = 976; members = []; };
        aos.users.users.rfc0011 = {
          uid = 976;
          group = \"rfc0011\";
          home = \"/var/lib/rfc0011\";
          shell = \"/bin/bash\";
          description = \"Runtime-configured host user\";
          extraGroups = [];
        };
        systemd.services.rfc0011-host = {
          description = \"Runtime-configured host service\";
          wantedBy = [ \"multi-user.target\" ];
          serviceConfig = { Type = \"oneshot\"; RemainAfterExit = true; };
          script = \"printf two > /run/rfc0011-host-service\";
        };
      }
      """
      encoded = base64.b64encode(second_host.encode()).decode()
      runtime.succeed(f"printf '%s' {encoded} | base64 -d > /run/rfc0011-host-two.nix")

      # The porcelain defaults derive the running base library, module ABI,
      # current retained manifest, and normalized facts automatically. The
      # JSON dry-run is the oracle for the real switch and must be a clean
      # no-op on both the generation pointer and live files.
      runtime.succeed("rm -rf /run/rfc0011-dry-run")
      dry_run = json.loads(runtime.succeed(f"""
          {APM} --json switch --dry-run \
            --from /run/rfc0011-host-two.nix \
            --eval-root /run/rfc0011-dry-run
      """, timeout=300))
      assert any(
          change["path"] in ("hostname", "rfc0011/runtime.conf")
          for change in dry_run["etc_diff"]
      ), dry_run
      for ca_path in (
          "ssl/certs/ca-certificates.crt",
          "ssl/certs/ca-bundle.crt",
          "pki/tls/certs/ca-bundle.crt",
      ):
          assert any(change["path"] == ca_path for change in dry_run["etc_diff"]), (
              ca_path,
              dry_run,
          )
      assert any(
          action["unit"] == "rfc0011-host.service"
          for action in dry_run["unit_actions"]
      ), dry_run
      assert isinstance(dry_run["fetch_plan"], list), dry_run
      assert isinstance(dry_run["resolution_trace"], list), dry_run
      assert current_generation() == first
      assert_live("one")

      runtime.succeed("rm -rf /run/rfc0011-switch")
      runtime.succeed(f"""
          set -eu
          {APM} switch \
            --from /run/rfc0011-host-two.nix \
            --eval-root /run/rfc0011-switch
      """, timeout=300)
      second = current_generation()
      assert second != first, (first, second)
      assert_live("two")
      ca_paths = (
          "/etc/ssl/certs/ca-certificates.crt",
          "/etc/ssl/certs/ca-bundle.crt",
          "/etc/pki/tls/certs/ca-bundle.crt",
      )
      for ca_path in ca_paths:
          runtime.succeed(f"test -f {ca_path}")
          runtime.succeed(f"{GREP} -q MIIDHzCCAgeg {ca_path}")
      runtime.succeed(f"{CMP} {ca_paths[0]} {ca_paths[1]}")
      runtime.succeed(f"{CMP} {ca_paths[0]} {ca_paths[2]}")
      second_manifest = json.loads(runtime.succeed(
          f"cat /var/lib/profiles/system/gen-{second}/manifest.json"
      ))
      for ca_path in (
          "ssl/certs/ca-certificates.crt",
          "ssl/certs/ca-bundle.crt",
          "pki/tls/certs/ca-bundle.crt",
      ):
          assert second_manifest["etc"][ca_path]["kind"] == "certificate-bundle"
          assert second_manifest["ownership"]["etc"][ca_path] == "@host"
      image_before_rollback = runtime.succeed(
          f"{JQ} -er '.running' /var/lib/profiles/image/state.json"
      ).strip()

      runtime.succeed(f"{APM} rollback --system --generation {first}", timeout=300)
      assert current_generation() == first
      assert runtime.succeed(
          f"{JQ} -er '.running' /var/lib/profiles/image/state.json"
      ).strip() == image_before_rollback
      assert_live("one")
      for ca_path in ca_paths:
          runtime.fail(f"{GREP} -q MIIDHzCCAgeg {ca_path}")

      # Reboot with the original metadata attached. Byte-identical evaluation
      # must reuse the retained content-addressed generation.
      runtime.reboot()
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      assert current_generation() == first
      assert_live("one")

      # Reboot without metadata exercises the durable, hash-checked host input
      # cache. The same host policy and generation must remain live.
      runtime.reboot_without_metadata()
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      assert current_generation() == first
      assert_live("one")

      # Fail-closed cache-loss regression: a machine that has committed a
      # non-empty operator host input must never silently substitute `{}` and
      # activate a base-only generation when both metadata and its durable cache
      # disappear. Either eval may fail or the graph may no-op; the committed
      # pointer and live policy must remain unchanged.
      runtime.succeed("rm -f /run/aos-metadata/host.nix")
      runtime.succeed("rm -f /var/lib/aos-provisioning/current/host.nix")
      runtime.succeed("rm -f /run/aos/manifest.json /run/aos/graph.json")
      runtime.fail("systemctl restart aos-host-config-restore.service")
      runtime.fail("systemctl restart aos-eval.service")
      runtime.succeed("systemctl restart aos-graph-compile.service")
      runtime.fail("test -e /run/aos/manifest.json")
      runtime.fail("test -e /run/aos/graph.json")
      assert current_generation() == first
      assert_live("one")
    '';
}
