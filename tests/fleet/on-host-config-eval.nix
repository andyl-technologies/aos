# General runtime host.nix activation acceptance.
#
# This is the load-bearing on-host evaluation acceptance gate. Unlike the
# provisioning test, the machine identity exercised here is not baked into the
# image: literal metadata host.nix overrides the baked hostname and contributes
# an /etc artifact, account, service, and desired package through the production
# native package evaluation and committed aos-activate transaction.
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
  name = "on-host-config-eval";
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
    metadata."host.nix" = import ./_native-runtime-source.nix {
      inherit pkgs;
      hostname = "runtime-one";
      value = "one";
      account = true;
      service = true;
    };
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

      APM = "${pkgs.aos.apm}/bin/apm"
      RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
      PROFILE = "/var/lib/profiles/system"
      GREP = "${pkgs.grep}/bin/grep"
      CMP = "${pkgs.diffutils}/bin/cmp"


      def current(machine):
          value = json.loads(machine.succeed(
              f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery"
          ))["generation"]
          assert isinstance(value, int) and value > 0, value
          directory = f"{PROFILE}/gen-{value}"
          marker = json.loads(machine.succeed(f"cat {directory}/native-deployment.json"))
          descriptor = json.loads(machine.succeed(f"cat {directory}/evaluation.json"))
          assert marker["profile_generation"] == value, marker
          assert descriptor["schema"] == "aos.package.evaluation-input", descriptor
          assert descriptor["scope"] == ["profile", "system"], descriptor
          assert descriptor["library"].startswith("/nix/store/"), descriptor
          machine.succeed(f"test -s {PROFILE}/deployment/generations.journal")
          machine.succeed(f"test -s {PROFILE}/deployment/effects.journal")
          for source in descriptor["configuration"] + descriptor["runtimeConfiguration"]:
              assert source.startswith("/nix/store/"), source
              machine.succeed(f"test -f {source}")
          return value, marker, descriptor


      def wait_for_activation(machine):
          machine.wait_until_succeeds(
              "systemctl is-active --quiet aos-activate.service", timeout=300
          )
          machine.succeed("systemctl is-active --quiet multi-user.target")
          return current(machine)


      def assert_live(value):
          runtime.wait_until_succeeds(
              f'test "$(cat /etc/hostname)" = runtime-{value}', timeout=60
          )
          runtime.succeed(f'test "$(cat /etc/runtime-config/runtime.conf)" = generation={value}')
          runtime.succeed('test "$(id -u runtime-config)" = 976')
          runtime.succeed('test "$(id -g runtime-config)" = 976')
          runtime.succeed("systemctl is-active --quiet runtime-config-host.service")
          runtime.succeed(f'test "$(cat /run/runtime-config-host-service)" = {value}')
          runtime.succeed("systemctl is-active --quiet aos-test-agent.service")


      def write_source(machine, directory, source):
          encoded = base64.b64encode(source.encode()).decode()
          machine.succeed(f"mkdir -p {directory}; printf '%s' {encoded} | base64 -d > {directory}/host.nix")


      # An empty operator worktree still evaluates the retained authored baseline.
      wait_for_activation(image_default)
      image_default.succeed("mkdir -p /run/empty-runtime-modules")
      preview = json.loads(image_default.succeed(
          f"{APM} --json switch --dry-run --worktree /run/empty-runtime-modules "
          "--eval-root /run/runtime-image-default-preview", timeout=300
      ))
      assert preview["added"] == [] and preview["removed"] == [], preview
      image_default.succeed(
          f"{APM} switch --worktree /run/empty-runtime-modules "
          "--eval-root /run/runtime-image-default-switch", timeout=300
      )

      first, first_marker, first_descriptor = wait_for_activation(runtime)
      controller = dict(line.split("=", 1) for line in runtime.succeed(
          "systemctl show aos-activate.service "
          "--property=Type --property=MemoryMax --property=MemoryHigh "
          "--property=TasksMax --property=PrivateTmp --property=ProtectSystem "
          "--property=NoNewPrivileges --property=KillMode --property=LimitCORE"
      ).splitlines())
      assert controller["Type"] == "oneshot", controller
      assert controller["MemoryMax"] == str(2 * 1024 * 1024 * 1024), controller
      assert controller["MemoryHigh"] == str(1536 * 1024 * 1024), controller
      assert controller["TasksMax"] == "4096", controller
      assert controller["PrivateTmp"] == "yes", controller
      # The native controller dispatches admitted host mutations, so its
      # process policy must permit those effects rather than sandbox them away.
      assert controller["ProtectSystem"] == "no", controller
      assert controller["NoNewPrivileges"] == "no", controller
      assert controller["KillMode"] == "control-group", controller
      assert controller["LimitCORE"] == "0", controller
      assert_live("one")
      assert first_descriptor["runtimeConfiguration"], first_descriptor
      runtime.fail(f"{GREP} -q MIIDHzCCAgeg /etc/ssl/certs/ca-certificates.crt")
      boot = runtime.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      image = runtime.succeed("cat /var/lib/profiles/image/state.json")

      # Equal-priority authored definitions fail before any live reconciliation.
      write_source(runtime, "/run/runtime-conflict", """{
        imports = [
          { aos.networking.hostName = "conflict-one"; }
          { aos.networking.hostName = "conflict-two"; }
        ];
      }""")
      status, stdout, stderr = runtime.execute(
          f"{APM} switch --worktree /run/runtime-conflict "
          "--eval-root /run/runtime-conflict-eval", timeout=300
      )
      assert status != 0, (stdout, stderr)
      assert "conflict" in (stdout + stderr).lower(), (stdout, stderr)
      assert current(runtime)[1] == first_marker
      assert_live("one")

      second_source = ${builtins.toJSON (import ./_native-runtime-source.nix {
        inherit pkgs;
        hostname = "runtime-two";
        value = "two";
        account = true;
        service = true;
        certificate = testCertificate;
      })}
      write_source(runtime, "/run/runtime-two", second_source)
      command = f"{APM} --json switch --dry-run --worktree /run/runtime-two"
      preview_one = json.loads(runtime.succeed(
          command + " --eval-root /run/runtime-preview-one", timeout=300
      ))
      preview_two = json.loads(runtime.succeed(
          command + " --eval-root /run/runtime-preview-two", timeout=300
      ))
      assert preview_one == preview_two, (preview_one, preview_two)
      assert preview_one["before"] == first_marker["content"], preview_one
      assert preview_one["after"] != preview_one["before"], preview_one
      assert preview_one["changed"] or preview_one["added"], preview_one
      assert current(runtime)[1] == first_marker
      assert_live("one")

      runtime.succeed(
          f"{APM} switch --worktree /run/runtime-two --eval-root /run/runtime-switch", timeout=300
      )
      second, second_marker, second_descriptor = current(runtime)
      assert second != first and second_marker["sequence"] > first_marker["sequence"]
      assert second_marker["content"] == preview_one["after"], second_marker
      assert second_descriptor["library"] == first_descriptor["library"]
      assert second_descriptor["runtimeConfiguration"] != first_descriptor["runtimeConfiguration"]
      assert_live("two")
      ca_paths = ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-bundle.crt", "/etc/pki/tls/certs/ca-bundle.crt"]
      for path in ca_paths:
          runtime.succeed(f"{GREP} -q MIIDHzCCAgeg {path}")
      runtime.succeed(f"{CMP} {ca_paths[0]} {ca_paths[1]}")
      runtime.succeed(f"{CMP} {ca_paths[0]} {ca_paths[2]}")

      # Rollback reconciles the original authenticated descriptor into a new publication.
      runtime.succeed(f"{APM} rollback --system --generation {first}", timeout=300)
      rolled, rolled_marker, rolled_descriptor = current(runtime)
      assert rolled not in (first, second)
      assert rolled_marker["sequence"] > second_marker["sequence"]
      assert rolled_marker["content"] == first_marker["content"]
      assert rolled_descriptor == first_descriptor
      assert runtime.succeed("cat /var/lib/profiles/image/state.json") == image
      assert runtime.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot
      assert_live("one")
      for path in ca_paths:
          runtime.fail(f"{GREP} -q MIIDHzCCAgeg {path}")

      # Boot reconciles committed operator sources, even after metadata disappears.
      for reboot in (runtime.reboot, runtime.reboot_without_metadata):
          reboot()
          _, marker, descriptor = wait_for_activation(runtime)
          assert marker["content"] == first_marker["content"]
          assert descriptor == first_descriptor
          assert_live("one")
      runtime.succeed("test ! -e /run/aos-metadata")
      runtime.succeed("systemctl restart aos-activate.service", timeout=300)
      assert current(runtime)[1]["content"] == first_marker["content"]
      assert_live("one")
    '';
}
