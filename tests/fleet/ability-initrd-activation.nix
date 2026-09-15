# Typed initrd activation and host continuation qualification.
{
  mkSystem,
  pkgs,
  ...
}: let
  activatedSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.image.erofsCompressionLevel = 1;
      aos.abilities.initrdActivationInput.operations = [
        {
          id = "authenticate-image";
          kind = "authenticate-target-image";
        }
        {
          id = "verify-static-contract";
          kind = "verify-static-ability-contract";
        }
      ];
      aos.packages.aos-test-agent = {
        package = pkgs.aos-test-agent;
        bundle = true;
      };
    }
  ];
in {
  name = "ability-initrd-activation";
  timeout = 600;
  bootTimeout = 300;

  machines.target = {
    system = activatedSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
  };

  testScript =
    # python
    ''
      import json


      target.wait_for_unit("aos-ability-host-receiver.service", timeout=120)
      target.succeed("systemctl is-active aos-ability-host-receiver.service")
      target.succeed("systemctl is-active multi-user.target")

      checkpoint_path = "/run/aos/ability-stage-handoff/initrd.json"
      checkpoint = json.loads(target.succeed(f"cat {checkpoint_path}"))
      assert checkpoint["schema"] == (
          "aos.ability.stage-handoff-checkpoint/v1"
      ), checkpoint
      assert checkpoint["source_stage"] == "initrd", checkpoint
      assert checkpoint["receiver_stage"] == "host", checkpoint
      assert checkpoint["disposition"] == "required", checkpoint
      assert checkpoint["activation_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["completion_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["status"] == "ownership-released", checkpoint

      boot_id = target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip()
      boot_token = boot_id.replace("-", "")
      transaction = f"initrd-{boot_token}"
      journal_path = (
          "/var/lib/profiles/image/ability-stage-transactions/initrd/"
          f"{transaction}/execution.journal"
      )
      journal_hex = target.succeed(
          f"od -An -v -tx1 {journal_path}"
      ).replace(" ", "").replace("\n", "")
      for marker in (
          '"event":"source-completed"',
          '"outcome":"activation-succeeded"',
          '"schema":"aos.ability.initrd-activation-completion/v1"',
          '"kind":"target-image-authenticated"',
          '"kind":"static-ability-contract-verified"',
          '"event":"host-received"',
          '"schema":"aos.ability.host-stage-continuation/v1"',
          '"manager_stage":"host"',
          '"kind":"target-image-reauthenticated"',
          '"kind":"static-ability-contract-reacquired"',
      ):
          assert marker.encode().hex() in journal_hex, marker
    '';
}
