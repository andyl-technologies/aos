# Checked initrd-stage execution and host receipt qualification.
{
  mkSystem,
  pkgs,
  ...
}: let
  activatedSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.image.erofsCompressionLevel = 1;
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
      assert checkpoint["source_stage_bundle_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["execution_sha256"].startswith("sha256:"), checkpoint
      assert checkpoint["status"] == "ownership-released", checkpoint
      assert checkpoint["transaction_root"] == (
          "/run/aos-boot-transaction-storage/aos/initrd-stage-journal"
      ), checkpoint
      transaction_storage = checkpoint["transaction_storage"]
      assert transaction_storage["interface"]["name"] == (
          "aos.boot.transaction-storage-view"
      ), transaction_storage
      assert transaction_storage["operations"] == ["observe"], transaction_storage
      assert transaction_storage["lifetime"] == "transaction", transaction_storage

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
          '"terminal":"succeeded"',
          '"retained_resources"',
          '"name":"aos.boot.transaction-storage-view"',
          '"output":"retained-resource"',
          '"event":"host-received"',
      ):
          assert marker.encode().hex() in journal_hex, marker
    '';
}
