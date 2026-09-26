# Produce an OVMF variable-store seed whose test key hierarchy is enforcing.
{
  lib,
  pkgs,
  systems,
}: let
  fleetHarness = import ../../lib/testing/fleet.nix {inherit lib pkgs;};

  enrollmentSpec = {
    name = "secure-boot-enrolled-vars";
    timeout = 1800;

    machines.enroller = {
      system = systems.server-secureboot;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
      exportFirmwareVars = true;
    };

    testScript =
      # python
      ''
        SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

        def efivar_byte(name):
            path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
            return int(enroller.succeed(f"od -An -tu1 -j4 -N1 {path}").strip())

        enroller.wait_until_succeeds(
            "systemctl is-active multi-user.target",
            timeout=120,
        )
        enroller.succeed("test -d /sys/firmware/efi/efivars")
        assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
        assert efivar_byte("SecureBoot") == 0, "Secure Boot must start disabled"

        updatevar = (
            "PATH=${pkgs.util-linux}/bin:$PATH "
            "${pkgs.efitools}/bin/efi-updatevar"
        )
        keys = "${pkgs.secure-boot-test-keys}"
        for variable in ("db", "KEK", "PK"):
            enroller.succeed(f"{updatevar} -f {keys}/{variable}.auth {variable} 2>&1")

        assert efivar_byte("SetupMode") == 0, "PK enrollment must exit Setup Mode"
        enroller.reboot()
        enroller.wait_until_succeeds(
            "systemctl is-active multi-user.target",
            timeout=120,
        )

        assert efivar_byte("SetupMode") == 0, "reboot must remain in User Mode"
        assert efivar_byte("SecureBoot") == 1, "Secure Boot must enforce after reboot"
        boot_status = enroller.succeed("bootctl status 2>&1 || true")
        assert "Secure Boot: enabled (user)" in boot_status, boot_status
      '';
  };
in
  fleetHarness.mkFleetTest enrollmentSpec
