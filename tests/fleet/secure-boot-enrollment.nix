# Qualify Secure Boot enrollment and retain its enforcing OVMF variable store.
{
  pkgs,
  systems,
}: let
  enrollmentSpec = {
    name = "secure-boot-enrolled-vars";
    timeout = 1800;
    bootTimeout = 240;

    machines.enroller = {
      system = systems.server-secureboot.extendModules {
        modules = [
          ../../systems/_server-test-packages.nix
          {
            # Preserve early PID1 errors when enrollment cannot reach the agent.
            aos.boot.kernelParams = [
              "systemd.log_level=debug"
              "rd.systemd.log_level=info"
              "systemd.log_target=console"
            ];
            # An unselected image must boot its ordinary host services while
            # refusing Sandbox jobs before any command can run without a bank.
            systemd.services.aos-sandbox-enrollment-negative = {
              serviceConfig = {
                Type = "oneshot";
                ExecStart = "${pkgs.coreutils}/bin/touch /run/aos-unfunded-sandbox-executed";
              };
            };
          }
        ];
      };
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

        def refuse_unfunded_sandbox():
            unit = "aos-sandbox-enrollment-negative.service"
            enroller.fail(f"systemctl start {unit}")
            enroller.succeed("test ! -e /run/aos-unfunded-sandbox-executed")
            diagnostics = enroller.succeed(f"journalctl -b -u {unit} --no-pager -o cat")
            assert "Refusing job resource admission" in diagnostics, diagnostics

        enroller.wait_until_succeeds(
            "systemctl is-active multi-user.target",
            timeout=120,
        )
        root_options = enroller.succeed("findmnt -n -o OPTIONS /").strip().split(",")
        assert "ro" in root_options and "nodev" in root_options, root_options
        refuse_unfunded_sandbox()
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
        refuse_unfunded_sandbox()
        boot_status = enroller.succeed("bootctl status 2>&1 || true")
        assert "Secure Boot: enabled (user)" in boot_status, boot_status
      '';
  };
in
  enrollmentSpec
