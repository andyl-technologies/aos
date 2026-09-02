# tests/fleet/measured-boot.nix — measured/verified boot + TPM-sealed /var.
#
# RFC-0006 phase 3. Proves the boot is measured into a (virtual) TPM and
# that /var is LUKS2-encrypted with its key sealed to a *signed PCR
# policy*, so it unlocks unattended across reboots:
#
#   1. First boot is in Setup Mode (no keys enrolled). PCR 7 (Secure Boot
#      state) is not yet the enforcing value, so /var is brought up plain
#      so the system reaches multi-user. Assert the vTPM is present.
#   2. Enroll db → KEK → PK via efivarfs, then reboot into enforcing SB.
#   3. On the first enforcing boot aos-var-crypt LUKS2-formats /var and
#      seals its key to the legacy signed-PCR-11 + pinned-PCR-7 policy, plus a
#      recovery key. Use that key to migrate in place to pinned PCRs 7+12,
#      verify the new token before deleting the old token, and retain durable
#      migration evidence.
#   4. Prove the running root is the dm-verity mapper selected by the UKI,
#      its live root hash and backing devices match the measured `.cmdline`,
#      and the achieved PCR 11 is one predicted from those exact UKI sections.
#      Also prove the base library and evaluator are present in the verified
#      immutable lower store, then alter a copy of the root data and require
#      `veritysetup verify` to reject it.
#   5. Reboot again and assert /var unlocks UNATTENDED via the TPM2 token
#      (no passphrase) — the new boot re-measured PCR 11 but the signed
#      policy still unseals, and pinned PCRs 7 and 12 are unchanged.
#
# Single image-boot machine with a vTPM (server-verity: server + dm-verity +
# SB-signed + PCR-policy-signed image + the bundled test-agent payload).
{
  lib,
  pkgs,
  systems,
}: let
  measuredSystem = systems.server-verity.extendModules {
    modules = [
      {
        # Exercise the deployed-host transition rather than only fresh
        # enrollment under the new default.
        aos.boot.secureBoot.measuredBoot.pinnedPcrs = lib.mkForce "7";
        # Boundary tests temporarily duplicate a complete normal UKI so a
        # failed addon boot cannot affect the clean default entry.
        aos.image.espExtraFreeMiB = 192;
        # Keep the serial console last so /dev/console and journald expose
        # initrd transaction failures in the fleet-test transcript.
        aos.boot.kernelParams = lib.mkAfter ["console=ttyS0,115200"];
        aos.packages.test-http-server.bundle = true;
        environment.systemPackages = [pkgs.binutils pkgs.diffutils pkgs.jq];
        # These are deliberate guest-side verification fixtures: objcopy
        # independently reads the booted UKI, while test-http-server proves
        # package activation across measured configuration generations.
        aos.image.testArtifactRoots = [pkgs.binutils pkgs.test-http-server.expose];
        aos.image.budgets.maxRootMiB = 640;
        aos.image.budgets.maxEspMiB = 640;
      }
    ];
  };
  ukiBMedia = effectiveSystem: let
    measuredImage = effectiveSystem.config.system.build.image.raw;
    dbKey = effectiveSystem.config.aos.boot.secureBoot.dbKey;
    dbCert = effectiveSystem.config.aos.boot.secureBoot.dbCert;
  in
    pkgs.mkDerivation {
      pname = "aos-measured-boot-uki-b-media";
      version = "1";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.e2fsprogs
        pkgs.sbsigntools
        pkgs.systemd.tools
      ];
      runtimeDeps = [];
      propagatedDeps = [];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p media $out
            cp ${measuredImage}/uki-b.efi media/uki-b.efi
            ${pkgs.systemd.tools}/bin/ukify build \
              --stub=${pkgs.systemd}/lib/systemd/boot/efi/addonx64.efi.stub \
              --cmdline='rdinit=/bin/sh' \
              --output=media/unsigned.addon.efi
            ${pkgs.sbsigntools}/bin/sbsign \
              --key ${dbKey} \
              --cert ${dbCert} \
              --output media/signed.addon.efi \
              media/unsigned.addon.efi
            payload_bytes=$(${pkgs.coreutils}/bin/du -sb media | ${pkgs.coreutils}/bin/cut -f1)
            media_bytes=$(( (payload_bytes + 64 * 1024 * 1024 + 1048575) / 1048576 * 1048576 ))
            ${pkgs.coreutils}/bin/truncate -s "$media_bytes" uki-b-media.img
            ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -q -L aos-uki-b -d media uki-b-media.img
            mv uki-b-media.img $out/uki-b-media.img
          '';
        }
      ];
    };
  recoveryMedia = effectiveSystem: let
    recoveryBundle = effectiveSystem.config.system.build.recoveryBundle;
  in
    pkgs.mkDerivation {
      pname = "aos-measured-boot-recovery-media";
      version = "1";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.e2fsprogs];
      runtimeDeps = [];
      propagatedDeps = [];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p media/aos/recovery $out
            cp -a ${recoveryBundle}/aos/recovery/. media/aos/recovery/
            bundle_bytes=$(${pkgs.coreutils}/bin/du -sb ${recoveryBundle}/aos/recovery | ${pkgs.coreutils}/bin/cut -f1)
            media_bytes=$(( (bundle_bytes + 256 * 1024 * 1024 + 1048575) / 1048576 * 1048576 ))
            ${pkgs.coreutils}/bin/truncate -s "$media_bytes" recovery-media.img
            ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -q -L AOS-RECOVERY \
              -d media recovery-media.img
            mv recovery-media.img $out/recovery-media.img
          '';
        }
      ];
    };
in {
  name = assert builtins.elem "aos-verity-root-verify.service" measuredSystem.config.boot.initrd.systemd.services."aos-var-crypt".requires; "measured-boot";
  # Image boot + enrollment/migration + the A/B counted-candidate lifecycle.
  timeout = 5400;
  # The emulated TPM (swtpm) adds tens of seconds of slow command
  # round-trips to every boot (firmware measurement, kernel TCG init,
  # systemd PCR phases, the cryptenroll/cryptsetup TPM2 ops), so each
  # boot needs well above the 180s default.
  bootTimeout = 600;

  machines = {
    # systemd-repart carves swap and var. /var is left raw (repart
    # omits Format= under measured boot) — aos-var-crypt owns its filesystem:
    # plain ext4 on the Setup boot, LUKS2 once enforcing.
    target = {
      system = measuredSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      tpm = true;
      extraDisks = [
        {
          interface = "scsi";
          # The source filesystem sizes itself from the UKI. This declared
          # capacity leaves bounded growth room and the driver rejects any
          # future artifact that exceeds it before launching QEMU.
          sizeMiB = 256;
          serial = "uki-b-media";
          source = effectiveSystem: "${ukiBMedia effectiveSystem}/uki-b-media.img";
          readOnly = true;
        }
        {
          interface = "usb";
          # QEMU's usb-storage device defaults to fixed media. Model an
          # operator-provided removable drive so recovery's sysfs topology
          # check exercises the production transport boundary.
          removable = true;
          sizeMiB = 8192;
          serial = "aos-recovery-media";
          source = effectiveSystem: "${recoveryMedia effectiveSystem}/recovery-media.img";
          # The recovery environment always mounts this untrusted transport
          # read-only. Keeping the harness copy writable lets the normal test
          # boot corrupt its manifest and prove signature rejection.
          readOnly = false;
        }
      ];
      # Keep the control-plane unit in every evaluated /etc generation. The
      # package payload is image-bundled test infrastructure, not a runtime
      # package selection, so verified-boot assertions do not depend on a
      # registry publishing the harness itself.
      metadata."host.nix" = ''
        { config, pkgs, ... }: {
          aos.apm.desiredPackages = [ "test-http-server" ];
          systemd.services.aos-test-agent = {
            description = "AOS VM Test Guest Agent";
            wantedBy = [ "multi-user.target" ];
            restartIfChanged = false;
            stopIfChanged = false;
            serviceConfig = {
              Type = "simple";
              ExecStart = "''${config.aos.packages.aos-test-agent.package}/share/aos-test-agent/aos-test-agent";
              Restart = "on-failure";
              RestartSec = 1;
              Environment = "PATH=''${pkgs.coreutils}/bin:''${pkgs.bash}/bin:''${pkgs.systemd}/bin:''${pkgs.systemd}/sbin";
            };
          };
        }
      '';
      # binutils extracts the measured UKI sections; jq validates the signed
      # policy and the evaluator manifest. Both are AOS-built packages and are
      # themselves inside the verified root exercised below.
      packages = ["test-http-server"];
    };
  };

  testScript =
    # python
    ''
      import hashlib
      import base64
      import json
      import os
      import re
      import time

      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      CS = "${pkgs.cryptsetup}/sbin/cryptsetup"
      VS = "${pkgs.cryptsetup}/sbin/veritysetup"
      OBJCOPY = "${pkgs.binutils}/bin/objcopy"
      JQ = "${pkgs.jq}/bin/jq"
      CMP = "${pkgs.diffutils}/bin/cmp"
      MEASURE = "${pkgs.systemd}/lib/systemd/systemd-measure"
      APM = "${pkgs.aos.apm}/bin/apm"
      TPM2_CHECKQUOTE = "${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      TPM2_PCREXTEND = "${pkgs.tpm2-tools}/bin/tpm2_pcrextend"
      TPM2_PCRREAD = "${pkgs.tpm2-tools}/bin/tpm2_pcrread"
      VAR_POLICY_MIGRATE = "${pkgs.aos-var-policy-migrate}/bin/aos-var-policy-migrate"
      VARDEV = "/dev/disk/by-partlabel/var"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      UMOUNT = "${pkgs.util-linux}/bin/umount"
      BOOTCTL = "${pkgs.systemd}/bin/bootctl"

      def read_pcr12():
          output = target.succeed(f"{TPM2_PCRREAD} sha256:12")
          match = re.search(r"^\s*12\s*:\s*0x([0-9A-Fa-f]+)\s*$", output, re.M)
          assert match is not None, output
          value = match.group(1).lower()
          assert len(value) == 64, output
          return value

      def serial_offset():
          try:
              return os.path.getsize(target.serial_log_path)
          except OSError:
              return 0

      def wait_serial(marker, offset, timeout=300):
          deadline = time.monotonic() + timeout
          transcript = ""
          while time.monotonic() < deadline:
              try:
                  with open(target.serial_log_path, "rb") as serial:
                      serial.seek(offset)
                      transcript = serial.read().decode("utf-8", errors="replace")
              except OSError:
                  transcript = ""
              if marker in transcript:
                  return transcript
              time.sleep(0.25)
          raise AssertionError(f"serial marker {marker!r} not observed:\n{transcript[-12000:]}")

      def serial_since(offset):
          try:
              with open(target.serial_log_path, "rb") as serial:
                  serial.seek(offset)
                  return serial.read().decode("utf-8", errors="replace")
          except OSError:
              return ""

      def reboot_recovery_console():
          boundary = "AOS_TEST_RECOVERY_REBOOT_BOUNDARY"
          boundary_offset = serial_offset()
          target.succeed(f"echo {boundary} > /dev/ttyS0")
          wait_serial(boundary, boundary_offset)
          offset = serial_offset()
          target.execute(
              "(sleep 1; systemctl reboot) >/dev/null 2>&1 &", timeout=30
          )
          target.agent.close()
          transcript = wait_serial("AOS recovery>", offset)
          recovery_start = transcript.rfind("AOS signed recovery environment")
          assert recovery_start >= 0, transcript[-12000:]
          return transcript[recovery_start:]

      def assert_external_cmdline_absent(transcript, fragment):
          kernel_cmdlines = [
              line.split("Command line:", 1)[1].strip()
              for line in transcript.splitlines()
              if "Command line:" in line
          ]
          assert kernel_cmdlines, transcript[-12000:]
          effective_cmdline = kernel_cmdlines[-1].split()
          assert fragment not in effective_cmdline, effective_cmdline

      def canonical_json(value):
          """Encode canonical attestation JSON independently of the AOS CLI."""
          if value is None:
              return "null"
          if value is True:
              return "true"
          if value is False:
              return "false"
          if isinstance(value, int):
              return str(value)
          if isinstance(value, str):
              encoded = ['"']
              for char in value:
                  if char == '"':
                      encoded.append('\\"')
                  elif char == "\\":
                      encoded.append("\\\\")
                  elif ord(char) < 0x20:
                      encoded.append(f"\\u{ord(char):04x}")
                  else:
                      encoded.append(char)
              encoded.append('"')
              return "".join(encoded)
          if isinstance(value, list):
              return "[" + ",".join(canonical_json(item) for item in value) + "]"
          if isinstance(value, dict):
              return "{" + ",".join(
                  canonical_json(key) + ":" + canonical_json(value[key])
                  for key in sorted(value)
              ) + "}"
          raise TypeError(f"unsupported canonical JSON value: {type(value)!r}")

      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)

      def var_source():
          # The /var mount source, read from /proc/mounts (no findmnt in
          # the agent's restricted PATH). Trailing `true` keeps the command
          # exit 0 — the while loop otherwise returns the status of its
          # last (non-matching) iteration.
          out = target.succeed(
              "while read -r dev mnt rest; do "
              "if [ \"$mnt\" = /var ]; then echo \"$dev\"; fi; "
              "done < /proc/mounts; true"
          ).strip()
          return out

      def assert_recurrent_substrate(label):
          # Repart convergence and stage-2 tmpfiles are lifecycle operations:
          # they run on every boot, while destructive formatting is guarded by
          # observed state inside the implementing tool/service.
          repart_log = target.succeed(
              "journalctl -b -u aos-repart.service --no-pager 2>&1"
          )
          assert "durable operator provisioning marker present" in repart_log, (
              f"{label}: repart did not perform its committed-layout pass:\n{repart_log}"
          )
          target.succeed("systemctl is-active systemd-tmpfiles-setup.service")
          entered = target.succeed(
              "systemctl show systemd-tmpfiles-setup.service "
              "-p ActiveEnterTimestampMonotonic --value"
          ).strip()
          assert int(entered) > 0, f"{label}: tmpfiles did not run in this boot"

      def mount_source(mountpoint):
          out = target.succeed(
              "while read -r dev mnt rest; do "
              f"if [ \"$mnt\" = {mountpoint} ]; then echo \"$dev\"; fi; "
              "done < /proc/mounts; true"
          ).strip()
          return out

      def assert_verified_root():
          cmdline = target.succeed("cat /proc/cmdline").strip()
          tokens = cmdline.split()
          roots = [t.split("=", 1)[1] for t in tokens if t.startswith("root=")]
          roothashes = [
              t.split("=", 1)[1] for t in tokens if t.startswith("roothash=")
          ]
          data_devices = [
              t.split("=", 1)[1]
              for t in tokens
              if t.startswith("systemd.verity_root_data=")
          ]
          hash_devices = [
              t.split("=", 1)[1]
              for t in tokens
              if t.startswith("systemd.verity_root_hash=")
          ]
          assert roots == ["/dev/mapper/root"], f"unexpected root= tokens: {roots!r}"
          assert len(roothashes) == 1, f"expected one roothash=, got {roothashes!r}"
          root_hash = roothashes[0]
          assert len(root_hash) == 64 and all(c in "0123456789abcdef" for c in root_hash), (
              f"invalid sha256 roothash: {root_hash!r}"
          )
          assert len(data_devices) == 1 and len(hash_devices) == 1, (
              f"verity device hints are not unique: data={data_devices!r}, "
              f"hash={hash_devices!r}"
          )
          slot_pairs = {
              "/dev/disk/by-partlabel/root-a": "/dev/disk/by-partlabel/root-a-hash",
              "/dev/disk/by-partlabel/root-b": "/dev/disk/by-partlabel/root-b-hash",
          }
          assert data_devices[0] in slot_pairs, f"unknown root slot: {data_devices[0]!r}"
          assert hash_devices[0] == slot_pairs[data_devices[0]], (
              f"cross-slot verity devices: {data_devices[0]!r}, {hash_devices[0]!r}"
          )

          # The root mount and the named mapper must resolve to the same dm
          # device even if /proc/mounts chooses the /dev/dm-N spelling.
          root_source = mount_source("/")
          mapper = target.succeed("readlink -f /dev/mapper/root").strip()
          mounted = target.succeed(f"readlink -f {root_source}").strip()
          assert mounted == mapper, (
              f"/ is not mounted from /dev/mapper/root: {root_source!r} -> {mounted!r}, "
              f"mapper -> {mapper!r}"
          )

          status = target.succeed(f"{VS} status root")
          status_fields = {
              match.group(1).strip().lower(): match.group(2).strip()
              for line in status.splitlines()
              if (match := re.match(r"^\s*([^:]+):\s*(.*?)\s*$", line))
          }
          assert status_fields.get("type", "").lower() == "verity", (
              f"root mapper is not verity:\n{status}"
          )
          assert status_fields.get("status", "").lower() == "verified", (
              f"root mapper is not verified:\n{status}"
          )
          assert status_fields.get("root hash", "").lower() == root_hash, (
              f"live verity root hash does not match cmdline {root_hash}:\n{status}"
          )
          expected_data = target.succeed(f"readlink -f {data_devices[0]}").strip()
          expected_hash = target.succeed(f"readlink -f {hash_devices[0]}").strip()
          assert status_fields.get("data device") == expected_data, (
              f"live verity data device does not match slot: {status}"
          )
          assert status_fields.get("hash device") == expected_hash, (
              f"live verity hash device does not match slot: {status}"
          )

          # Extract the booted UKI's own cmdline. Its root hash and device
          # tuple must be the same bytes the kernel consumed; Secure Boot's
          # Authenticode signature covers this section as part of the PE.
          uki = target.succeed("""
              set -eu
              uki=__missing__
              for candidate in /boot/EFI/Linux/aos-*.efi; do
                uki="$candidate"
                break
              done
              test "$uki" != __missing__
              printf '%s' "$uki"
          """).strip()
          target.succeed(f"{OBJCOPY} -O binary --only-section=.cmdline {uki} /tmp/uki.cmdline")
          uki_cmdline = target.succeed("tr -d '\\000' < /tmp/uki.cmdline").strip()
          assert uki_cmdline.split() == tokens, (
              f"running cmdline differs from UKI .cmdline:\nUKI={uki_cmdline!r}\nrun={cmdline!r}"
          )

          # Independently reproduce sd-stub's PCR-11 measurements from every
          # measured section of the booted UKI. The current PCR must be one of
          # the boot-phase values calculated from this exact section set. Since
          # `.cmdline` contains `roothash=`, this is the measured root binding.
          pcr_check = target.succeed(f"""
              set -eu
              work=/tmp/aos-pcr11-check
              rm -rf "$work"
              mkdir -p "$work"
              args=""
              for section in linux osrel cmdline initrd ucode splash dtb uname sbat pcrpkey; do
                {OBJCOPY} -O binary --only-section=.$section {uki} "$work/$section" 2>/dev/null || true
                if [ -s "$work/$section" ]; then
                  args="$args --$section=$work/$section"
                fi
              done
              {MEASURE} calculate --bank=sha256 $args > "$work/calculated"
              {MEASURE} status --bank=sha256 > "$work/current"
              actual=""
              while IFS= read -r line; do
                case "$line" in
                  11:sha256=*)
                    actual=$(printf '%s' "$line" | ${pkgs.coreutils}/bin/cut -d= -f2)
                    break
                    ;;
                esac
              done < "$work/current"
              test -n "$actual"
              matched=false
              while IFS= read -r line; do
                case "$line" in
                  11:*="$actual") matched=true; break ;;
                esac
              done < "$work/calculated"
              "$matched"
              printf '%s' "$actual"
          """).strip()
          assert len(pcr_check) == 64 and all(c in "0123456789abcdef" for c in pcr_check), (
              f"invalid achieved PCR11: {pcr_check!r}"
          )
          expected_pcr11 = target.succeed(f"""
              {JQ} -er \
                '.running as $running
                 | .generations[]
                 | select(.number == $running)
                 | .expected_pcr11' \
                /var/lib/profiles/image/state.json
          """).strip().removeprefix("sha256:").lower()
          calculated = target.succeed("cat /tmp/aos-pcr11-check/calculated").splitlines()
          calculated_phases = [
              line.split("=", 1)[1]
              for line in calculated
              if line.startswith("11:sha256=")
          ]
          calculated_enter_initrd = calculated_phases[0]
          calculated_ready = calculated_phases[-1]
          assert expected_pcr11 == calculated_ready, (
              "image index does not match the booted UKI's stable ready-phase "
              f"measurement: index={expected_pcr11!r}, "
              f"calculated={calculated_ready!r}"
          )

          # sd-stub must have materialized this UKI's signed PCR policy. A
          # semantic JSON comparison tolerates PE section padding. The later
          # unattended TPM unlock is the load-bearing validation that the TPM
          # accepted this signed policy rather than a merely present blob.
          target.succeed(f"""
              set -eu
              {OBJCOPY} -O binary --only-section=.pcrsig {uki} /tmp/uki.pcrsig.raw
              tr -d '\\000' < /tmp/uki.pcrsig.raw > /tmp/uki.pcrsig.json
              test -s /run/systemd/tpm2-pcr-signature.json
              {JQ} -e '.sha256 | type == "array" and length > 0' /tmp/uki.pcrsig.json
              {JQ} -S . /tmp/uki.pcrsig.json > /tmp/uki.pcrsig.canonical
              {JQ} -S . /run/systemd/tpm2-pcr-signature.json > /tmp/runtime.pcrsig.canonical
              {CMP} /tmp/uki.pcrsig.canonical /tmp/runtime.pcrsig.canonical
          """)

          # The manifest's base library and evaluator paths must both have
          # identical immutable lower-store residents on the verified EROFS
          # root, rather than existing only in the writable /nix upper layer.
          manifest = "/run/aos/manifest.json"
          base_lib = target.succeed(f"{JQ} -er '.inputs.base_lib.store_path' {manifest}").strip()
          evaluator = target.succeed(f"{JQ} -er '.inputs.evaluator.store_path' {manifest}").strip()
          linked_base = target.succeed("readlink -f /aos-toplevel/base-lib").strip()
          assert base_lib == linked_base, (
              f"manifest base-lib {base_lib!r} != running base-lib {linked_base!r}"
          )
          for label, path, required in (
              ("base-lib", base_lib, "default.nix"),
              ("evaluator", evaluator, "bin/apm"),
          ):
              assert path.startswith("/nix/store/"), f"unsafe {label} path: {path!r}"
              lower = "/nix.lower/store/" + path.removeprefix("/nix/store/")
              target.succeed(f"test -e {lower}/{required}")
              root_dev = target.succeed("stat -c %d /").strip()
              lower_dev = target.succeed(f"stat -c %d {lower}/{required}").strip()
              assert lower_dev == root_dev, (
                  f"{label} lower-store input is not on the verified root filesystem"
              )
          target.succeed(
              f"test -s /nix.lower/store/{base_lib.removeprefix('/nix/store/')}/system-roots.json"
          )

          return root_hash, data_devices[0], hash_devices[0], calculated_ready

      def assert_tamper_rejected(root_hash, data_device, hash_device):
          # Exercise the same root hash/tree against a private copy. Altering
          # the copy avoids destabilizing the running root mapper while still
          # proving dm-verity rejects changed root bytes against the booted
          # UKI's authenticated hash.
          target.succeed(f"""
              set -eu
              dd if={data_device} of=/var/tmp/root-tamper.img bs=4M status=none
              dd if={hash_device} of=/var/tmp/root-tamper.verity bs=4M status=none
              {VS} verify /var/tmp/root-tamper.img /var/tmp/root-tamper.verity {root_hash}
              original=$(${pkgs.coreutils}/bin/od -An -tu1 -j1024 -N1 /var/tmp/root-tamper.img)
              set -- $original
              if [ "$1" -eq 0 ]; then changed='\\001'; else changed='\\000'; fi
              printf "$changed" | dd of=/var/tmp/root-tamper.img bs=1 seek=1024 conv=notrunc status=none
              if {VS} verify /var/tmp/root-tamper.img /var/tmp/root-tamper.verity {root_hash} \
                   > /var/tmp/tamper-verify.out 2>&1; then
                echo 'altered root data unexpectedly passed dm-verity verification' >&2
                exit 1
              fi
              rm -f /var/tmp/root-tamper.img /var/tmp/root-tamper.verity
          """, timeout=300)

      def assert_generation_attestation(root_hash, expected_pcr11):
          # Force a post-enrollment generation so the quote records the
          # enforcing PCR-7 state rather than the Setup-Mode first boot. This
          # host consumes one image-local config module; signed registry
          # release/store verification remains covered by registry fixtures.
          attested_host = """{ config, pkgs, ... }: {
            aos.apm.desiredPackages = [ \"test-http-server\" ];
            environment.etc.\"runtime-config-attested\".text = \"enforcing\\n\";
            systemd.services.aos-test-agent = {
              description = \"AOS VM Test Guest Agent\";
              wantedBy = [ \"multi-user.target\" ];
              restartIfChanged = false;
              stopIfChanged = false;
              serviceConfig = {
                Type = \"simple\";
                ExecStart = \"''${config.aos.packages.aos-test-agent.package}/share/aos-test-agent/aos-test-agent\";
                Restart = \"on-failure\";
                RestartSec = 1;
                Environment = \"PATH=''${pkgs.coreutils}/bin:''${pkgs.bash}/bin:''${pkgs.systemd}/bin:''${pkgs.systemd}/sbin\";
              };
            };
          }
          """
          encoded = base64.b64encode(attested_host.encode()).decode()
          target.succeed(
              f"printf '%s' {encoded} | base64 -d > /run/runtime-config-attested-host.nix"
          )
          target.succeed(f"""
              rm -rf /run/runtime-config-attestation-switch
              {APM} switch \
                --from /run/runtime-config-attested-host.nix \
                --facts /run/aos-metadata/facts.json \
                --eval-root /run/runtime-config-attestation-switch
          """, timeout=300)

          generation = int(target.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())
          generation_dir = f"/var/lib/profiles/system/gen-{generation}"
          record_path = f"{generation_dir}/gen-attestation.json"
          quote_dir = f"{generation_dir}/gen-attestation-quote"
          target.succeed(f"test -s {record_path}")
          target.succeed(f"test -d {quote_dir}")
          record = json.loads(target.succeed(f"cat {record_path}"))
          manifest_text = target.succeed(f"cat {generation_dir}/manifest.json")
          manifest = json.loads(manifest_text)

          assert record["schema"] == "aos.gen-attestation/v1", record
          assert re.fullmatch(r"sha256:[0-9a-f]{64}", record["activation_id"]), record
          assert record["eval_mode"] == "pure-eval", record
          assert record["quote_status"] == "quoted", record
          canonical_manifest = canonical_json(manifest).encode()
          manifest_hash = "sha256:" + hashlib.sha256(canonical_manifest).hexdigest()
          assert record["manifest_hash"] == manifest_hash, (
              record["manifest_hash"], manifest_hash
          )
          assert record["generation_id"] == manifest_hash, record

          inputs = record["inputs"]
          assert inputs["base_lib"]["store_path"] == manifest["inputs"]["base_lib"]["store_path"]
          assert inputs["base_lib"]["abi_hash"] == manifest["inputs"]["base_lib"]["abi_hash"]
          assert inputs["base_lib"]["module_abi"] == manifest["inputs"]["base_lib"]["module_abi"]
          assert inputs["base_lib"]["root_verity_roothash"] == root_hash
          recorded_pcr11 = inputs["base_lib"]["pcr11_expected"].removeprefix("sha256:")
          assert recorded_pcr11 == expected_pcr11, (recorded_pcr11, expected_pcr11)
          assert inputs["evaluator"] == manifest["inputs"]["evaluator"]
          config_inputs = manifest["inputs"]["config_modules"]
          attested_modules = inputs["config_modules"]
          assert attested_modules["closure_hash"] == config_inputs["closure_hash"]
          assert attested_modules["count"] == config_inputs["count"]
          assert attested_modules["count"] == 1, attested_modules
          assert attested_modules["store_paths"] == config_inputs["store_paths"]
          assert attested_modules["nar_hashes"] == config_inputs["nar_hashes"]
          assert attested_modules["package_names"] == config_inputs["package_names"]
          assert config_inputs["origins"] == ["image"], config_inputs
          for field in ("registry", "release_tag", "tag_signer_key", "realization"):
              assert attested_modules.get(field) is None, (field, attested_modules)
              assert config_inputs.get(field) is None, (field, config_inputs)
          assert attested_modules["provenance"] == {
              "module_abi_compat": config_inputs["module_abi_compat"],
              "authorizations": config_inputs["authorizations"],
              "origins": config_inputs["origins"],
          }
          assert inputs["host_nix"] == {
              key: value
              for key, value in manifest["inputs"]["host_nix"].items()
              if value is not None
          }
          assert inputs["instance_facts"] == manifest["inputs"]["instance_facts"]

          # The embedded quote is independently signature-checked under its
          # AK. Its PCR payload must be byte-identical to a fresh read of the
          # same 7/11/12/15 selection; PCR 7 and 11 cannot be silently omitted.
          embedded = json.loads(bytes.fromhex(record["quote"]).decode())
          assert embedded["schema"] == "aos.gen-attestation-quote/v1", embedded
          assert embedded["pcr_selection"] == "sha256:7,11,12,15", embedded
          bare = dict(record)
          bare.pop("quote")
          canonical_bare = canonical_json(bare).encode()
          record_digest = hashlib.sha256(canonical_bare).hexdigest()
          assert embedded["nonce"] == record_digest, embedded
          for field, filename in (
              ("ak_public", "ak.pub"),
              ("quote_message", "quote.msg"),
              ("quote_signature", "quote.sig"),
              ("quote_pcrs", "quote.pcrs"),
          ):
              assert embedded[field] == target.succeed(
                  f"od -An -v -tx1 {quote_dir}/{filename} | tr -d ' \\n'"
              ).strip(), field
          target.succeed(f"""
              {TPM2_CHECKQUOTE} \
                -u {quote_dir}/ak.pub \
                -m {quote_dir}/quote.msg \
                -s {quote_dir}/quote.sig \
                -f {quote_dir}/quote.pcrs \
                -l sha256:7,11,12,15 \
                -g sha256 -q {record_digest}
              {TPM2_PCRREAD} -o /tmp/runtime-config-current-pcrs sha256:7,11,12,15
              {CMP} {quote_dir}/quote.pcrs /tmp/runtime-config-current-pcrs
          """)
          pcrs = target.succeed(f"{TPM2_PCRREAD} sha256:7,11,12")
          parsed = {
              int(index): value.lower()
              for index, value in re.findall(r"^\s*(7|11|12)\s*:\s*0x([0-9A-Fa-f]+)\s*$", pcrs, re.M)
          }
          assert set(parsed) == {7, 11, 12}, pcrs
          assert parsed[11] == expected_pcr11, (parsed, expected_pcr11)
          assert parsed[7] != "0" * 64, parsed

          # Replay the CEL through this generation event. The replayed PCR 15
          # must be exactly the value covered by the checked quote, and the
          # event bytes must be the canonical record with `quote` omitted.
          records = [
              json.loads(line)
              for line in target.succeed("cat /run/log/aos-packages.cel").splitlines()
              if line.strip()
          ]
          pcr15 = bytes(32)
          baseline_pcr15 = None
          saw_generation = False
          for event in records:
              if event["event_type"] == "aos-pcr-baseline":
                  baseline_pcr15 = event["pcr_value"]
                  baseline = event["pcr_value"].removeprefix("sha256:")
                  assert re.fullmatch(r"[0-9a-f]{64}", baseline), event
                  pcr15 = bytes.fromhex(baseline)
                  continue
              digest = event["digest"].removeprefix("sha256:")
              assert digest == hashlib.sha256(event["event"].encode()).hexdigest(), event
              pcr15 = hashlib.sha256(pcr15 + bytes.fromhex(digest)).digest()
              if (
                  event["event_type"] == "aos-generation-attestation"
                  and event["activation_id"] == record["activation_id"]
              ):
                  assert event["generation_id"] == record["generation_id"]
                  assert event["event"].encode() == canonical_bare
                  saw_generation = True
                  break
          assert saw_generation, records
          assert baseline_pcr15 is not None, records
          assert pcr15.hex() == embedded["quoted_pcr15"], (
              pcr15.hex(), embedded["quoted_pcr15"]
          )

          # Re-run the production evaluator from the attested input bytes and
          # require byte-identical canonical output. This is stronger than
          # accepting a self-reported manifest hash: it demonstrates full
          # re-derivation while ignoring JSON object insertion order, which is
          # deliberately outside the canonical attestation identity.
          target.succeed(f"""
              rm -rf /run/runtime-config-attestation-rederive
              mkdir -p /run/runtime-config-attestation-rederive
              {APM} __eval \
                --host-nix /run/runtime-config-attested-host.nix \
                --base-lib {inputs['base_lib']['store_path']} \
                --facts /run/aos-metadata/facts.json \
                --module-abi {inputs['base_lib']['module_abi']} \
                --out /run/runtime-config-attestation-rederive/manifest.json \
                --eval-root /run/runtime-config-attestation-rederive
          """, timeout=300)
          rederived_text = target.succeed(
              "cat /run/runtime-config-attestation-rederive/manifest.json"
          )
          rederived = json.loads(rederived_text)
          if manifest != rederived:
              differences = []

              def collect_differences(left, right, path="$", limit=32):
                  if len(differences) >= limit:
                      return
                  if type(left) is not type(right):
                      differences.append((path, left, right))
                  elif isinstance(left, dict):
                      for key in sorted(set(left) | set(right)):
                          if key not in left or key not in right:
                              differences.append((f"{path}.{key}", left.get(key), right.get(key)))
                          else:
                              collect_differences(left[key], right[key], f"{path}.{key}", limit)
                  elif isinstance(left, list):
                      if len(left) != len(right):
                          differences.append((f"{path}.length", len(left), len(right)))
                      for index, (left_item, right_item) in enumerate(zip(left, right)):
                          collect_differences(
                              left_item, right_item, f"{path}[{index}]", limit
                          )
                  elif left != right:
                      differences.append((path, left, right))

              collect_differences(manifest, rederived)
              raise AssertionError(f"re-derived manifest differs: {differences!r}")
          assert canonical_json(manifest) == canonical_json(rederived), (
              "canonical manifest JSON is not byte-reproducible"
          )

          # Exercise the public, identity-pinned generation verifier. The
          # verifier policy is a separate file even in this single-node test;
          # production callers supply these values from their fleet catalog.
          immutable_top = target.succeed("readlink /aos-toplevel").strip()
          immutable_top_lower = (
              "/nix.lower/store/" + immutable_top.removeprefix("/nix/store/")
          )
          immutable_seed = target.succeed(
              f"readlink {immutable_top_lower}/package-profile-seed"
          ).strip()
          immutable_seed_lower = (
              "/nix.lower/store/" + immutable_seed.removeprefix("/nix/store/")
          )
          seed_meta_paths = target.succeed(
              f"ls -1 {immutable_seed_lower}/meta/*.json"
          ).splitlines()
          seed_records = [
              json.loads(target.succeed(f"cat {path}")) for path in seed_meta_paths
          ]
          image_members = []
          for package_name, store_path, nar_hash, abi, authorization, origin in zip(
              config_inputs["package_names"],
              config_inputs["store_paths"],
              config_inputs["nar_hashes"],
              config_inputs["module_abi_compat"],
              config_inputs["authorizations"],
              config_inputs["origins"],
          ):
              if origin != "image":
                  continue
              matches = [
                  item for item in seed_records
                  if item.get("pushed_by") == "aos-image"
                  and item.get("apm", {}).get("registry") == "seed"
                  and item.get("apm", {}).get("name") == package_name
                  and item.get("apm", {}).get("config_module", {})
                      .get("config_output", {}).get("store_path") == store_path
              ]
              assert len(matches) == 1, (package_name, matches)
              lower_store_path = (
                  "/nix.lower/store/" + store_path.removeprefix("/nix/store/")
              )
              target.succeed(f"test -e {lower_store_path}")
              actual_nar_hash = "sha256:" + target.succeed(
                  f"${pkgs.nix}/bin/nix-store --dump {lower_store_path} "
                  "| ${pkgs.nix}/bin/nix-hash --type sha256 --base32 "
                  "--flat /dev/stdin"
              ).strip()
              assert actual_nar_hash == nar_hash, (actual_nar_hash, nar_hash)
              module = matches[0]["apm"]["config_module"]
              owns = sorted(set(item["root"] for item in module["owns_roots"]))
              contributes = {}
              for contribution in module["contributes"]:
                  contributes.setdefault(contribution["root"], []).extend(
                      contribution["paths"]
                  )
              contributes = {
                  root: sorted(set(paths)) for root, paths in sorted(contributes.items())
              }
              assert abi == module["module_abi_compat"], (abi, module)
              assert authorization == {"owns": owns, "contributes": contributes}, (
                  authorization, module
              )
              image_members.append({
                  "package_name": package_name,
                  "store_path": store_path,
                  "nar_hash": nar_hash,
                  "module_abi_compat": abi,
                  "authorization": authorization,
              })
          policy = {
              "schema": "aos.gen-attestation-policy/v2",
              "expected_pcr7": parsed[7],
              "expected_pcr11": "sha256:" + expected_pcr11,
              "expected_pcr12": parsed[12],
              "expected_root_roothash": root_hash,
              "expected_facts_hash": inputs["instance_facts"]["facts_hash"],
              "trusted_config_keys": [],
              "trusted_platforms": [inputs["host_nix"]["platform"]],
              "image_config_modules": image_members,
          }
          policy_encoded = base64.b64encode(
              json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
          ).decode()
          target.succeed(
              f"printf '%s' {policy_encoded} | base64 -d > /run/runtime-config-attestation-policy.json"
          )
          target.succeed(f"""
              printf '%s\n' 'measured-boot fixture identity proof' \
                > /run/runtime-config-attestation-enrollment.txt
              rm -f /run/runtime-config-attestation-identities.json
              {APM} attest enroll \
                --quote-dir {quote_dir} \
                --label measured-boot-target \
                --method out-of-band \
                --evidence-file /run/runtime-config-attestation-enrollment.txt \
                --catalog-file /run/runtime-config-attestation-identities.json
          """, timeout=300)
          verification = json.loads(target.succeed(f"""
              {APM} --json attest verify --system \
                --event-log /run/log/aos-packages.cel \
                --pcr15-baseline {baseline_pcr15} \
                --quote-dir {quote_dir} \
                --nonce {record_digest} \
                --quote-identity-file /run/runtime-config-attestation-identities.json \
                --generation-attestation {record_path} \
                --generation-policy-file /run/runtime-config-attestation-policy.json \
                --rederived-manifest /run/runtime-config-attestation-rederive/manifest.json
          """, timeout=300))
          assert verification["generation_verified"] is True, verification
          assert verification["quote_bundle_verified"] is True, verification
          assert verification["quote_identity_pinned"] is True, verification
          assert verification["generation"]["rederived"] is True, verification

      def wait_multi_user(label):
          # The swtpm-backed enforcing/seal boot is slow (argon2 luksFormat
          # + many TPM PCR round-trips through the emulator), and 180s was
          # marginal — multi-user occasionally landed just past it. Give it
          # the same generous budget as the harness boot timeout. The agent
          # autologins, so it stays reachable even if multi-user.target is
          # blocked; on timeout, dump what is still pending so an opaque
          # "deadline fired" becomes a named culprit.
          try:
              target.wait_until_succeeds(
                  "systemctl is-active multi-user.target", timeout=420
              )
          except Exception:
              print(f"=== {label}: multi-user.target stalled — diagnostics ===")
              failed = target.succeed("systemctl --failed --no-legend 2>&1 || true").strip()
              if failed:
                  print("--- failed units ---")
                  print(failed)
                  for line in failed.splitlines():
                      fields = line.split()
                      unit = fields[1] if fields and fields[0] == "*" else fields[0]
                      print(f"--- journalctl -u {unit} -b ---")
                      print(target.succeed(
                          f"journalctl -u {unit} -b --no-pager -n 120 2>&1 || true"
                      ))
              for cmd in (
                  "systemctl list-jobs --no-pager",
                  "systemctl --failed --no-pager",
                  "journalctl -b --no-pager | tail -n 80",
              ):
                  print(f"--- {cmd} ---")
                  print(target.succeed(f"{cmd} 2>&1 || true"))
              raise

      # ════ 1. First boot — Setup Mode; vTPM present ════════════════════
      wait_multi_user("boot1 (setup)")
      assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
      assert efivar_byte("SecureBoot") == 0, "SB should not be enforcing yet"
      # The emulated TPM is wired in and the kernel TCG driver bound it.
      target.succeed("test -e /dev/tpm0")
      target.succeed("test -e /sys/class/tpm/tpm0")
      # /var is up (plain) so the system is healthy pre-enrollment.
      assert var_source() != "", "/var not mounted on first boot"
      target.succeed(
          "test -e /dev/disk/by-partlabel/aos-provenance-operator-v1"
      )
      target.succeed("test -s /var/lib/aos-provisioning/audit.json")
      measurement_unit = "aos-image-measurement-index.service"
      try:
          target.wait_until_succeeds(
              f"systemctl is-active {measurement_unit}", timeout=60
          )
      except Exception:
          print(target.succeed(
              f"systemctl status {measurement_unit} --no-pager 2>&1 || true"
          ))
          print(target.succeed(
              f"journalctl -b -u {measurement_unit} --no-pager 2>&1 || true"
          ))
          raise
      for unit in (
          "aos-seed-baked-packages.service",
          "aos-eval.service",
          "aos-graph-compile.service",
          "aos-activate.service",
      ):
          try:
              target.wait_until_succeeds(
                  f"systemctl is-active {unit}", timeout=420
              )
          except Exception:
              print(target.succeed(f"systemctl status {unit} --no-pager 2>&1 || true"))
              print(target.succeed(f"journalctl -b -u {unit} --no-pager 2>&1 || true"))
              raise
          state = target.succeed(
              f"systemctl show {unit} -p ActiveState --value"
          ).strip()
          if state != "active":
              print(target.succeed(f"systemctl status {unit} --no-pager 2>&1 || true"))
              print(target.succeed(f"journalctl -b -u {unit} --no-pager 2>&1 || true"))
              if unit == "aos-graph-compile.service":
                  print("--- PCR 15 and AOS CEL ---")
                  print(target.succeed(
                      f"{TPM2_PCRREAD} sha256:15 2>&1 || true; "
                      "cat /run/log/aos-packages.cel 2>&1 || true"
                  ))
                  print(target.succeed(
                      "systemctl status 'aos-pkg-*' aos-fetch.target "
                      "aos-config-render.target aos-activate.service "
                      "aos-config.target --no-pager 2>&1 || true"
                  ))
                  print(target.succeed(
                      "journalctl -b -u 'aos-pkg-*' -u aos-fetch.target "
                      "-u aos-config-render.target -u aos-activate.service "
                      "-u aos-config.target --no-pager 2>&1 || true"
                  ))
              raise AssertionError(f"{unit} is {state}, expected active")
      # The retained operator module must be attested under the exact platform
      # identity recorded by initrd authorization. Reaching multi-user also
      # proves the mandatory quote was published successfully.
      target.succeed(f"""
          platform=$({JQ} -er '.platform_id' \
            /run/aos-metadata/.provisioning-result.json)
          current=$({JQ} -er '.current' /var/lib/profiles/system/state.json)
          {JQ} -e --arg platform "$platform" \
            '.quote_status == "quoted"
             and .inputs.host_nix.trust_mode == "platform"
             and .inputs.host_nix.platform == $platform' \
            /var/lib/profiles/system/gen-$current/gen-attestation.json
      """)
      target.succeed("""
          set -eu
          for file in /var/lib/aos-provisioning/desired/repart.d/*/*-var.conf; do
            while IFS= read -r line; do
              case "$line" in Format=*) exit 1 ;; esac
            done < "$file"
          done
      """)

      # ════ 2. Enroll db → KEK → PK, reboot into enforcing SB ═══════════
      eu = "PATH=${pkgs.util-linux}/bin:$PATH ${pkgs.efitools}/bin/efi-updatevar"
      keys = "${pkgs.secure-boot-test-keys}"
      for var in ("db", "KEK", "PK"):
          target.succeed(f"{eu} -f {keys}/{var}.auth {var} 2>&1")
      assert efivar_byte("SetupMode") == 0, "PK enrollment should exit Setup Mode"
      target.reboot(timeout=600)

      # ════ 3. First enforcing boot — /var sealed to the signed policy ══
      wait_multi_user("boot2 (enforcing seal)")
      assert efivar_byte("SecureBoot") == 1, "Secure Boot should be enforcing"
      target.succeed(
          "test \"$(cat /run/aos-metadata/storage-coherence)\" = coherent"
      )
      # /var is now a LUKS2 device, mounted via the device-mapper node.
      # isLuks confirms LUKS; the systemd-tpm2 token (a LUKS2-only feature)
      # confirms it was sealed to the TPM. (luksDump prints "Version: 2",
      # not the literal "LUKS2", and the agent capture tail-truncates to
      # the Tokens section, so assert on the token, not a header string.)
      target.succeed(f"{CS} isLuks {VARDEV}")
      dump = target.succeed(f"{CS} luksDump {VARDEV}")
      assert "systemd-tpm2" in dump, f"/var has no TPM2 token:\n{dump}"
      assert "systemd-recovery" in dump, f"/var has no recovery token:\n{dump}"
      legacy_metadata = json.loads(target.succeed(
          f"{CS} luksDump --dump-json-metadata {VARDEV}"
      ))
      legacy_tpm_tokens = [
          token for token in legacy_metadata["tokens"].values()
          if token["type"] == "systemd-tpm2"
      ]
      assert len(legacy_tpm_tokens) == 1, legacy_tpm_tokens
      assert sorted(legacy_tpm_tokens[0]["tpm2-pcrs"]) == [7], legacy_tpm_tokens
      recovery_key_encoded = base64.b64encode(
          target.succeed("cat /run/aos-var-recovery.key").encode()
      ).decode()
      recovery_key = base64.b64decode(recovery_key_encoded).decode().strip()

      clean_pcr12 = read_pcr12()
      assert clean_pcr12 == "0" * 64, (
          f"clean embedded-command-line boot unexpectedly extended PCR 12: {clean_pcr12}"
      )
      migration_evidence = "/var/lib/aos/security/var-policy-migration.json"
      target.fail(f"""
          AOS_VAR_POLICY_MIGRATE_STOP_AFTER_VERIFY=1 {VAR_POLICY_MIGRATE} \
            {VARDEV} \
            /run/aos-var-recovery.key \
            /etc/aos/pcr-sign.pem \
            /run/systemd/tpm2-pcr-signature.json \
            {migration_evidence}
      """, timeout=180)
      interrupted_evidence = json.loads(target.succeed(f"cat {migration_evidence}"))
      assert interrupted_evidence["state"] == "verified", interrupted_evidence
      interrupted_metadata = json.loads(target.succeed(
          f"{CS} luksDump --dump-json-metadata {VARDEV}"
      ))
      assert len([
          token for token in interrupted_metadata["tokens"].values()
          if token["type"] == "systemd-tpm2"
      ]) == 2, interrupted_metadata
      target.succeed(
          f"{CS} open --test-passphrase "
          f"--key-slot {interrupted_evidence['recovery_keyslot']} "
          f"--key-file /run/aos-var-recovery.key {VARDEV}"
      )
      target.succeed(f"""
          {VAR_POLICY_MIGRATE} \
            {VARDEV} \
            /run/aos-var-recovery.key \
            /etc/aos/pcr-sign.pem \
            /run/systemd/tpm2-pcr-signature.json \
            {migration_evidence}
      """, timeout=180)
      migrated_metadata = json.loads(target.succeed(
          f"{CS} luksDump --dump-json-metadata {VARDEV}"
      ))
      migrated_tpm_tokens = [
          token for token in migrated_metadata["tokens"].values()
          if token["type"] == "systemd-tpm2"
      ]
      assert len(migrated_tpm_tokens) == 1, migrated_tpm_tokens
      migrated_token = migrated_tpm_tokens[0]
      assert sorted(migrated_token["tpm2-pcrs"]) == [7, 12], migrated_token
      assert sorted(migrated_token["tpm2_pubkey_pcrs"]) == [11], migrated_token
      assert migrated_token["tpm2-pcr-bank"] == "sha256", migrated_token
      expected_pubkey = base64.b64encode(
          target.succeed("cat /etc/aos/pcr-sign.pem").encode()
      ).decode()
      assert migrated_token["tpm2_pubkey"] == expected_pubkey, migrated_token
      evidence = json.loads(target.succeed(f"cat {migration_evidence}"))
      assert evidence["schema"] == "aos.var-tpm-policy-migration/v1", evidence
      assert evidence["state"] == "complete", evidence
      assert evidence["pinned_pcrs"] == [7, 12], evidence
      assert evidence["recovery_authorized"] is True, evidence
      assert read_pcr12() == clean_pcr12, "migration changed the live PCR-12 state"

      evidence_digest = target.succeed(
          f"sha256sum {migration_evidence} | cut -d' ' -f1"
      ).strip()
      metadata_digest = hashlib.sha256(json.dumps(
          migrated_metadata, sort_keys=True, separators=(",", ":")
      ).encode()).hexdigest()
      invalid_evidence_mutations = [
          ".planned_old_tpm_keyslots = [-1]",
          ".old_token_ids = [0.5]",
          '.verified_tpm_token_id = "0"',
          '.verified_tpm_keyslot = "0"',
      ]
      for mutation in invalid_evidence_mutations:
          target.succeed(f"cp {migration_evidence} /run/var-policy-migration.valid.json")
          target.succeed(f"""
              {JQ} '{mutation}' {migration_evidence} \
                > /run/var-policy-migration.invalid.json
              mv /run/var-policy-migration.invalid.json {migration_evidence}
          """)
          target.fail(f"""
              {VAR_POLICY_MIGRATE} \
                {VARDEV} \
                /run/aos-var-recovery.key \
                /etc/aos/pcr-sign.pem \
                /run/systemd/tpm2-pcr-signature.json \
                {migration_evidence}
          """, timeout=180)
          target.succeed(f"mv /run/var-policy-migration.valid.json {migration_evidence}")
      target.succeed(f"""
          {VAR_POLICY_MIGRATE} \
            {VARDEV} \
            /run/aos-var-recovery.key \
            /etc/aos/pcr-sign.pem \
            /run/systemd/tpm2-pcr-signature.json \
            {migration_evidence}
      """, timeout=180)
      assert target.succeed(
          f"sha256sum {migration_evidence} | cut -d' ' -f1"
      ).strip() == evidence_digest, "completed migration evidence was rewritten"
      rerun_metadata = json.loads(target.succeed(
          f"{CS} luksDump --dump-json-metadata {VARDEV}"
      ))
      assert hashlib.sha256(json.dumps(
          rerun_metadata, sort_keys=True, separators=(",", ":")
      ).encode()).hexdigest() == metadata_digest, "idempotent rerun changed LUKS metadata"

      dump = target.succeed(f"{CS} luksDump {VARDEV}")
      sealed_luks_digest = hashlib.sha256(dump.encode()).hexdigest()
      src = var_source()
      assert src == "/dev/mapper/var", f"/var not on the LUKS mapper: {src!r}"
      seal_log = target.succeed(
          "journalctl -b -k --no-pager 2>&1"
      )
      assert "isLuks=N" in seal_log, seal_log
      assert "unlocking /var via TPM2" not in seal_log, seal_log
      assert_recurrent_substrate("boot2")

      root_hash, root_data, root_hash_device, expected_pcr11 = assert_verified_root()
      assert_generation_attestation(root_hash, expected_pcr11)

      # A guard-valid boot can still acquire a different PCR-12 state. The
      # TPM policy itself must deny the exact TPM token while the retained,
      # exact recovery keyslot remains usable.
      target.succeed(f"{TPM2_PCREXTEND} 12:sha256={'a5' * 32}")
      assert read_pcr12() != clean_pcr12
      current_generation = target.succeed(
          f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
      ).strip()
      target.fail(f"""
          {APM} attest __verify-boot-commit \
            --generation-attestation /var/lib/profiles/system/gen-{current_generation}/gen-attestation.json \
            --quote-dir /var/lib/profiles/system/gen-{current_generation}/gen-attestation-quote \
            --expected-pcr11 sha256:{expected_pcr11}
      """)
      target.fail(
          f"{CS} open --test-passphrase --token-only "
          f"--token-id {evidence['verified_tpm_token_id']} "
          f"--external-tokens-path ${pkgs.systemd}/lib/cryptsetup {VARDEV}"
      )
      target.succeed(
          f"{CS} open --test-passphrase "
          f"--key-slot {evidence['recovery_keyslot']} "
          f"--key-file /run/aos-var-recovery.key {VARDEV}"
      )

      # ════ 4. Reboot — /var must unlock UNATTENDED via the TPM2 token ══
      target.reboot(timeout=600)
      wait_multi_user("boot3 (unattended unlock)")
      assert efivar_byte("SecureBoot") == 1
      assert read_pcr12() == clean_pcr12, "clean reboot changed pinned PCR 12"
      src = var_source()
      assert src == "/dev/mapper/var", (
          f"/var did not unlock via TPM2 on reboot (source {src!r})"
      )
      dump = target.succeed(f"{CS} luksDump {VARDEV}")
      assert "systemd-tpm2" in dump, "TPM2 token vanished across reboot"
      assert hashlib.sha256(dump.encode()).hexdigest() == sealed_luks_digest, (
          "LUKS metadata changed on the steady-state unlock boot; formatting or "
          "enrollment must run only when state is absent"
      )
      unlock_log = target.succeed(
          "journalctl -b -k --no-pager 2>&1"
      )
      assert "isLuks=Y" in unlock_log, unlock_log
      assert "unlocking /var via TPM2" in unlock_log, unlock_log
      assert "isLuks=N" not in unlock_log, unlock_log
      assert_recurrent_substrate("boot3")
      # The unlock above proves the signed policy extracted and compared in
      # assert_verified_root() was accepted by the TPM across a fresh boot.
      assert_verified_root()
      assert_tamper_rejected(root_hash, root_data, root_hash_device)
      print("=== /var unsealed UNATTENDED via TPM2 across reboot ===")

      # ════ 5. A/B and counted-candidate PCR-12 qualification ════════
      # Populate the initially empty B data/hash partitions from the verified
      # A bytes, then boot the independently measured slot-B UKI under a
      # counted filename. This isolates the boot-entry lifecycle from payload
      # differences: every supported clean transition must leave PCR 12 at its
      # reset value while PCR 11 selects the slot-specific signed policy. The
      # temporary generation also records recovery B exactly as a production
      # slot-B generation would; initrd seeding rejects cross-slot recovery
      # metadata before switch-root.
      candidate_name = "aos-phase3-slot-b+3.efi"
      stable_name = "aos-phase3-slot-b.efi"
      image_state_a_text = target.succeed("cat /var/lib/profiles/image/state.json")
      image_state_a = json.loads(image_state_a_text)
      running_a = image_state_a["running"]
      generation_a = next(
          generation for generation in image_state_a["generations"]
          if generation["number"] == running_a
      )
      stable_a_name = re.sub(
          r"\+[0-9]+(?:-[0-9]+)?(?=\.efi$)",
          "",
          generation_a["uki_path"].split("/")[-1],
      )
      image_state_a_encoded = base64.b64encode(image_state_a_text.encode()).decode()
      target.succeed(f"""
          dd if=/dev/disk/by-partlabel/root-a of=/dev/disk/by-partlabel/root-b bs=4M conv=fsync status=none
          dd if=/dev/disk/by-partlabel/root-a-hash of=/dev/disk/by-partlabel/root-b-hash bs=4M conv=fsync status=none
          mkdir -p /run/aos-uki-b-media
          {MOUNT} -t ext4 -o ro /dev/disk/by-label/aos-uki-b /run/aos-uki-b-media
          {MOUNT} -o remount,rw /boot
          cp /run/aos-uki-b-media/uki-b.efi /boot/EFI/Linux/{candidate_name}
          recovery_b_digest=$(${pkgs.coreutils}/bin/sha256sum \
            /boot/EFI/AOS/recovery-b.efi | ${pkgs.coreutils}/bin/cut -d' ' -f1)
          recovery_b_size=$(${pkgs.coreutils}/bin/stat -c %s \
            /boot/EFI/AOS/recovery-b.efi)
          {JQ} --arg candidate "EFI/Linux/{candidate_name}" \
            --arg recovery_digest "$recovery_b_digest" \
            --argjson recovery_size "$recovery_b_size" '
            .running as $running
            | (.generations[] | select(.number == $running)) |=
                (.uki_source_path = (.uki_source_path // .uki_path)
                 | .uki_path = $candidate
                 | .slot = "B"
                 | .recovery.copy = "B"
                 | .recovery.uki_path = "EFI/AOS/recovery-b.efi"
                 | .recovery.entry_path = "loader/entries/recovery-b.conf"
                 | .recovery.source_path = "recovery-b.efi"
                 | .recovery.sha256 = $recovery_digest
                 | .recovery.byte_size = $recovery_size
                 | del(.initrd_pcr11, .expected_pcr11))
            | .default = $running
            | .pending = null
          ' /var/lib/profiles/image/state.json > /var/lib/profiles/image/.state.json.phase3-b
          mv /var/lib/profiles/image/.state.json.phase3-b /var/lib/profiles/image/state.json
          sync /var/lib/profiles/image
          {BOOTCTL} set-oneshot {stable_name}
          {MOUNT} -o remount,ro /boot
          {UMOUNT} /run/aos-uki-b-media
      """, timeout=300)
      target.reboot(timeout=600)
      wait_multi_user("boot4 (counted slot-B candidate)")
      assert read_pcr12() == clean_pcr12, "counted slot-B boot changed PCR 12"
      assert "/dev/disk/by-partlabel/root-b" in target.succeed("cat /proc/cmdline")
      assert var_source() == "/dev/mapper/var"
      target.succeed("test -e /boot/EFI/Linux/aos-phase3-slot-b+2-1.efi")
      image_state_b = json.loads(target.succeed("cat /var/lib/profiles/image/state.json"))
      generation_b = next(
          generation for generation in image_state_b["generations"]
          if generation["number"] == image_state_b["running"]
      )
      assert generation_b["slot"] == "B"
      assert generation_b["uki_path"] == f"EFI/Linux/{candidate_name}"
      assert generation_b["uki_source_path"] == (
          generation_a.get("uki_source_path") or generation_a["uki_path"]
      )
      assert re.fullmatch(r"[0-9a-f]{64}", generation_b["initrd_pcr11"])
      target.fail("journalctl -b -u aos-seed-profiles.service --no-pager | grep -F 'Failed'")

      target.succeed(f"""
          {MOUNT} -o remount,rw /boot
          ${pkgs.systemd}/lib/systemd/systemd-bless-boot --path=/boot good
          {BOOTCTL} set-default {stable_name}
          test -e /boot/EFI/Linux/{stable_name}
          {MOUNT} -o remount,ro /boot
      """)
      assert read_pcr12() == clean_pcr12, "committing candidate changed PCR 12"

      target.reboot(timeout=600)
      wait_multi_user("boot5 (committed slot-B candidate)")
      assert read_pcr12() == clean_pcr12, "committed slot-B boot changed PCR 12"
      assert "/dev/disk/by-partlabel/root-b" in target.succeed("cat /proc/cmdline")
      assert var_source() == "/dev/mapper/var"

      target.reboot(timeout=600)
      wait_multi_user("boot6 (normal reboot after commit)")
      assert read_pcr12() == clean_pcr12, "post-commit reboot changed PCR 12"
      assert "/dev/disk/by-partlabel/root-b" in target.succeed("cat /proc/cmdline")
      assert var_source() == "/dev/mapper/var"

      # This is deliberately a bootloader/PCR qualification using identical
      # immutable payload bytes, not an APM image-generation transition.
      # Restore the exact coherent AOS image index and durable A entry before
      # later tests exercise the production evaluation/commit services.
      target.succeed(f"""
          printf '%s' {image_state_a_encoded} | base64 -d > /var/lib/profiles/image/.state.json.phase3-a
          mv /var/lib/profiles/image/.state.json.phase3-a /var/lib/profiles/image/state.json
          sync /var/lib/profiles/image
          {MOUNT} -o remount,rw /boot
          {BOOTCTL} set-default {stable_a_name}
          {MOUNT} -o remount,ro /boot
      """)
      target.reboot(timeout=600)
      wait_multi_user("boot7 (coherent slot-A state restored)")
      assert read_pcr12() == clean_pcr12
      assert "/dev/disk/by-partlabel/root-a" in target.succeed("cat /proc/cmdline")
      assert var_source() == "/dev/mapper/var"
      assert json.loads(target.succeed("cat /var/lib/profiles/image/state.json")) == image_state_a

      # ════ 6. External command-line transports cannot override UKIs ════
      # Under enforcing Secure Boot, systemd-boot measures Type #1 entry
      # options into PCR 12 and the stub then discards them when an embedded
      # .cmdline exists. The signed command line remains authoritative while
      # the changed PCR denies unattended /var unlock.
      target.succeed(f"""
          {MOUNT} -o remount,rw /boot
          printf '%s\n' \
            'title AOS EFI LoadOptions rejection test' \
            'efi /EFI/Linux/{stable_a_name}' \
            'options rdinit=/bin/sh' \
            > /boot/loader/entries/aos-load-options-test.conf
          {BOOTCTL} set-oneshot aos-load-options-test.conf
          sync /boot
          {MOUNT} -o remount,ro /boot
      """)
      transcript = target.relaunch_with_smbios_oem_strings(
          [], expect_agent=False, settle=45
      )
      assert_external_cmdline_absent(transcript, "rdinit=/bin/sh")
      assert "aos-var-crypt: TPM2 unlock failed" in transcript, transcript[-12000:]
      assert "AOS recovery>" not in transcript, transcript[-12000:]

      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("clean recovery after EFI LoadOptions rejection")
      assert read_pcr12() == clean_pcr12
      assert var_source() == "/dev/mapper/var"
      target.succeed(f"""
          {MOUNT} -o remount,rw /boot
          rm -f /boot/loader/entries/aos-load-options-test.conf
          {MOUNT} -o remount,ro /boot
      """)

      # A db-signed addon is accepted and measured into PCR 12, but its
      # command-line fragment is discarded. The changed PCR denies unattended
      # /var unlock, proving measurement happened even though rdinit did not.
      target.succeed(f"""
          set -eu
          mkdir -p /run/aos-uki-b-media
          {MOUNT} -t ext4 -o ro /dev/disk/by-label/aos-uki-b /run/aos-uki-b-media
          {MOUNT} -o remount,rw /boot
          cp /boot/EFI/Linux/{stable_a_name} /boot/EFI/Linux/aos-signed-addon-test.efi
          mkdir -p /boot/EFI/Linux/aos-signed-addon-test.efi.extra.d
          cp /run/aos-uki-b-media/signed.addon.efi \
            /boot/EFI/Linux/aos-signed-addon-test.efi.extra.d/injected.addon.efi
          {BOOTCTL} set-oneshot aos-signed-addon-test.efi
          sync /boot
          {MOUNT} -o remount,ro /boot
          {UMOUNT} /run/aos-uki-b-media
      """)
      transcript = target.relaunch_with_smbios_oem_strings(
          [], expect_agent=False, settle=45
      )
      assert "Ignoring externally supplied command line because the UKI embeds one." in transcript, transcript[-12000:]
      assert_external_cmdline_absent(transcript, "rdinit=/bin/sh")
      assert "aos-var-crypt: TPM2 unlock failed" in transcript, transcript[-12000:]
      assert "AOS recovery>" not in transcript, transcript[-12000:]

      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("clean recovery after signed addon")
      assert read_pcr12() == clean_pcr12
      assert var_source() == "/dev/mapper/var"
      target.succeed(f"""
          {MOUNT} -o remount,rw /boot
          rm -rf /boot/EFI/Linux/aos-signed-addon-test.efi.extra.d
          rm -f /boot/EFI/Linux/aos-signed-addon-test.efi
          {MOUNT} -o remount,ro /boot
      """)

      # An unsigned addon is rejected by the Secure Boot image loader before
      # its .cmdline is measured. The copied UKI still boots with clean PCR 12.
      target.succeed(f"""
          set -eu
          mkdir -p /run/aos-uki-b-media
          {MOUNT} -t ext4 -o ro /dev/disk/by-label/aos-uki-b /run/aos-uki-b-media
          {MOUNT} -o remount,rw /boot
          cp /boot/EFI/Linux/{stable_a_name} /boot/EFI/Linux/aos-unsigned-addon-test.efi
          mkdir -p /boot/EFI/Linux/aos-unsigned-addon-test.efi.extra.d
          cp /run/aos-uki-b-media/unsigned.addon.efi \
            /boot/EFI/Linux/aos-unsigned-addon-test.efi.extra.d/injected.addon.efi
          {BOOTCTL} set-oneshot aos-unsigned-addon-test.efi
          sync /boot
          {MOUNT} -o remount,ro /boot
          {UMOUNT} /run/aos-uki-b-media
      """)
      offset = serial_offset()
      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("unsigned addon rejection")
      transcript = serial_since(offset)
      assert "injected.addon.efi" in transcript and "ignoring" in transcript, transcript[-12000:]
      assert_external_cmdline_absent(transcript, "rdinit=/bin/sh")
      assert read_pcr12() == clean_pcr12
      assert var_source() == "/dev/mapper/var"
      target.succeed(f"""
          {MOUNT} -o remount,rw /boot
          rm -rf /boot/EFI/Linux/aos-unsigned-addon-test.efi.extra.d
          rm -f /boot/EFI/Linux/aos-unsigned-addon-test.efi
          {MOUNT} -o remount,ro /boot
      """)

      # Recovery has no TPM-authorized degraded mode to preserve. After
      # measuring an external fragment, the stub refuses the launch rather
      # than entering even the bounded recovery console.
      target.succeed(f"""
          {BOOTCTL} set-oneshot recovery-a.conf
          sync
      """)
      transcript = target.relaunch_with_smbios_oem_strings(
          ["io.systemd.stub.kernel-cmdline-extra=rdinit=/bin/sh"],
          expect_agent=False,
          settle=45,
      )
      assert "Ignoring externally supplied command line because the UKI embeds one." in transcript, transcript[-12000:]
      assert "Refusing recovery boot with an external command line." in transcript, transcript[-12000:]
      assert "Linux version" not in transcript, transcript[-12000:]
      assert "AOS recovery>" not in transcript, transcript[-12000:]
      assert "aos-var-crypt: unlocking /var via TPM2" not in transcript, transcript[-12000:]

      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("normal boot after refused recovery SMBIOS launch")
      assert read_pcr12() == clean_pcr12

      # SMBIOS Type-11 fragments are accepted and measured before being
      # discarded, so every case must deny the PCR-12-bound TPM token.
      appended_inputs = [
          "SYSTEMD_SULOGIN_FORCE=1",
          "rdinit=/bin/sh",
          f"roothash={root_hash}",
          "rd.systemd.unit=emergency.target",
      ]
      for appended in appended_inputs:
          transcript = target.relaunch_with_smbios_oem_strings(
              [f"io.systemd.stub.kernel-cmdline-extra={appended}"],
              expect_agent=False,
              settle=45,
          )
          assert (
              "Ignoring externally supplied command line because the UKI embeds one."
              in transcript
          ), transcript
          if appended.startswith("roothash="):
              kernel_cmdlines = [
                  line.split("Command line:", 1)[1].strip()
                  for line in transcript.splitlines()
                  if "Command line:" in line
              ]
              assert kernel_cmdlines, transcript
              effective_cmdline = kernel_cmdlines[-1].split()
              assert effective_cmdline.count(appended) == 1, effective_cmdline
          else:
              assert_external_cmdline_absent(transcript, appended)
          assert "aos-var-crypt: TPM2 unlock failed" in transcript, transcript
          assert "AOS recovery>" not in transcript, transcript

          target.relaunch_with_smbios_oem_strings([], timeout=600)
          wait_multi_user(f"clean recovery after appended input {appended}")
          assert read_pcr12() == clean_pcr12
          assert var_source() == "/dev/mapper/var"
          target.succeed(f"""
              printf '%s' {recovery_key_encoded} | base64 -d > /run/aos-var-recovery.key
              chmod 0600 /run/aos-var-recovery.key
              {CS} open --test-passphrase \
                --key-slot {evidence['recovery_keyslot']} \
                --key-file /run/aos-var-recovery.key {VARDEV}
          """)

      # ════ 7. Paired recovery UKIs boot without normal storage ═════
      recovery_state = target.succeed(
          "base64 -w0 /var/lib/profiles/image/state.json"
      ).strip()

      # The bounded console rejects a wrong key, accepts the per-machine key,
      # contains a maintenance shell, and closes both /var and its mapper on
      # shell exit. Exercise a valid authenticated restore while recovery A is
      # running; it may replace only B.
      target.succeed(f"{BOOTCTL} set-oneshot recovery-a.conf && sync")
      transcript = reboot_recovery_console()
      assert "AOS signed recovery environment" in transcript, transcript[-12000:]

      offset = serial_offset()
      target.send_serial("7\n")
      wait_serial("AOS /var recovery key:", offset)
      offset = serial_offset()
      target.send_serial("definitely-wrong-recovery-key\n")
      wait_serial("persistent state remains locked", offset)

      offset = serial_offset()
      target.send_serial("7\n")
      wait_serial("AOS /var recovery key:", offset)
      offset = serial_offset()
      target.send_serial(recovery_key + "\n")
      wait_serial("persistent state authenticated and mounted at /var", offset)

      offset = serial_offset()
      target.send_serial("8\n")
      wait_serial("AOS authenticated maintenance shell", offset)
      offset = serial_offset()
      target.send_serial(
          "test -e /dev/mapper/var && while read -r device mountpoint rest; do "
          "if test \"$mountpoint\" = /var; then echo AOS_RECOVERY_SHELL_OK; break; fi; "
          "done < /proc/mounts\nexit\n"
      )
      shell_transcript = wait_serial(
          "maintenance session ended; persistent state is locked", offset
      )
      assert "AOS_RECOVERY_SHELL_OK" in shell_transcript, shell_transcript[-12000:]
      offset = serial_offset()
      target.send_serial("1\n")
      status_transcript = wait_serial("persistent-state: locked", offset)
      assert "cleanup-required-mapper-open" not in status_transcript, status_transcript[-12000:]

      offset = serial_offset()
      target.send_serial("6\n")
      wait_serial("type RESTORE SLOT B to continue:", offset, timeout=600)
      offset = serial_offset()
      target.send_serial("RESTORE SLOT B\n")
      wait_serial("AOS /var recovery key:", offset)
      offset = serial_offset()
      target.send_serial(recovery_key + "\n")
      wait_serial("slot B restored", offset, timeout=900)
      offset = serial_offset()
      target.send_serial("3\n")
      wait_serial("slot B: verified", offset, timeout=600)
      offset = serial_offset()
      target.send_serial("2\n")
      wait_serial("slot A: verified", offset, timeout=600)
      target.send_serial("p\n")
      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("normal boot after authenticated recovery restore")
      assert target.succeed(
          "base64 -w0 /var/lib/profiles/image/state.json"
      ).strip() == recovery_state
      assert var_source() == "/dev/mapper/var"

      # The same transport becomes malicious. Recovery must reject its changed
      # manifest before confirmation, key prompting, or any destination write.
      target.succeed(f"""
          mkdir -p /run/aos-recovery-media
          {MOUNT} -t ext4 -o rw /dev/disk/by-label/AOS-RECOVERY /run/aos-recovery-media
          printf '\n' >> /run/aos-recovery-media/aos/recovery/recovery-bundle.json
          sync /run/aos-recovery-media
          {UMOUNT} /run/aos-recovery-media
          {BOOTCTL} set-oneshot recovery-a.conf
          sync
      """)
      transcript = reboot_recovery_console()
      assert "AOS signed recovery environment" in transcript, transcript[-12000:]
      offset = serial_offset()
      target.send_serial("6\n")
      rejected = wait_serial("restore refused:", offset)
      assert "type RESTORE SLOT" not in rejected, rejected[-12000:]
      assert "AOS /var recovery key:" not in rejected, rejected[-12000:]
      target.send_serial("p\n")
      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("normal boot after tampered recovery bundle rejection")
      assert target.succeed(
          "base64 -w0 /var/lib/profiles/image/state.json"
      ).strip() == recovery_state
      assert var_source() == "/dev/mapper/var"

      recovery_entries = target.succeed(
          "find /boot/EFI/Linux -maxdepth 1 -type f -name '*.efi' -printf '%f\\n' | sort"
      )
      for copy in ["a", "b"]:
          target.succeed(f"{BOOTCTL} set-oneshot recovery-{copy}.conf && sync")
          transcript = reboot_recovery_console()
          assert "AOS signed recovery environment" in transcript, transcript[-12000:]
          assert "Persistent state is locked. Networking is disabled." in transcript, transcript[-12000:]
          assert "unlocking /var via TPM2" not in transcript, transcript[-12000:]
          assert "Switching root" not in transcript, transcript[-12000:]
          assert "Reached target Network" not in transcript, transcript[-12000:]
          assert "Give root password for maintenance" not in transcript, transcript[-12000:]

          target.relaunch_with_smbios_oem_strings([], timeout=600)
          wait_multi_user(f"normal boot after recovery {copy.upper()}")
          assert target.succeed(
              "base64 -w0 /var/lib/profiles/image/state.json"
          ).strip() == recovery_state
          assert target.succeed(
              "find /boot/EFI/Linux -maxdepth 1 -type f -name '*.efi' -printf '%f\\n' | sort"
          ) == recovery_entries
          assert var_source() == "/dev/mapper/var"

      # A normal boot is intentionally fail-closed when its paired recovery
      # artifact cannot be authenticated. Make the untouched recovery copy the
      # fallback instead: reaching its signed copy identity proves both that
      # firmware rejected the modified PE and that the retained copy remains
      # usable. The authenticated maintenance shell then repairs only the
      # damaged recovery artifact before normal boot resumes.
      for copy in ["a", "b"]:
          retained = "b" if copy == "a" else "a"
          target.succeed(f"""
              {MOUNT} -o remount,rw /boot
              cp /boot/EFI/AOS/recovery-{copy}.efi /var/recovery-{copy}.efi.qualified
              printf X | dd of=/boot/EFI/AOS/recovery-{copy}.efi bs=1 seek=4096 conv=notrunc
              sync /boot
              {MOUNT} -o remount,ro /boot
              {BOOTCTL} set-default recovery-{retained}.conf
              {BOOTCTL} set-oneshot recovery-{copy}.conf
              sync
          """)
          transcript = reboot_recovery_console()
          assert "AOS signed recovery environment" in transcript, transcript[-12000:]

          offset = serial_offset()
          target.send_serial("1\n")
          status_transcript = wait_serial(
              f"recovery-copy: {retained.upper()}", offset
          )
          assert f"recovery-copy: {copy.upper()}" not in status_transcript

          offset = serial_offset()
          target.send_serial("7\n")
          wait_serial("AOS /var recovery key:", offset)
          offset = serial_offset()
          target.send_serial(recovery_key + "\n")
          wait_serial("persistent state authenticated and mounted at /var", offset)
          offset = serial_offset()
          target.send_serial("8\n")
          wait_serial("AOS authenticated maintenance shell", offset)
          offset = serial_offset()
          target.send_serial(f"""
              set -e
              mkdir -p /run/aos-recovery/esp
              mount -t vfat -o rw /dev/disk/by-partlabel/ESP /run/aos-recovery/esp
              cp /var/recovery-{copy}.efi.qualified /run/aos-recovery/esp/EFI/AOS/recovery-{copy}.efi
              sync
              mount -o remount,rw,nosuid,nodev,noexec /sys/firmware/efi/efivars
              bootctl --esp-path /run/aos-recovery/esp set-default {stable_a_name}
              mount -o remount,ro,nosuid,nodev,noexec /sys/firmware/efi/efivars
              umount /run/aos-recovery/esp
              echo AOS_RECOVERY_COPY_REPAIRED
              exit
          """)
          repair_transcript = wait_serial(
              "maintenance session ended; persistent state is locked", offset
          )
          assert "AOS_RECOVERY_COPY_REPAIRED" in repair_transcript, repair_transcript[-12000:]

          target.send_serial("p\n")
          target.relaunch_with_smbios_oem_strings([], timeout=600)
          wait_multi_user(f"normal boot after repairing recovery {copy.upper()}")
          assert var_source() == "/dev/mapper/var"
          target.succeed(f"rm -f /var/recovery-{copy}.efi.qualified")

      # ════ 8. A real corrupt counted root fails and falls back ════
      recovery_a_before = target.succeed(
          "sha256sum /boot/EFI/AOS/recovery-a.efi | cut -d ' ' -f1"
      ).strip()
      target.succeed(f"""
          set -eu
          mkdir -p /run/aos-uki-b-media
          {MOUNT} -t ext4 -o ro /dev/disk/by-label/aos-uki-b /run/aos-uki-b-media
          {MOUNT} -o remount,rw /boot
          cp /run/aos-uki-b-media/uki-b.efi /boot/EFI/Linux/aos-corrupt-slot-b+1.efi
          sync /boot
          {MOUNT} -o remount,ro /boot
          {UMOUNT} /run/aos-uki-b-media
          printf X | dd of=/dev/disk/by-partlabel/root-b bs=1 seek=4096 conv=notrunc
          sync /dev/disk/by-partlabel/root-b
          {BOOTCTL} set-oneshot aos-corrupt-slot-b.efi
          sync
      """)
      transcript = target.relaunch_with_smbios_oem_strings(
          [], expect_agent=False, settle=45
      )
      assert (
          "AOS root verification failure: corrupt root rejected; /var unmounted"
          in transcript
      ), transcript[-12000:]
      assert "Switching root" not in transcript, transcript[-12000:]
      assert "unlocking /var via TPM2" not in transcript, transcript[-12000:]
      assert "Give root password for maintenance" not in transcript, transcript[-12000:]

      target.relaunch_with_smbios_oem_strings([], timeout=600)
      wait_multi_user("known-good slot-A fallback after corrupt slot B")
      assert "/dev/disk/by-partlabel/root-a" in target.succeed("cat /proc/cmdline")
      assert var_source() == "/dev/mapper/var"
      assert target.succeed(
          "sha256sum /boot/EFI/AOS/recovery-a.efi | cut -d ' ' -f1"
      ).strip() == recovery_a_before

      # ════ 9. Fault injection — failed ready phase must not bless ═══
      target.succeed(f"""
          set -eu
          mkdir -p /var/etc/systemd/system/systemd-pcrphase.service.d
          printf '%s\n' '[Unit]' 'FailureAction=none' \
            '[Service]' 'ExecStart=' \
            'ExecStart=${pkgs.coreutils}/bin/false' \
            > /var/etc/systemd/system/systemd-pcrphase.service.d/fail.conf
          {JQ} '.pending = .running' /var/lib/profiles/image/state.json \
            > /var/lib/profiles/image/.state.json.pcrphase-fault
          mv /var/lib/profiles/image/.state.json.pcrphase-fault \
            /var/lib/profiles/image/state.json
          sync
      """)
      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-failed systemd-pcrphase.service", timeout=120
      )
      target.succeed(
          'test "$(systemctl show aos-eval.service -p ActiveState --value)" = inactive'
      )
      running = target.succeed(
          f"{JQ} -er '.running' /var/lib/profiles/image/state.json"
      ).strip()
      pending = target.succeed(
          f"{JQ} -er '.pending' /var/lib/profiles/image/state.json"
      ).strip()
      assert pending == running, (
          f"failed ready phase changed pending image: running={running}, pending={pending}"
      )
      target.succeed("test -e /run/aos/image-reeval-required")
      target.fail("systemctl is-active aos-image-boot-commit.service")
      print("=== failed PCR 11 ready phase left the image pending and unblessed ===")
    '';
}
