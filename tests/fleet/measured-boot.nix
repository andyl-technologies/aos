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
#      seals its key to the signed PCR policy (PCR 11) + pinned PCR 7, plus
#      a recovery key. Assert SecureBoot=1, /var is a LUKS2 device with a
#      systemd-tpm2 token, mounted via /dev/mapper/var.
#   4. Prove the running root is the dm-verity mapper selected by the UKI,
#      its live root hash and backing devices match the measured `.cmdline`,
#      and the achieved PCR 11 is one predicted from those exact UKI sections.
#      Also prove the base library and evaluator are present in the verified
#      immutable lower store, then alter a copy of the root data and require
#      `veritysetup verify` to reject it.
#   5. Reboot again and assert /var unlocks UNATTENDED via the TPM2 token
#      (no passphrase) — the new boot re-measured PCR 11 but the signed
#      policy still unseals, and PCR 7 is unchanged.
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
        aos.packages.test-http-server.bundle = true;
        environment.systemPackages = [pkgs.binutils pkgs.diffutils pkgs.jq];
      }
    ];
  };
in {
  name = "measured-boot";
  # Image boot + enroll + three reboots (enforcing seal, then unattended
  # unlock). Budget like secure-boot plus an extra reboot.
  timeout = 3600;
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
      import re

      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      CS = "${pkgs.cryptsetup}/sbin/cryptsetup"
      VS = "${pkgs.cryptsetup}/sbin/veritysetup"
      OBJCOPY = "${pkgs.binutils}/bin/objcopy"
      JQ = "${pkgs.jq}/bin/jq"
      CMP = "${pkgs.diffutils}/bin/cmp"
      MEASURE = "${pkgs.systemd}/lib/systemd/systemd-measure"
      APM = "${pkgs.aos}/bin/apm"
      TPM2_CHECKQUOTE = "${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      TPM2_PCRREAD = "${pkgs.tpm2-tools}/bin/tpm2_pcrread"
      VARDEV = "/dev/disk/by-partlabel/var"

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
              "journalctl -b -k --no-pager 2>&1"
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
            environment.etc.\"rfc0011-attested\".text = \"enforcing\\n\";
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
              f"printf '%s' {encoded} | base64 -d > /run/rfc0011-attested-host.nix"
          )
          target.succeed(f"""
              rm -rf /run/rfc0011-attestation-switch
              {APM} switch \
                --from /run/rfc0011-attested-host.nix \
                --facts /run/aos-metadata/facts.json \
                --eval-root /run/rfc0011-attestation-switch
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
              {TPM2_PCRREAD} -o /tmp/rfc0011-current-pcrs sha256:7,11,12,15
              {CMP} {quote_dir}/quote.pcrs /tmp/rfc0011-current-pcrs
          """)
          pcrs = target.succeed(f"{TPM2_PCRREAD} sha256:7,11")
          parsed = {
              int(index): value.lower()
              for index, value in re.findall(r"^\s*(7|11)\s*:\s*0x([0-9A-Fa-f]+)\s*$", pcrs, re.M)
          }
          assert set(parsed) == {7, 11}, pcrs
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
              rm -rf /run/rfc0011-attestation-rederive
              mkdir -p /run/rfc0011-attestation-rederive
              {APM} __eval \
                --host-nix /run/rfc0011-attested-host.nix \
                --base-lib {inputs['base_lib']['store_path']} \
                --facts /run/aos-metadata/facts.json \
                --module-abi {inputs['base_lib']['module_abi']} \
                --out /run/rfc0011-attestation-rederive/manifest.json \
                --eval-root /run/rfc0011-attestation-rederive
          """, timeout=300)
          rederived_text = target.succeed(
              "cat /run/rfc0011-attestation-rederive/manifest.json"
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
              "schema": "aos.gen-attestation-policy/v1",
              "expected_pcr7": parsed[7],
              "expected_pcr11": "sha256:" + expected_pcr11,
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
              f"printf '%s' {policy_encoded} | base64 -d > /run/rfc0011-attestation-policy.json"
          )
          target.succeed(f"""
              printf '%s\n' 'measured-boot fixture identity proof' \
                > /run/rfc0011-attestation-enrollment.txt
              rm -f /run/rfc0011-attestation-identities.json
              {APM} attest enroll \
                --quote-dir {quote_dir} \
                --label measured-boot-target \
                --method out-of-band \
                --evidence-file /run/rfc0011-attestation-enrollment.txt \
                --catalog-file /run/rfc0011-attestation-identities.json
          """, timeout=300)
          verification = json.loads(target.succeed(f"""
              {APM} --json attest verify --system \
                --event-log /run/log/aos-packages.cel \
                --pcr15-baseline {baseline_pcr15} \
                --quote-dir {quote_dir} \
                --nonce {record_digest} \
                --quote-identity-file /run/rfc0011-attestation-identities.json \
                --generation-attestation {record_path} \
                --generation-policy-file /run/rfc0011-attestation-policy.json \
                --rederived-manifest /run/rfc0011-attestation-rederive/manifest.json
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

      # ════ 4. Reboot — /var must unlock UNATTENDED via the TPM2 token ══
      target.reboot(timeout=600)
      wait_multi_user("boot3 (unattended unlock)")
      assert efivar_byte("SecureBoot") == 1
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

      # ════ 5. Fault injection — failed ready phase must not bless ═══
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
