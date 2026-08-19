##! aos-uki — Unified Kernel Image assembly
##!
##! Wraps `systemd-ukify` (from the AOS systemd package built with
##! -Dukify=enabled) to assemble a PE-COFF binary that UEFI firmware
##! loads directly: the sd-stub prepended with kernel + initrd +
##! cmdline + os-release as appended PE sections. One UKI per (kernel,
##! initrd, cmdline, os-release) tuple; the image builder drops it under
##! EFI/Linux/ on the ESP and sd-boot auto-discovers it.
##!
##! The UKI is Secure Boot signed (a single Authenticode signature over
##! the whole PE, covering kernel + initrd + cmdline transitively) ONLY
##! when `secureBootKey`/`secureBootCert` are supplied — otherwise it is
##! an unsigned, byte-reproducible artifact. SB keys are a deployment
##! overlay, never baked into the reproducible base (RFC-0006).
##!
##! Arguments:
##!   kernel     — kernel derivation (provides /boot/vmlinuz-*)
##!   initrd     — initrd derivation (provides /initrd.img)
##!   cmdline    — plain string baked into the UKI's .cmdline section
##!   osRelease  — path to an os-release file (typically the
##!                toplevel's /etc/os-release)
##!   name       — slug used in the output filename
##!   version    — version string used in the output filename
##!   stub       — optional stub PE path; defaults to x86_64 stub
##!                from the systemd package
##!   secureBootKey  — optional db private key (PEM) to sign the UKI
##!   secureBootCert — optional db certificate (PEM); required with key
##!   pcrPrivateKey  — optional PCR-policy private key (PEM); when set,
##!                    ukify measures the UKI and signs a PCR policy into
##!                    the `.pcrsig` section so TPM-sealed secrets unseal
##!                    against "any UKI signed by this key" (survives OTA —
##!                    RFC-0006 measured-boot.md)
##!   pcrPublicKey   — optional PCR-policy public key (PEM); embedded in
##!                    the `.pcrpkey` section, required with pcrPrivateKey
##!   rootHashFile   — optional path to a file containing the dm-verity root
##!                    hash (ASCII hex) of the erofs root. When
##!                    set, `roothash=<hex>` is appended to the materialized
##!                    cmdline before ukify, so the build-output Merkle root —
##!                    unknowable at Nix eval — lands in the same `.cmdline`
##!                    section ukify measures (into PCR 11) and the db key
##!                    signs. This is what binds a UKI to exactly one root
##!                    image. `null` (default) leaves the cmdline untouched, so
##!                    non-verity UKIs are byte-identical.
##!
##! Output: $out/aos-${name}-${version}.efi
{
  mkDerivation,
  systemd,
  sbsigntools,
  binutils,
  openssl,
}: {
  kernel,
  initrd,
  cmdline,
  osRelease,
  name,
  version,
  stub ? null,
  secureBootKey ? null,
  secureBootCert ? null,
  pcrPrivateKey ? null,
  pcrPublicKey ? null,
  rootHashFile ? null,
}: let
  effectiveStub =
    if stub != null
    then stub
    else "${systemd}/lib/systemd/boot/efi/linuxx64.efi.stub";
  signing = secureBootKey != null;
  signArgs =
    if signing
    then "--signtool=sbsign --secureboot-private-key=${secureBootKey} --secureboot-certificate=${secureBootCert}"
    else "";
  # Signing a PCR policy makes the seal track the policy key, not a fixed
  # hash, so any db-signed UKI unseals /var across upgrades.
  measuring = pcrPrivateKey != null;
  pcrArgs =
    if measuring
    then "--pcr-private-key=${pcrPrivateKey} --pcr-public-key=${pcrPublicKey}"
    else "";
in
  mkDerivation {
    pname = "aos-uki-${name}";
    inherit version;
    src = null;

    # systemd carries `ukify` (and pefile/pyelftools via the wrapper) in
    # its `tools` output. The main systemd output is still needed for
    # the linuxx64.efi.stub (consumed via ${effectiveStub} below).
    # sbsigntools (sbsign) is only needed when signing.
    buildDeps =
      [systemd.tools systemd]
      ++ (
        if measuring
        then [binutils openssl]
        else []
      )
      ++ (
        if signing
        then [sbsigntools]
        else []
      );
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out
          # When signing a PCR policy, ukify shells out to systemd-measure
          # to compute the section measurements. It lives in systemd's
          # lib/systemd (not bin), so put that on PATH — otherwise ukify
          # falls back to /usr/lib/systemd/systemd-measure (absent in the
          # sandbox) and fails.
          export PATH="${systemd}/lib/systemd''${PATH:+:$PATH}"
          # cmdline arrives as a Nix string; materialize to a file so
          # ukify's @path read path handles special characters and
          # trailing-newline rules consistently. When a
          # rootHashFile is supplied, append `roothash=<hex>` here — this is
          # the load-bearing trick. The roothash is a build output (the Merkle
          # root of root.img), unknowable at Nix eval, so it cannot travel
          # through aos.boot.kernelParams; injecting it into the same .cmdline
          # ukify measures (--pcr-private-key) and the db key signs puts it
          # simultaneously into PCR 11 and under the Authenticode signature.
          ${
            if rootHashFile != null
            then ''printf '%s roothash=%s' "${cmdline}" "$(cat ${rootHashFile})" > cmdline''
            else ''printf '%s' "${cmdline}" > cmdline''
          }

          # Resolve the kernel's actual vmlinuz path — the kernel
          # derivation names it with the upstream version suffix
          # (vmlinuz-6.18.12). ukify rejects glob patterns passed
          # as --linux=.
          vmlinuz=$(ls ${kernel}/boot/vmlinuz-* | head -n1)
          if [ -z "$vmlinuz" ]; then
            echo "aos-uki: no vmlinuz-* found under ${kernel}/boot/" >&2
            exit 1
          fi

          # ${signArgs} is empty unless SB signing is configured, in
          # which case ukify signs the assembled PE with sbsign.
          # ${pcrArgs} is empty unless PCR-policy signing is configured, in
          # which case ukify measures the assembled sections and writes a
          # signed PCR policy (.pcrsig/.pcrpkey) for TPM-sealed unlock.
          uki="$out/aos-${name}-${version}.efi"
          ${systemd.tools}/bin/ukify build \
            --stub=${effectiveStub} \
            --linux="$vmlinuz" \
            --initrd=${initrd}/initrd.img \
            --cmdline=@cmdline \
            --os-release=@${osRelease} \
            ${signArgs} \
            ${pcrArgs} \
            --output="$uki"

          ${
            if signing
            then ''
              # Signing success alone is not sufficient evidence that the
              # emitted PE carries the configured db identity. Verify the
              # completed UKI before publishing it to the image builder.
              ${sbsigntools}/bin/sbverify --cert ${secureBootCert} "$uki"
            ''
            else ""
          }

          ${
            if measuring
            then ''
              # Publish the stable ready-phase PCR-11 prediction beside the
              # UKI, authenticated by the same key carried in its signed
              # .pcrpkey section. The sidecar also binds the prediction to the
              # exact UKI bytes, so it cannot be replayed across slots or
              # image revisions. Runtime imports this build result; it never
              # promotes a live TPM reading into catalog authority.
              mkdir -p pcr11-sections
              measure_args=""
              for section in linux osrel cmdline initrd ucode splash dtb uname sbat pcrpkey; do
                ${binutils}/bin/objcopy -O binary --only-section=.$section \
                  "$uki" "pcr11-sections/$section" 2>/dev/null || true
                if [ -s "pcr11-sections/$section" ]; then
                  measure_args="$measure_args --$section=pcr11-sections/$section"
                fi
              done
              ${systemd}/lib/systemd/systemd-measure calculate \
                --bank=sha256 $measure_args > pcr11-calculated
              expected_pcr11=""
              while IFS= read -r line; do
                case "$line" in
                  11:sha256=*) expected_pcr11="''${line#*=}" ;;
                esac
              done < pcr11-calculated
              case "$expected_pcr11" in
                *[!0-9a-f]*|"")
                  echo "aos-uki: malformed predicted PCR 11: $expected_pcr11" >&2
                  exit 1
                  ;;
              esac
              [ "''${#expected_pcr11}" -eq 64 ] || {
                echo "aos-uki: predicted PCR 11 has the wrong length" >&2
                exit 1
              }
              uki_sha256=$(${openssl}/bin/openssl dgst -sha256 -r "$uki")
              uki_sha256=''${uki_sha256%% *}
              measurement="$out/aos-${name}-${version}.efi.measurement"
              signature="$measurement.sig"
              printf '%s\n' \
                'aos.uki-measurement/v1' \
                "uki_sha256=$uki_sha256" \
                "expected_pcr11=sha256:$expected_pcr11" \
                > "$measurement"
              ${openssl}/bin/openssl dgst -sha256 \
                -sign ${pcrPrivateKey} -out "$signature" "$measurement"
            ''
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "AOS Unified Kernel Image (sd-stub + kernel + initrd + cmdline)";
    };
  }
