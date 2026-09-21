##! Offline PCR policy tooling without the system and service manager runtime.
{
  mkDerivation,
  buildPackages,
  stdenv,
  systemd,
  util-linux,
  openssl,
  tpm2-tss,
}: let
  version = systemd.version;
in
  mkDerivation {
    # Keep the installed prefix shorter than systemd's compiled prefix so its
    # private library paths can be redirected without changing string offsets.
    pname = "sd-pcr";
    inherit version;
    src = systemd.src;

    buildDeps = [buildPackages.python3 buildPackages.patchelf];
    runtimeDeps = [openssl tpm2-tss];
    disallowedRequisites = [systemd util-linux];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib/systemd" "$out/share/licenses/sd-pcr"
          tar -xOf "$src" systemd-${version}/LICENSE.LGPL2.1 \
            > "$out/share/licenses/sd-pcr/systemd-LGPL-2.1"
          tar -xOf ${util-linux.src} util-linux-${util-linux.version}/libblkid/COPYING \
            > "$out/share/licenses/sd-pcr/libblkid-COPYING"
          tar -xOf ${util-linux.src} util-linux-${util-linux.version}/libuuid/COPYING \
            > "$out/share/licenses/sd-pcr/libuuid-COPYING"

          tar -xOf ${util-linux.src} util-linux-${util-linux.version}/Documentation/licenses/COPYING.BSD-3-Clause \
            > "$out/share/licenses/sd-pcr/BSD-3-Clause"

          ${buildPackages.python3}/bin/python3 - "${systemd}" "${util-linux}" "$out" <<'PY'
          import pathlib
          import sys

          systemd, utilities, output = map(pathlib.Path, sys.argv[1:])
          files = [(systemd / "lib/systemd/systemd-measure", output / "bin/systemd-measure")]
          files += [(path, output / "lib/systemd" / path.name)
                    for path in (systemd / "lib/systemd").glob("libsystemd-shared-*.so")]
          files += [(path, output / "lib" / path.name)
                    for name in ("libblkid", "libuuid")
                    for path in (utilities / "lib").glob(name + ".so*")]
          files.append((systemd / "bin/systemd-tty-ask-password-agent",
                        output / "bin/systemd-tty-ask-password-agent"))
          if not any(path.name.startswith("libsystemd-shared-") for path, _ in files):
              raise SystemExit("systemd-measure support library is missing")

          for source, destination in files:
              data = source.read_bytes()
              for original in (systemd, utilities):
                  prefix = str(original).encode()
                  replacement = str(output).encode()
                  if len(replacement) > len(prefix):
                      raise SystemExit("PCR tool prefix exceeds its source prefix")
                  replacement += b"/" * (len(prefix) - len(replacement))
                  data = data.replace(prefix, replacement)
              destination.write_bytes(data)
              destination.chmod(0o755)
          PY

          # systemd loads crypto/TPM libraries dynamically, so DT_NEEDED-only
          # shrinking is insufficient. Preserve their explicit library paths.
          for executable in "$out/bin/"* "$out/lib/systemd/"* "$out/lib/"*.so*; do
            ${buildPackages.patchelf}/bin/patchelf --set-rpath \
              "$out/lib/systemd:$out/lib:${stdenv.glibc}/lib:${openssl}/lib:${tpm2-tss}/lib" \
              "$executable"
          done
        '';
      }
    ];

    passthru.evidenceSources = [systemd.src util-linux.src];
    meta = {
      description = "systemd PCR policy calculation and signing tools";
      homepage = "https://systemd.io";
      license = ["LGPL-2.1-or-later" "BSD-3-Clause"];
      mainProgram = "systemd-measure";
    };
  }
