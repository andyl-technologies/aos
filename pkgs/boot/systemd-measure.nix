##! Offline PCR policy tooling without the system and service manager runtime.
{
  lib,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    # Keep the installed prefix shorter than systemd's compiled prefix so its
    # private library paths can be redirected without changing string offsets.
    pname = "sd-pcr";
    inherit version;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A fixed kernel payload with a known SHA-256 PCR-11 policy.";
        operation = "Calculate the boot phase measurements without a TPM device.";
        expected = "The ready-phase PCR equals the independently recorded policy.";
        files."kernel.bin" = "AOS PCR qualification kernel\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess

                result = subprocess.run([
                    "@out@/bin/systemd-measure", "calculate", "--bank=sha256",
                    "--linux=kernel.bin",
                ], check=True, capture_output=True, text=True)
                assert result.stdout.splitlines()[-1] == (
                    "11:sha256=409e5c39ec8c4f4e77ff36cdb794fafb"
                    "304dbb3f6ee3e3bc4c0535ce2b781c84"
                )
                print("PCR-11 known-answer calculation passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "PCR-11 known-answer calculation passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unsupported PCR bank name.";
        operation = "Attempt to calculate the policy with an invalid bank.";
        expected = "The tool rejects the unsupported digest algorithm.";
        files."kernel.bin" = "AOS PCR qualification kernel\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess
                import sys

                result = subprocess.run([
                    "@out@/bin/systemd-measure", "calculate", "--bank=invalid-bank",
                    "--linux=kernel.bin",
                ], capture_output=True)
                assert result.returncode != 0
                assert b"invalid-bank" in result.stderr
                sys.stderr.write("PCR tool rejected invalid bank\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "PCR tool rejected invalid bank\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
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
