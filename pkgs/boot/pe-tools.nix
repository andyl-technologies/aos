##! Target-executable PE section inspection without the full binutils runtime.
{
  mkDerivation,
  binutils,
  fetchurl,
  buildPackages,
}:
assert builtins.elem (binutils.version or "") ["2.41" "2.41.0"];
  mkDerivation {
    pname = "pe-tools";
    version = "2.41";
    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/binutils/binutils-2.41.tar.xz"];
      hash = "sha256-rppXieI0WeWWBuZxRyPy0//DHAMXQZHvDQFb3wYAdFA=";
    };

    # Reuse the source-built target executable without changing its compiler
    # derivation. Python performs only a length-preserving installation rewrite.
    buildDeps = [buildPackages.python3];
    runtimeDeps = [];
    disallowedReferences = [binutils];
    dontStrip = true;
    # Preserve the executable's already-audited target library references. Only
    # its original binutils prefix is rewritten, then forbidden by Nix above.
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/licenses/pe-tools"
          tar -xOf "$src" binutils-2.41/COPYING3 > "$out/share/licenses/pe-tools/COPYING3"
          ${buildPackages.python3}/bin/python3 - "${binutils}" "$out" <<'PY'
          import pathlib
          import sys

          source, output = map(pathlib.Path, sys.argv[1:])
          old_prefix = str(source).encode()
          new_prefix = str(output).encode()
          if len(new_prefix) > len(old_prefix):
              raise SystemExit("PE tools output prefix exceeds the original prefix")

          # Repeated slashes preserve compiled string offsets while redirecting
          # optional plugin/debug lookups into this intentionally minimal output.
          replacement = new_prefix + b"/" * (len(old_prefix) - len(new_prefix))
          binary = (source / "bin/objcopy").read_bytes()
          installed = output / "bin/objcopy"
          installed.write_bytes(binary.replace(old_prefix, replacement))
          installed.chmod(0o755)
          PY
        '';
      }
    ];

    meta = {
      description = "GNU objcopy for runtime PE section inspection";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      mainProgram = "objcopy";
    };
  }
