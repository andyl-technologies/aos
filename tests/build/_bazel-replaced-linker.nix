##! Replaces the selected linker while retaining the AOS compiler's flags.
{pkgs}: let
  binutils = pkgs.runCommand "aos-bazel-replaced-linker" {dontNukeRefs = true;} ''
    mkdir -p "$out/bin"
    for tool in ${pkgs.binutils}/bin/*; do
      ln -s "$tool" "$out/bin/''${tool##*/}"
    done
    rm "$out/bin/ld"
    cat > "$out/bin/ld" <<'LINKER'
    #!${pkgs.bash}/bin/bash
    printf '%s\n' 'AOS_BAZEL_REPLACED_LINKER_EXECUTED' >&2
    exec ${pkgs.binutils}/bin/ld "$@"
    LINKER
    chmod +x "$out/bin/ld"
  '';
  cc =
    pkgs.runCommand "aos-bazel-linker-selection-wrapper" {
      buildDeps = [pkgs.python3];
      dontNukeRefs = true;
    } ''
      mkdir -p "$out/bin"
      ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
      from pathlib import Path
      import sys

      output = Path(sys.argv[1]) / "bin"
      for name in ["cc", "c++"]:
          source = Path("${pkgs.cc}/bin") / name
          text = source.read_text()
          original = "-B${pkgs.binutils}/bin/"
          if text.count(original) != 1:
              raise ValueError("AOS compiler wrapper no longer selects one explicit binutils prefix")
          target = output / name
          target.write_text(text.replace(original, "-B${binutils}/bin/"))
          target.chmod(0o755)
      PYTHON
    '';
in {inherit binutils cc;}
