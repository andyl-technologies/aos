##! Source-only inputs needed to compile the language rules' own helpers.
{
  pkgs,
  lib,
  modules,
}: let
  inventory = builtins.fromJSON (builtins.readFile ../../../third_party/bazel/rule-inputs.json);
  prepare = name: input: let
    archive = pkgs.fetchurl {
      urls = [input.url];
      hash = input.sha256;
    };
  in
    pkgs.mkDerivation {
      pname = "aos-bazel-rule-input";
      version = "1";
      src = null;
      buildDeps = [pkgs.tar pkgs.gzip pkgs.python3];
      sharedBuildCache = false;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir unpacked
            tar xf ${archive} -C unpacked
            mkdir -p "$out"
            cp -a unpacked/${lib.escapeShellArg input.strip_prefix}/. "$out/"
            chmod -R u+w "$out"
            cp ${modules.${input.build_module}}/${input.build_file} "$out/BUILD.bazel"
            touch "$out/REPO.bazel"
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/source_only.py} "$out"
          '';
        }
      ];
    };
in
  assert inventory.schema == 1;
    builtins.mapAttrs prepare inventory.repositories
