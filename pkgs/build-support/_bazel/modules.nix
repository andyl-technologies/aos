##! Immutable source repositories for the pinned first-party Bzlmod graph.
{
  pkgs,
  lib,
}: let
  inventory = builtins.fromJSON (builtins.readFile ../../../third_party/bazel/modules.json);
  prepare = name: entry: let
    source = entry.source;
    archive = pkgs.fetchurl {
      urls = [source.url];
      hash = source.integrity;
    };
    moduleFile = pkgs.fetchurl {
      urls = ["${entry.registry}/MODULE.bazel"];
      hash = entry.module_sha256;
    };
    patches = builtins.mapAttrs (filename: hash:
      pkgs.fetchurl {
        urls = ["${entry.registry}/patches/${filename}"];
        inherit hash;
      }) (source.patches or {});
    prefix = source.strip_prefix or "";
    patchScript = lib.concatStringsSep "\n" (map
      (filename: "patch -p${toString (source.patch_strip or 0)} < ${patches.${filename}}")
      (builtins.attrNames patches));
  in
    pkgs.mkDerivation {
      pname = "aos-bazel-module-${name}";
      inherit (entry) version;
      src = null;
      buildDeps = [pkgs.patch pkgs.python3];
      sharedBuildCache = false;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            ${pkgs.python3}/bin/python3 - ${archive} <<'PY'
            from pathlib import Path
            import sys
            import tarfile
            import zipfile

            destination = Path("unpacked")
            destination.mkdir()
            if zipfile.is_zipfile(sys.argv[1]):
                with zipfile.ZipFile(sys.argv[1]) as archive:
                    archive.extractall(destination)
                    for entry in archive.infolist():
                        mode = (entry.external_attr >> 16) & 0o777
                        if mode:
                            (destination / entry.filename).chmod(mode)
            else:
                with tarfile.open(sys.argv[1]) as archive:
                    archive.extractall(destination, filter="data")
            PY
            mkdir -p "$out"
            cp -a unpacked/${lib.escapeShellArg prefix}/. "$out/"
            chmod -R u+w "$out"
            cd "$out"
            ${patchScript}
            cp ${moduleFile} MODULE.bazel
            ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/source_only.py} "$out"
          '';
        }
      ];
      passthru.sourceArchive = archive;
    };
in
  assert inventory.schema == 1;
  assert inventory.workspace_module_sha256 == builtins.hashFile "sha256" ../../../MODULE.bazel;
  assert inventory.module_lock_sha256 == builtins.hashFile "sha256" ../../../MODULE.bazel.lock;
    builtins.mapAttrs prepare inventory.modules
