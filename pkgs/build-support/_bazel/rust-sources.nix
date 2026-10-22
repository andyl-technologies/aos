##! Realizes a checked-in crate_universe family without invoking its resolver.
{
  pkgs,
  lib,
  root,
  family,
}: let
  directory = root + "/third_party/rust/${family}";
  inventory = builtins.fromJSON (builtins.readFile (directory + "/sources.json"));
  validBasename = name: builtins.match "[a-zA-Z0-9][a-zA-Z0-9._+-]*" name != null && !lib.hasInfix ".." name;
  validRelative = name: !lib.hasPrefix "/" name && builtins.all (part: !builtins.elem part ["" "." ".."]) (lib.splitString "/" name);
  valid =
    inventory.schema_version
    == 1
    && inventory.family == family
    && builtins.all (name: validRelative name && builtins.hashFile "sha256" (root + "/${name}") == inventory.contracts.${name}) (builtins.attrNames inventory.contracts)
    && builtins.all (name: validBasename name && builtins.hashFile "sha256" (directory + "/${name}") == inventory.generated_files.${name}) (builtins.attrNames inventory.generated_files);
  prepare = repository: source: let
    archive = pkgs.fetchurl {
      urls = [source.url];
      hash = source.sha256;
    };
  in
    assert validBasename source.strip_prefix && validBasename source.build_file;
      pkgs.mkDerivation {
        pname = "aos-rust-source-${source.name}";
        inherit (source) version;
        src = null;
        sharedBuildCache = false;
        buildDeps = [pkgs.python3];
        dontStrip = true;
        dontPatchELF = true;
        dontNukeRefs = true;
        phases = [
          {
            name = "install";
            script = ''
              ${pkgs.python3}/bin/python3 - ${archive} <<'PY'
              import sys
              import tarfile

              with tarfile.open(sys.argv[1]) as archive:
                  archive.extractall("unpacked", filter="data")
              PY
              mkdir -p "$out"
              cp -a unpacked/${lib.escapeShellArg source.strip_prefix}/. "$out/"
              chmod -R u+w "$out"
              cp ${directory + "/${source.build_file}"} "$out/BUILD.bazel"
              touch "$out/REPO.bazel"
              ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/source_only.py} "$out"
            '';
          }
        ];
        passthru = {
          sourceArchive = archive;
          sourceLicense = source.license;
        };
      };
in
  if valid
  then builtins.mapAttrs prepare inventory.sources
  else throw "stale Rust source inventory for ${family}; run the explicit Bazel dependency update"
