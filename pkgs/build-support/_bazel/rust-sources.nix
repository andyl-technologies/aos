##! Realizes a checked-in crate_universe family without invoking its resolver.
{
  pkgs,
  lib,
  root,
  family,
  sourcePatchPolicyFile ? root + "/third_party/rust/source-patches.json",
}: let
  directory = root + "/third_party/rust/${family}";
  # The lock records historical generator store paths as provenance. When read
  # from a corresponding-source output, Nix attaches those references to the
  # text, which fromJSON rejects. They are not build dependencies: the current
  # toolchain comes from pkgs and each source/build file is declared below.
  inventory = builtins.fromJSON (builtins.unsafeDiscardStringContext (
    builtins.readFile (directory + "/sources.json")
  ));
  sourcePatchPolicy = builtins.fromJSON (builtins.readFile sourcePatchPolicyFile);
  validBasename = name: builtins.match "[a-zA-Z0-9][a-zA-Z0-9._+-]*" name != null && !lib.hasInfix ".." name;
  validRelative = name: !lib.hasPrefix "/" name && builtins.all (part: !builtins.elem part ["" "." ".."]) (lib.splitString "/" name);
  valid =
    inventory.schema_version
    == 1
    && inventory.family == family
    && builtins.all (name: validRelative name && builtins.hashFile "sha256" (root + "/${name}") == inventory.contracts.${name}) (builtins.attrNames inventory.contracts)
    && builtins.all (name: validBasename name && builtins.hashFile "sha256" (directory + "/${name}") == inventory.generated_files.${name}) (builtins.attrNames inventory.generated_files);
  prepare = repository: source: let
    versions = sourcePatchPolicy.packages.${source.name} or null;
    policy =
      if versions == null
      then null
      else versions.${source.version} or (throw "unreviewed Rust source patch policy: ${source.name}-${source.version}");
    patches =
      if policy == null
      then []
      else policy.patches;
    validPatch = patch:
      validRelative patch.path
      && builtins.match "[A-Za-z0-9/._+-]+" patch.path != null
      && lib.hasPrefix "third_party/rust/patches/" patch.path
      && lib.hasSuffix ".patch" patch.path
      && patch.strip == 1
      && builtins.hashFile "sha256" (root + "/${patch.path}") == patch.sha256;
    patchNames = map (patch: baseNameOf patch.path) patches;
    validPolicy =
      policy
      == null
      || (policy.archive_sha256
        == source.sha256
        && builtins.all validPatch patches
        && builtins.length patchNames == builtins.length (lib.unique patchNames));
    appliedPatches =
      map (patch: {
        inherit (patch) sha256 strip;
        origin = patch.path;
        path = baseNameOf patch.path;
      })
      patches;
    # Upstream compile_data globs cover the entire source repository. Retain
    # patch provenance separately so audit files do not become compiler inputs.
    patchScript = lib.optionalString (patches != []) (
      "mkdir -p \"$patches\"\n"
      + lib.concatMapStringsSep "\n" (patch: ''
        patch --forward --batch --fuzz=0 -p${toString patch.strip} -d "$out" < ${root + "/${patch.path}"}
        cp ${root + "/${patch.path}"} "$patches/${baseNameOf patch.path}"
      '')
      patches
      + ''
        cat > "$patches/manifest.json" <<'JSON'
        ${builtins.toJSON {
          schema_version = 1;
          package = source.name;
          version = source.version;
          archive_sha256 = source.sha256;
          patches = appliedPatches;
        }}
        JSON
      ''
    );
    archive = pkgs.fetchurl {
      urls = [source.url];
      hash = source.sha256;
    };
  in
    assert validBasename source.strip_prefix && validBasename source.build_file;
    assert validPolicy;
      pkgs.mkDerivation ({
          pname = "aos-rust-source-${source.name}";
          inherit (source) version;
          src = null;
          sharedBuildCache = false;
          buildDeps = [pkgs.python3] ++ lib.optionals (patches != []) [pkgs.patch];
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
                ${patchScript}cp ${directory + "/${source.build_file}"} "$out/BUILD.bazel"
                touch "$out/REPO.bazel"
                ${pkgs.python3}/bin/python3 ${../../../tools/bazel/metadata/source_only.py} "$out"
              '';
            }
          ];
          passthru = {
            sourceArchive = archive;
            sourceLicense = source.license;
            sourcePatches = appliedPatches;
          };
        }
        // lib.optionalAttrs (patches != []) {outputs = ["out" "patches"];});
in
  if valid && sourcePatchPolicy.schema_version == 1
  then builtins.mapAttrs prepare inventory.sources
  else throw "stale Rust source inventory for ${family}; run the explicit Bazel dependency update"
