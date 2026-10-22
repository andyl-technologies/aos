##! Immutable source repositories for the pinned first-party Bzlmod graph.
{
  pkgs,
  lib,
}: let
  inventory = builtins.fromJSON (builtins.readFile ../../../third_party/bazel/modules.json);
  manifestExtractor = import ./rust-helper.nix {pkgs = pkgs.buildPackages;};
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
            ${lib.optionalString (name == "rules_rust") ''
              ${pkgs.python3}/bin/python3 - ${lib.escapeShellArg "${pkgs.bash}/bin/bash"} <<'PY'
              from pathlib import Path
              import sys

              # The source-built writer embeds this interpreter in every
              # doctest runner. It must never discover a host shell at runtime.
              writer = Path("rust/private/rustdoc/rustdoc_test_writer.rs")
              source = writer.read_text()
              original = "#!/usr/bin/env bash"
              if source.count(original) != 1:
                  raise ValueError("rules_rust doctest interpreter patch no longer applies")
              writer.write_text(source.replace(original, "#!" + sys.argv[1]))

              # The bootstrap wrapper can run before rules_rust has compiled
              # its native process wrapper. Its fallback must also use an AOS
              # shell when the Nix client provides no compatibility /bin/sh.
              bootstrap = Path("util/process_wrapper/private/process_wrapper.sh")
              source = bootstrap.read_text()
              original = "#!/bin/sh\n"
              if not source.startswith(original) or source.count(original) != 1:
                  raise ValueError("rules_rust bootstrap interpreter patch no longer applies")
              bootstrap.write_text("#!" + sys.argv[1] + "\n" + source[len(original):])

              # The pinned analyzer aspect exposes OUT_DIR but omits build
              # script cfgs and rustc environment files. Export their declared
              # action outputs so the editor adapter can read the compiler's
              # actual inputs after the successful build.
              analyzer = Path("rust/private/rust_analyzer.bzl")
              source = analyzer.read_text()
              original = '    crate["cfg"] = info.cfgs\n'
              replacement = original + "\n".join([
                  '    crate["aos_rustc_env_files"] = [_EXEC_ROOT_TEMPLATE + file.path for file in info.crate.rustc_env_files]',
                  '    if info.build_info != None:',
                  '        if info.build_info.out_dir != None:',
                  '            crate["aos_out_dir"] = _EXEC_ROOT_TEMPLATE + info.build_info.out_dir.path',
                  '        if info.build_info.flags != None:',
                  '            crate["aos_build_script_flags"] = _EXEC_ROOT_TEMPLATE + info.build_info.flags.path',
                  '        if info.build_info.rustc_env != None:',
                  '            crate["aos_rustc_env_files"].append(_EXEC_ROOT_TEMPLATE + info.build_info.rustc_env.path)',
                  "",
              ])
              if source.count(original) != 1:
                  raise ValueError("rules_rust analyzer build metadata patch no longer applies")
              analyzer.write_text(source.replace(original, replacement))
              PY
              # Compile the unchanged upstream helper once in Nix, rather
              # than rebuilding its dependency graph in every empty Bazel
              # output base. This remains an explicit executable action input.
              helper=cargo/private/cargo_toml_variable_extractor
              cat > "$helper/BUILD.bazel" <<'BUILD'
              exports_files(["cargo_toml_variable_extractor"], visibility = ["//visibility:public"])
              BUILD
              cat > "$helper/cargo_toml_variable_extractor" <<'HELPER'
              #!${pkgs.bash}/bin/bash
              exec ${manifestExtractor}/bin/cargo_toml_variable_extractor "$@"
              HELPER
              chmod +x "$helper/cargo_toml_variable_extractor"
            ''}
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
