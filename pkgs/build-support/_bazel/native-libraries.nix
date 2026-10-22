##! Imports selected AOS native-library variants without changing compiler identity.
{
  pkgs,
  lib,
}: {
  libraries,
  platform ? pkgs.stdenv.hostPlatform,
}: let
  validRelativePath = path:
    builtins.isString path
    && path != ""
    && builtins.match "[A-Za-z0-9_.+/-]+" path != null
    && !lib.hasPrefix "/" path
    && builtins.all (part: !builtins.elem part ["" "." ".."]) (lib.splitString "/" path);
  variants = lib.mapAttrs (name: specification: let
    variant =
      {
        linkage = "shared";
        headerPackage = specification.package.dev or specification.package;
        headerDirectory = "include";
        linkopts = [];
        licenseDomain = "apache-host";
      }
      // specification;
  in
    assert builtins.match "[a-z][a-z0-9_]*" name != null;
    assert builtins.elem variant.linkage ["shared" "static"];
    assert builtins.elem variant.licenseDomain ["apache-host" "permissive-protocol" "gpl-qemu"];
    assert variant.package.targetSystem == platform.system;
    assert variant.headerPackage.targetSystem == platform.system;
    assert validRelativePath variant.headerDirectory && validRelativePath variant.libraryFile; variant)
  libraries;
  constraints = [
    "@platforms//cpu:${
      if platform.isx86_64
      then "x86_64"
      else "aarch64"
    }"
    "@platforms//os:linux"
  ];
  buildFile =
    ''
      load("@rules_cc//cc:defs.bzl", "cc_import", "cc_library")

      package(default_visibility = ["//visibility:public"])
    ''
    + lib.concatStringsSep "\n" (lib.mapAttrsToList (name: variant: let
        library = "${name}/lib/${baseNameOf variant.libraryFile}";
        flags = variant.linkopts ++ lib.optional (variant.linkage == "shared") "-Wl,-rpath,${variant.package}/${dirOf variant.libraryFile}";
        tags = ["aos-license:${variant.licenseDomain}"];
        libraryAttribute =
          if variant.linkage == "shared"
          then "shared_library"
          else "static_library";
      in ''
        cc_import(
            name = "${name}_import",
            hdrs = glob(["${name}/include/**"]),
            ${libraryAttribute} = ${builtins.toJSON library},
            tags = ${builtins.toJSON tags},
            target_compatible_with = ${builtins.toJSON constraints},
        )

        cc_library(
            name = "${name}",
            deps = [":${name}_import"],
            includes = ["${name}/include"],
            additional_linker_inputs = ["${name}/closure.json"],
            linkopts = ${builtins.toJSON flags},
            tags = ${builtins.toJSON tags},
            target_compatible_with = ${builtins.toJSON constraints},
        )

        filegroup(
            name = "${name}_files",
            srcs = [${builtins.toJSON library}, "${name}/closure.json"] + glob(["${name}/include/**"]),
            tags = ${builtins.toJSON tags},
            target_compatible_with = ${builtins.toJSON constraints},
        )
      '')
      variants);
  identities =
    lib.mapAttrs (_: variant: {
      inherit (variant) linkage libraryFile headerDirectory linkopts licenseDomain;
      package = toString variant.package;
      headerPackage = toString variant.headerPackage;
      target = platform.config;
    })
    variants;
in
  assert platform.isLinux && (platform.isx86_64 || platform.isAarch64);
    pkgs.mkDerivation {
      pname = "aos-bazel-native-libraries";
      version = "1";
      src = null;
      sharedBuildCache = false;
      outputChecks.out = {};
      buildDeps = [pkgs.python3];
      exportReferencesGraph = lib.mapAttrs (_: variant: [variant.package variant.headerPackage]) variants;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: variant: ''
                test -d ${lib.escapeShellArg "${variant.headerPackage}/${variant.headerDirectory}"}
                test -f ${lib.escapeShellArg "${variant.package}/${variant.libraryFile}"}
                mkdir -p "$out/${name}/lib"
                ln -s ${lib.escapeShellArg "${variant.headerPackage}/${variant.headerDirectory}"} "$out/${name}/include"
                ln -s ${lib.escapeShellArg "${variant.package}/${variant.libraryFile}"} "$out/${name}/lib/${baseNameOf variant.libraryFile}"
              '')
              variants)}
            cat > variants.json <<'JSON'
            ${builtins.toJSON identities}
            JSON
            ${pkgs.python3}/bin/python3 - variants.json "$out" <<'PYTHON'
            import json
            import os
            from pathlib import Path
            import sys

            variants = json.loads(Path(sys.argv[1]).read_text())
            closures = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())
            for name, variant in variants.items():
                # Keep only runtime references when the exported graph also
                # contains build inputs alongside the requested roots.
                by_path = {item["path"]: item for item in closures[name]}
                pending = [variant["package"], variant["headerPackage"]]
                selected = set()
                while pending:
                    path = pending.pop()
                    if path in selected:
                        continue
                    selected.add(path)
                    pending.extend(by_path[path]["references"])
                variant["schema_version"] = 1
                variant["closure"] = sorted(
                    ({"path": path, "narHash": by_path[path]["narHash"]} for path in selected),
                    key=lambda item: item["path"],
                )
                (Path(sys.argv[2]) / name / "closure.json").write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n")
            PYTHON
            cat > "$out/BUILD.bazel" <<'BUILD'
            ${buildFile}
            BUILD
            touch "$out/REPO.bazel"
          '';
        }
      ];
    }
