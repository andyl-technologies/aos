##! Imports selected AOS native-library variants without changing compiler identity.
{
  pkgs,
  lib,
}: {
  libraries,
  platform ? pkgs.stdenv.hostPlatform,
}: let
  buildPkgs = pkgs.buildPackages;
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
        pkgConfigFiles = [];
        # Shared-library queries can still need private dependencies' headers.
        pkgConfigDependencies = [];
        compilerResponseFile = false;
      }
      // specification;
  in
    assert builtins.match "[a-z][a-z0-9_]*" name != null;
    assert builtins.elem variant.linkage ["shared" "static"];
    assert builtins.isBool variant.compilerResponseFile;
    assert builtins.elem variant.licenseDomain ["apache-host" "permissive-protocol" "gpl-qemu"];
    assert variant.package.targetSystem == platform.system;
    assert variant.headerPackage.targetSystem == platform.system;
    assert builtins.all (path: validRelativePath path && lib.hasSuffix ".pc" path) variant.pkgConfigFiles;
    assert variant.pkgConfigDependencies == [] || variant.pkgConfigFiles != [];
    assert builtins.all (dependency:
      builtins.hasAttr dependency libraries
      && dependency != name
      && (libraries.${dependency}.pkgConfigFiles or []) != [])
    variant.pkgConfigDependencies;
    assert builtins.length variant.pkgConfigDependencies == builtins.length (lib.unique variant.pkgConfigDependencies);
    assert builtins.length variant.pkgConfigFiles == builtins.length (lib.unique (map baseNameOf variant.pkgConfigFiles));
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
    in
      ''
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
            srcs = [${builtins.toJSON library}, "${name}/closure.json"] + glob(["${name}/include/**", "${name}/pkgconfig/*.pc"], allow_empty = True),
            tags = ${builtins.toJSON tags},
            target_compatible_with = ${builtins.toJSON constraints},
        )
      ''
      + lib.optionalString variant.compilerResponseFile ''
        exports_files(["${name}/cflags"], visibility = ["//visibility:public"])
      ''
      + lib.optionalString (variant.pkgConfigFiles != []) ''
        exports_files(["${name}/pkg-config"])

        # This tool executes natively while inspecting target-library metadata.
        filegroup(
            name = "${name}_pkg_config_tools",
            srcs = ["${name}/pkg-config", "${name}/pkg-config-tools.json"],
            tags = ${builtins.toJSON tags},
        )
      '')
    variants);
  needsPkgConfig = builtins.any (variant: variant.pkgConfigFiles != []) (builtins.attrValues variants);
  toolRoots = lib.optionals needsPkgConfig [buildPkgs.pkg-config buildPkgs.bash];
  identities = lib.mapAttrs (_: variant:
    {
      inherit (variant) linkage libraryFile headerDirectory linkopts licenseDomain pkgConfigFiles;
      package = toString variant.package;
      headerPackage = toString variant.headerPackage;
      target = platform.config;
    }
    // lib.optionalAttrs variant.compilerResponseFile {inherit (variant) compilerResponseFile;}
    // lib.optionalAttrs (variant.pkgConfigDependencies != []) {inherit (variant) pkgConfigDependencies;})
  variants;
in
  assert platform.isLinux && (platform.isx86_64 || platform.isAarch64);
    pkgs.mkDerivation {
      pname = "aos-bazel-native-libraries";
      version = "1";
      src = null;
      sharedBuildCache = false;
      outputChecks.out = {};
      buildDeps = [buildPkgs.python3];
      exportReferencesGraph =
        lib.mapAttrs (_: variant: [variant.package variant.headerPackage]) variants
        // lib.optionalAttrs needsPkgConfig {__pkg_config_tools = toolRoots;};
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: variant:
              ''
                test -d ${lib.escapeShellArg "${variant.headerPackage}/${variant.headerDirectory}"}
                test -f ${lib.escapeShellArg "${variant.package}/${variant.libraryFile}"}
                mkdir -p "$out/${name}/lib"
                ln -s ${lib.escapeShellArg "${variant.headerPackage}/${variant.headerDirectory}"} "$out/${name}/include"
                ln -s ${lib.escapeShellArg "${variant.package}/${variant.libraryFile}"} "$out/${name}/lib/${baseNameOf variant.libraryFile}"
              ''
              + lib.optionalString variant.compilerResponseFile ''
                # C probes also link before deciding whether to use a bundled
                # fallback. Supply both searches through declared response data.
                printf '%s\n' \
                  ${lib.escapeShellArg "-I${variant.headerPackage}/${variant.headerDirectory}"} \
                  ${lib.escapeShellArg "-L${variant.package}/${dirOf variant.libraryFile}"} > "$out/${name}/cflags"
              ''
              + lib.optionalString (variant.pkgConfigFiles != []) ''
                mkdir -p "$out/${name}/pkgconfig"
                ${lib.concatMapStringsSep "\n" (file: ''
                    test -f ${lib.escapeShellArg "${variant.package}/${file}"}
                    ln -s ${lib.escapeShellArg "${variant.package}/${file}"} "$out/${name}/pkgconfig/${baseNameOf file}"
                  '')
                  variant.pkgConfigFiles}
                cat > "$out/${name}/pkg-config" <<PKG_CONFIG
                #!${buildPkgs.bash}/bin/bash
                set -euo pipefail
                unset PKG_CONFIG_PATH PKG_CONFIG_TOP_BUILD_DIR PKG_CONFIG_SYSROOT_DIR
                export PKG_CONFIG_LIBDIR="${lib.concatStringsSep ":" (map (dependency: "$out/${dependency}/pkgconfig") ([name] ++ variant.pkgConfigDependencies))}"
                export PKG_CONFIG_SYSTEM_INCLUDE_PATH= PKG_CONFIG_SYSTEM_LIBRARY_PATH=
                exec ${buildPkgs.pkg-config}/bin/pkg-config "\$@"
                PKG_CONFIG
                chmod +x "$out/${name}/pkg-config"
              '')
            variants)}
            cat > variants.json <<'JSON'
            ${builtins.toJSON {
              libraries = identities;
              tools = map toString toolRoots;
            }}
            JSON
            ${buildPkgs.python3}/bin/python3 - variants.json "$out" <<'PYTHON'
            import json
            import os
            from pathlib import Path
            import sys

            configuration = json.loads(Path(sys.argv[1]).read_text())
            variants = configuration["libraries"]
            closures = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())

            def realized(roots, graph):
                # Keep only runtime references when the exported graph also
                # contains build inputs alongside the requested roots.
                by_path = {item["path"]: item for item in closures[graph]}
                pending = list(roots)
                selected = set()
                while pending:
                    path = pending.pop()
                    if path in selected:
                        continue
                    selected.add(path)
                    pending.extend(by_path[path]["references"])
                return sorted(
                    ({"path": path, "narHash": by_path[path]["narHash"]} for path in selected),
                    key=lambda item: item["path"],
                )

            for name, variant in variants.items():
                variant["schema_version"] = 1
                variant["closure"] = realized([variant["package"], variant["headerPackage"]], name)
                (Path(sys.argv[2]) / name / "closure.json").write_text(json.dumps(variant, indent=2, sort_keys=True) + "\n")
                if variant["pkgConfigFiles"]:
                    tools = {"schema_version": 1, "closure": realized(configuration["tools"], "__pkg_config_tools")}
                    (Path(sys.argv[2]) / name / "pkg-config-tools.json").write_text(json.dumps(tools, indent=2, sort_keys=True) + "\n")
            PYTHON
            cat > "$out/BUILD.bazel" <<'BUILD'
            ${buildFile}
            BUILD
            touch "$out/REPO.bazel"
          '';
        }
      ];
    }
