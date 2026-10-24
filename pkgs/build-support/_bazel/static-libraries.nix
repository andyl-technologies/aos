##! Adds declared static libc/unwinder inputs to a native-library repository.
{
  pkgs,
  lib,
}: {libraries}: let
  platform = pkgs.stdenv.hostPlatform;
  imports = pkgs.mkAosBazelNativeLibraries {inherit libraries;};
  glibc = pkgs.stdenv.glibc;
  gcc = pkgs.stdenv.gcc;
  cc = pkgs.stdenv.cc;
in
  assert !pkgs.stdenv.isCross && platform.isLinux;
  assert builtins.all (variant: variant.linkage or "shared" == "static") (builtins.attrValues libraries);
    pkgs.mkDerivation {
      pname = "aos-bazel-static-libraries";
      version = "1";
      src = null;
      sharedBuildCache = false;
      buildDeps = [pkgs.python3];
      outputChecks.out = {};
      exportReferencesGraph.runtime = [glibc glibc.static gcc imports];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/static/lib"
            for entry in ${imports}/*; do
              name="''${entry##*/}"
              case "$name" in
                BUILD.bazel|nix-support) ;;
                *) ln -s "$entry" "$out/$name" ;;
              esac
            done
            cp ${imports}/BUILD.bazel "$out/BUILD.bazel"
            chmod u+w "$out/BUILD.bazel"
            for archive in ${glibc.static}/lib/*.a; do
              ln -s "$archive" "$out/static/lib/''${archive##*/}"
            done

            # GCC's shared-runtime build installs the unwinder as libgcc_s.a.
            # Rust's crt-static link requests that same archive as libgcc_eh.a.
            unwinder="$(dirname "$(${cc}/bin/cc -print-libgcc-file-name)")/libgcc_s.a"
            test -f "$unwinder"
            ln -s "$unwinder" "$out/static/lib/libgcc_eh.a"

            # Split glibc outputs retain the original libm member paths. Rebase
            # this link-only script without changing the compiler or sysroot.
            rm "$out/static/lib/libm.a"
            sed 's|${builtins.storeDir}/[^ /]*/lib/|${glibc.static}/lib/|g' \
              ${glibc.static}/lib/libm.a > "$out/static/lib/libm.a"
            ${pkgs.python3}/bin/python3 - "$out" "$unwinder" <<'PYTHON'
            import json
            import os
            from pathlib import Path
            import sys

            output, unwinder = Path(sys.argv[1]), Path(sys.argv[2])
            graph = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())["runtime"]
            report = {
                "schema_version": 1,
                "target": "${platform.config}",
                "glibc": "${glibc}",
                "glibc_static": "${glibc.static}",
                "unwinder": str(unwinder),
                "closure": sorted(({"path": entry["path"], "narHash": entry["narHash"]} for entry in graph), key=lambda entry: entry["path"]),
            }
            (output / "static/closure.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            PYTHON
            cat >> "$out/BUILD.bazel" <<BUILD

            # Consumers opt in to static linkage. Execution-platform tools keep
            # the ordinary dynamic toolchain and never depend on this provider.
            cc_library(
                name = "static_runtime",
                additional_linker_inputs = ["static/closure.json"] + glob(["static/lib/*.a"]),
                linkopts = ["-L$out/static/lib", "-static", "-no-pie"],
                tags = ["aos-license:apache-host"],
                target_compatible_with = ["@platforms//cpu:${
              if platform.isx86_64
              then "x86_64"
              else "aarch64"
            }", "@platforms//os:linux"],
            )
            BUILD
          '';
        }
      ];
    }
