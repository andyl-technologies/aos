##! Source-built CPython runtime repository for Bazel's rules_python toolchains.
{buildPackages}: let
  version = "3.11.10";
  interpreter = buildPackages.python3-3_12.overrideAttrs (original: {
    pname = "bazel-python-runtime-interpreter";
    inherit version;
    src = buildPackages.fetchurl {
      urls = ["https://www.python.org/ftp/python/${version}/Python-${version}.tar.xz"];
      hash = "sha256-B6Q1bpEpAOYaFcsJSaBsSgUBLiE+zWtOhND2equ+43I=";
    };
    # Keep the complete AOS bootstrap interpreter's dependencies and phases.
    # The pinned rules_python module resolves Python 3.11 to this exact patch.
    phases = map (phase:
      phase
      // {
        script =
          builtins.replaceStrings
          ["3.12.9" "python3.12" "${./python/python3-3_12-openssl4.patch}"]
          [version "python3.11" "${./_bazel-python311-openssl4.patch}"]
          phase.script;
      })
    original.phases;
    meta = original.meta // {description = "Source-built Python runtime for Bazel toolchains";};
  });
in
  buildPackages.mkDerivation {
    pname = "bazel-python-runtime-repository";
    inherit version;
    buildDeps = [buildPackages.coreutils];
    runtimeDeps = [interpreter];
    passthru = {inherit interpreter;};

    phases = [
      {
        name = "install";
        script = ''
          # CPython can finish installation despite a missing optional module.
          # Require the full bootstrap extension set before exposing the runtime.
          ${interpreter}/bin/python3 - <<'PY'
          import bz2
          import ctypes
          import curses
          import hashlib
          import jinja2
          import lzma
          import readline
          import sqlite3
          import ssl
          import zlib

          assert ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).minimum_version >= ssl.TLSVersion.TLSv1_2
          PY
          mkdir -p "$out"
          cp -R ${interpreter}/. "$out/"
          chmod -R u+w "$out"
          ln -sf bin/python3 "$out/python"
          cat > "$out/BUILD.bazel" <<'BUILD'
          load("@rules_python//python/private:hermetic_runtime_repo_setup.bzl", "define_hermetic_runtime_toolchain_impl")

          package(default_visibility = ["//visibility:public"])

          define_hermetic_runtime_toolchain_impl(
              name = "define_runtime",
              extra_files_glob_include = ["lib/**"],
              extra_files_glob_exclude = ["**/__pycache__/*.pyc", "**/__pycache__/*.pyo"],
              python_version = "${version}",
              python_bin = "bin/python3",
              coverage_tool = None,
          )
          BUILD
          printf '%s\n' 'workspace(name = "aos_python_runtime")' > "$out/WORKSPACE.bazel"
        '';
      }
    ];
  }
