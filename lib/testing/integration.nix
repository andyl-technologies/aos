# lib/testing/integration.nix — Higher-level integration test wrappers
#
# Provides convenience functions built on top of mkFirecrackerTest for
# common integration test patterns:
#
#   mkLinkCheck    — Compile, link, and run a C program against a library
#   mkToolCheck    — Run a CLI tool and optionally verify output
#   mkCompileCheck — Compile-only (no run) to verify headers/linkage
#
# All tests run in headless Firecracker microVMs with no systemd and
# no agent. The test script IS the init process (PID 1).
{
  pkgs,
  lib,
  mkFirecrackerTest,
}: let
  bootstrapTools = pkgs.bootstrapTools;

  # Helper: build colon-separated paths for C_INCLUDE_PATH, LIBRARY_PATH,
  # and LD_LIBRARY_PATH from a list of packages.
  # Automatically includes bootstrap tools' glibc headers and libraries
  # so that the raw gcc from bootstrap tools can find standard headers.
  makeIncludePath = deps:
    builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in ["${base}/include"]
      )
      deps
      ++ ["${builtins.toString bootstrapTools}/include-glibc"]
    );

  makeLibraryPath = deps:
    builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in ["${base}/lib"]
      )
      deps
      ++ ["${builtins.toString bootstrapTools}/lib"]
    );

  # -------------------------------------------------------------------------
  # mkLinkCheck — Compile + link + run a C program against a library
  # -------------------------------------------------------------------------
  mkLinkCheck = {
    pname,
    library,
    testSource,
    includes ? [],
    libs ? [],
    extraDeps ? [],
  }: let
    allLibDeps = [library] ++ extraDeps;
    includeFlags = builtins.concatStringsSep " " (builtins.map (i: "-I${i}") includes);
    libFlags = builtins.concatStringsSep " " libs;
    includePath = makeIncludePath allLibDeps;
    libraryPath = makeLibraryPath allLibDeps;
  in
    mkFirecrackerTest {
      inherit pname;
      rootfsDeps = allLibDeps;
      testScript = ''
                export C_INCLUDE_PATH="${includePath}:$C_INCLUDE_PATH"
                export LIBRARY_PATH="${libraryPath}:$LIBRARY_PATH"
                export LD_LIBRARY_PATH="${libraryPath}:$LD_LIBRARY_PATH"

                cat > /tmp/test.c << 'TESTSRC'
        ${testSource}
        TESTSRC

                echo "==> Compiling test program"
                gcc -o /tmp/test /tmp/test.c ${includeFlags} ${libFlags}
                echo "==> Running test program"
                /tmp/test
                echo "==> Test program exited successfully"
      '';
    };

  # -------------------------------------------------------------------------
  # mkToolCheck — Run a CLI tool and optionally verify output
  # -------------------------------------------------------------------------
  mkToolCheck = {
    pname,
    tool,
    command,
    expectedOutput ? null,
    extraDeps ? [],
  }: let
    allDeps = [tool] ++ extraDeps;
    checkOutput =
      if expectedOutput != null
      then ''
        ACTUAL=$(cat /tmp/tool-output)
        EXPECTED="${expectedOutput}"
        if [ "$ACTUAL" != "$EXPECTED" ]; then
          printf 'Expected: %s\n' "$EXPECTED" >&2
          printf 'Actual:   %s\n' "$ACTUAL" >&2
          exit 1
        fi
        echo "==> Output matches expected value"
      ''
      else "";
  in
    mkFirecrackerTest {
      inherit pname;
      rootfsDeps = allDeps;
      testScript = ''
        echo "==> Running tool check"
        ${command} > /tmp/tool-output 2>&1
        echo "==> Command exited successfully"
        cat /tmp/tool-output
        ${checkOutput}
      '';
    };

  # -------------------------------------------------------------------------
  # mkCompileCheck — Compile-only (no run) to verify headers/linkage
  # -------------------------------------------------------------------------
  mkCompileCheck = {
    pname,
    deps,
    testSource,
    flags ? "",
  }: let
    includePath = makeIncludePath deps;
    libraryPath = makeLibraryPath deps;
  in
    mkFirecrackerTest {
      inherit pname;
      rootfsDeps = deps;
      testScript = ''
                export C_INCLUDE_PATH="${includePath}:$C_INCLUDE_PATH"
                export LIBRARY_PATH="${libraryPath}:$LIBRARY_PATH"

                cat > /tmp/test.c << 'TESTSRC'
        ${testSource}
        TESTSRC

                echo "==> Compiling test program (compile-only)"
                gcc -o /tmp/test /tmp/test.c ${flags}
                echo "==> Compilation succeeded"
      '';
    };

  # -------------------------------------------------------------------------
  # mkCxxCompileCheck — Compile + run a C++ program (for header-only libs)
  # -------------------------------------------------------------------------
  mkCxxCompileCheck = {
    pname,
    deps,
    testSource,
    flags ? "-std=c++17",
  }: let
    includePath = makeIncludePath deps;
    libraryPath = makeLibraryPath deps;
  in
    mkFirecrackerTest {
      inherit pname;
      rootfsDeps = deps;
      testScript = ''
                export C_INCLUDE_PATH="${includePath}:$C_INCLUDE_PATH"
                export CPLUS_INCLUDE_PATH="${includePath}:$CPLUS_INCLUDE_PATH"
                export LIBRARY_PATH="${libraryPath}:$LIBRARY_PATH"
                export LD_LIBRARY_PATH="${libraryPath}:$LD_LIBRARY_PATH"

                cat > /tmp/test.cpp << 'TESTSRC'
        ${testSource}
        TESTSRC

                echo "==> Compiling C++ test program"
                g++ ${flags} -o /tmp/test /tmp/test.cpp
                echo "==> Running test program"
                /tmp/test
                echo "==> Test program exited successfully"
      '';
    };
in {
  inherit
    mkLinkCheck
    mkToolCheck
    mkCompileCheck
    mkCxxCompileCheck
    ;
}
