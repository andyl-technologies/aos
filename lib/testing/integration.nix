# lib/testing/integration.nix — Higher-level integration test wrappers
#
# Provides convenience functions built on top of mkVMTest (headless mode)
# for common integration test patterns:
#
#   mkLinkCheck       — Compile, link, and run a C program against a library
#   mkToolCheck       — Run a CLI tool and optionally verify output
#   mkCompileCheck    — Compile-only (no run) to verify headers/linkage
#   mkSONAMECheck     — Verify SONAME exists on shared libraries
#   mkRPATHCheck      — Verify RPATH entries point to valid dirs
#   mkSymbolCheck     — Verify symbols are exported from a shared library
#   mkVersionCheck    — Compare header version macros to runtime version
#   mkDynLinkerCheck  — Verify ELF interpreter exists
#
# All tests run in headless microVMs with no systemd and no agent.
# The test script IS the init process (PID 1).
{
  pkgs,
  lib,
  mkVMTest,
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
    mkVMTest {
      name = pname;
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
    mkVMTest {
      name = pname;
      rootfsDeps = allDeps;
      testScript = ''
        echo "==> Running tool check"
        if ! ( ${command} ) > /tmp/tool-output 2>&1; then
          cat /tmp/tool-output
          exit 1
        fi
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
    mkVMTest {
      name = pname;
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
    mkVMTest {
      name = pname;
      rootfsDeps = [pkgs.gcc] ++ deps;
      memory = 512;
      testScript = ''
                export C_INCLUDE_PATH="${includePath}:$C_INCLUDE_PATH"
                export CPLUS_INCLUDE_PATH="${includePath}:$CPLUS_INCLUDE_PATH"
                export LIBRARY_PATH="${libraryPath}:$LIBRARY_PATH"
                export LD_LIBRARY_PATH="${libraryPath}:$LD_LIBRARY_PATH"

                cat > /tmp/test.cpp << 'TESTSRC'
        ${testSource}
        TESTSRC

                echo "==> Compiling C++ test program"
                ${pkgs.gcc}/bin/g++ ${flags} -o /tmp/test /tmp/test.cpp
                echo "==> Running test program"
                /tmp/test
                echo "==> Test program exited successfully"
      '';
    };
  # -------------------------------------------------------------------------
  # mkSONAMECheck — Verify SONAME exists on shared libraries
  # -------------------------------------------------------------------------
  mkSONAMECheck = {
    pkg,
    libs,
  }: let
    libChecks = builtins.concatStringsSep "\n" (
      builtins.map (l: ''
        check_soname "${pkg}/lib/${l}" "${l}"
      '')
      libs
    );
  in
    mkVMTest {
      name = "${pkg.pname or "pkg"}-soname";
      rootfsDeps = [
        pkgs.elfutils
        pkgs.grep
        pkgs.sed
        pkg
      ];
      testScript = ''
        FAIL=0

        check_soname() {
          LIB_PATH="$1"
          LIB_NAME="$2"

          if [ ! -f "$LIB_PATH" ]; then
            echo "SKIP: $LIB_NAME ($LIB_PATH not found)"
            return
          fi

          SONAME_LINE=$(readelf -d "$LIB_PATH" 2>/dev/null | ${pkgs.grep}/bin/grep SONAME || true)
          if [ -z "$SONAME_LINE" ]; then
            echo "FAIL: $LIB_NAME has no SONAME"
            FAIL=1
            return
          fi
          echo "PASS: $LIB_NAME SONAME: $SONAME_LINE"
        }

        echo "==> Checking SONAMEs"
        ${libChecks}

        if [ "$FAIL" -ne 0 ]; then
          echo "==> SONAME check FAILED"
          exit 1
        fi
        echo "==> All SONAME checks passed"
      '';
    };

  # -------------------------------------------------------------------------
  # mkRPATHCheck — Verify RPATH entries point to valid dirs
  # -------------------------------------------------------------------------
  mkRPATHCheck = {
    pkg,
    bins,
  }: let
    binChecks = builtins.concatStringsSep "\n" (
      builtins.map (
        b: let
          # Support both bin/ and sbin/ — try both paths
          binPath =
            if builtins.substring 0 1 b == "/"
            then "${pkg}${b}"
            else "${pkg}/bin/${b}";
        in ''
          if [ -f "${binPath}" ]; then
            check_rpath "${binPath}" "${b}"
          elif [ -f "${pkg}/sbin/${b}" ]; then
            check_rpath "${pkg}/sbin/${b}" "${b}"
          else
            echo "SKIP: ${b} not found in ${pkg}/bin/ or ${pkg}/sbin/"
          fi
        ''
      )
      bins
    );
  in
    mkVMTest {
      name = "${pkg.pname or "pkg"}-rpath";
      rootfsDeps = [
        pkgs.elfutils
        pkgs.grep
        pkgs.sed
        pkg
      ];
      testScript = ''
        FAIL=0

        check_rpath() {
          BINARY="$1"
          LABEL="$2"

          echo "==> Checking RPATH for $LABEL ($BINARY)"

          RPATH_LINE=$(readelf -d "$BINARY" 2>/dev/null | ${pkgs.grep}/bin/grep -E 'RPATH|RUNPATH' || true)

          if [ -z "$RPATH_LINE" ]; then
            echo "  WARN: $LABEL has no RPATH/RUNPATH"
            return
          fi

          echo "  $RPATH_LINE"

          RPATH_VAL=$(echo "$RPATH_LINE" | ${pkgs.sed}/bin/sed 's/.*\[//' | ${pkgs.sed}/bin/sed 's/\]//')

          OLD_IFS="$IFS"
          IFS=":"
          for dir in $RPATH_VAL; do
            IFS="$OLD_IFS"

            case "$dir" in
              /usr/lib*|/lib|/lib64)
                echo "  FAIL: $LABEL has non-Nix RPATH entry: $dir"
                FAIL=1
                ;;
            esac

            if [ ! -d "$dir" ]; then
              echo "  FAIL: $LABEL RPATH directory does not exist: $dir"
              FAIL=1
            else
              echo "  OK: $dir exists"
            fi
          done
          IFS="$OLD_IFS"
        }

        ${binChecks}

        if [ "$FAIL" -ne 0 ]; then
          echo "==> RPATH check FAILED"
          exit 1
        fi
        echo "==> All RPATH checks passed"
      '';
    };

  # -------------------------------------------------------------------------
  # mkSymbolCheck — Verify symbols are exported from a shared library
  # -------------------------------------------------------------------------
  mkSymbolCheck = {
    pkg,
    libName,
    symbols,
  }: let
    symbolChecks = builtins.concatStringsSep "\n" (
      builtins.map (sym: ''
        check_symbol "${pkg}/lib/${libName}" "${libName}" "${sym}"
      '')
      symbols
    );
  in
    mkVMTest {
      name = "${pkg.pname or "pkg"}-symbols";
      rootfsDeps = [
        pkgs.binutils
        pkgs.grep
        pkg
      ];
      testScript = ''
        FAIL=0

        check_symbol() {
          LIB_PATH="$1"
          LIB_NAME="$2"
          SYMBOL="$3"

          if [ ! -f "$LIB_PATH" ]; then
            echo "SKIP: $LIB_NAME ($LIB_PATH not found)"
            return
          fi

          if nm -D "$LIB_PATH" 2>/dev/null | ${pkgs.grep}/bin/grep -q " T $SYMBOL"; then
            echo "PASS: $LIB_NAME exports $SYMBOL"
          else
            echo "FAIL: $LIB_NAME missing symbol $SYMBOL"
            FAIL=1
          fi
        }

        echo "==> Checking symbol exports"
        ${symbolChecks}

        if [ "$FAIL" -ne 0 ]; then
          echo "==> Symbol check FAILED"
          exit 1
        fi
        echo "==> All symbol checks passed"
      '';
    };

  # -------------------------------------------------------------------------
  # mkVersionCheck — Compare header version macros to runtime version
  # -------------------------------------------------------------------------
  # headerCode: C code fragment that sets `const char *header_ver = ...;`
  # runtimeCode: C code fragment that sets `const char *runtime_ver = ...;`
  # libs: linker flags (e.g. ["-lssl" "-lcrypto"])
  mkVersionCheck = {
    pkg,
    name,
    headerCode,
    runtimeCode,
    libs ? [],
  }: let
    includePath = makeIncludePath [pkg];
    libraryPath = makeLibraryPath [pkg];
    libFlags = builtins.concatStringsSep " " libs;
  in
    mkVMTest {
      name = "${pkg.pname or "pkg"}-version-${name}";
      rootfsDeps = [pkg];
      testScript = ''
        export C_INCLUDE_PATH="${includePath}:$C_INCLUDE_PATH"
        export LIBRARY_PATH="${libraryPath}:$LIBRARY_PATH"
        export LD_LIBRARY_PATH="${libraryPath}:$LD_LIBRARY_PATH"

        cat > /tmp/check_version.c << 'EOF'
        #include <stdio.h>
        #include <string.h>
        ${headerCode}
        int main(void) {
            ${runtimeCode}
            if (strcmp(header_ver, runtime_ver) != 0) {
                fprintf(stderr, "MISMATCH: header=%s runtime=%s\n", header_ver, runtime_ver);
                return 1;
            }
            printf("MATCH: %s\n", runtime_ver);
            return 0;
        }
        EOF

        echo "==> Checking ${name} version consistency"
        gcc -o /tmp/check_version /tmp/check_version.c ${libFlags}
        /tmp/check_version
        echo "==> Version consistency check passed"
      '';
    };

  # -------------------------------------------------------------------------
  # mkDynLinkerCheck — Verify ELF interpreter exists
  # -------------------------------------------------------------------------
  mkDynLinkerCheck = {
    pkg,
    bins,
  }: let
    binChecks = builtins.concatStringsSep "\n" (
      builtins.map (
        b: let
          binPath =
            if builtins.substring 0 1 b == "/"
            then "${pkg}${b}"
            else "${pkg}/bin/${b}";
        in ''
          if [ -f "${binPath}" ]; then
            check_interp "${binPath}" "${b}"
          elif [ -f "${pkg}/sbin/${b}" ]; then
            check_interp "${pkg}/sbin/${b}" "${b}"
          else
            echo "SKIP: ${b} not found in ${pkg}/bin/ or ${pkg}/sbin/"
          fi
        ''
      )
      bins
    );
  in
    mkVMTest {
      name = "${pkg.pname or "pkg"}-dynamic-linker";
      rootfsDeps = [
        pkgs.elfutils
        pkgs.grep
        pkgs.sed
        pkg
      ];
      testScript = ''
        FAIL=0

        check_interp() {
          BINARY="$1"
          LABEL="$2"

          echo "==> Checking dynamic linker for $LABEL ($BINARY)"

          INTERP_LINE=$(readelf -l "$BINARY" 2>/dev/null | ${pkgs.grep}/bin/grep "interpreter" || true)

          if [ -z "$INTERP_LINE" ]; then
            echo "  INFO: $LABEL has no interpreter (possibly static)"
            return
          fi

          echo "  $INTERP_LINE"

          INTERP=$(echo "$INTERP_LINE" | ${pkgs.sed}/bin/sed 's/.*interpreter: //' | ${pkgs.sed}/bin/sed 's/\].*//')

          if [ -z "$INTERP" ]; then
            echo "  FAIL: could not parse interpreter path for $LABEL"
            FAIL=1
            return
          fi

          if [ -f "$INTERP" ]; then
            echo "  PASS: interpreter exists: $INTERP"
          else
            echo "  FAIL: interpreter does not exist: $INTERP"
            FAIL=1
          fi
        }

        ${binChecks}

        if [ "$FAIL" -ne 0 ]; then
          echo "==> Dynamic linker check FAILED"
          exit 1
        fi
        echo "==> All dynamic linker checks passed"
      '';
    };
in {
  inherit
    mkLinkCheck
    mkToolCheck
    mkCompileCheck
    mkCxxCompileCheck
    mkSONAMECheck
    mkRPATHCheck
    mkSymbolCheck
    mkVersionCheck
    mkDynLinkerCheck
    ;
}
