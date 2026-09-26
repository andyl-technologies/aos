##! Apache Portable Runtime built from the upstream source release.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bash,
  lib,
}: let
  version = "1.7.0";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "apr";
    inherit version;

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed APR configuration helper.";
        operation = "Request the installed APR release version.";
        expected = "The helper reports the packaged release version.";
        artifacts = [];
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess
                result = subprocess.run(["@out@/bin/apr-1-config", "--version"], capture_output=True, text=True)
                assert result.returncode == 0 and result.stdout.strip() == "${version}", (result.returncode, result.stdout, result.stderr)
                print("APR version passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "APR version passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An unsupported configuration-helper option.";
        operation = "Pass the unsupported option to APR's configuration helper.";
        expected = "The helper rejects the option and prints usage information.";
        artifacts = [];
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess
                import sys
                result = subprocess.run(["@out@/bin/apr-1-config", "--aos-invalid-option"], capture_output=True, text=True)
                assert result.returncode != 0 and "Usage: apr-1-config" in result.stdout, (result.returncode, result.stdout, result.stderr)
                sys.stderr.write("APR rejected invalid input\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "APR rejected invalid input\n";
          }
        ];
      };
    };

    src = fetchurl {
      urls = ["https://archive.apache.org/dist/apr/apr-${version}.tar.gz"];
      hash = "sha256-SOnb9Frj/ce0kSWf+2zPfWMEn/rLwcCXfM7QleTC1aI=";
    };

    buildDeps = [buildPackages.file];
    runtimeDeps = [bash];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd apr-${version}
          # The released configure script hardcodes this host path in libtool.
          sed -i 's|/usr/bin/file|${buildPackages.file}/bin/file|g' configure
          ${
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # Its cross default assumes GNU strerror_r, unlike macOS.
              sed -i '/^if test "$cross_compiling" = yes; then :$/,/^else$/s/    ac_cv_strerror_r_rc_int=no/    ac_cv_strerror_r_rc_int=yes/' configure
            ''
            else ""
          }
        '';
      }
      {
        name = "configure";
        script = ''
          # JNI embeds the static archive; old probes use K&R main and exit.
          export CFLAGS="''${CFLAGS:-} -fPIC -Wno-error=implicit-int -Wno-error=implicit-function-declaration"
          ${
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # The target's /dev/zero exists; its pid_t is a 32-bit int.
              export ac_cv_file__dev_zero=yes ac_cv_sizeof_pid_t=4
              export ac_cv_sizeof_struct_iovec=16
              export ac_cv_func_setpgrp_void=yes
              # macOS uses its alternate process-lock and TCP buffering paths.
              export apr_cv_process_shared_works=no
              export apr_cv_tcp_nodelay_with_cork=no
            ''
            else if stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # Linux arm64 uses the same 64-bit data model as native Linux.
              export ac_cv_file__dev_zero=yes ac_cv_sizeof_pid_t=4
              export ac_cv_sizeof_struct_iovec=16
              export ac_cv_func_setpgrp_void=yes
              export apr_cv_process_shared_works=yes
              export apr_cv_mutex_robust_shared=yes
              export apr_cv_tcp_nodelay_with_cork=yes
            ''
            else ""
          }
          $CONFIG_SHELL ./configure $configureFlags \
            --prefix="$out" --enable-shared --enable-static
        '';
      }
      {
        name = "build";
        script = ''
          ${
            if stdenv.isCross
            then ''
              # The generated escape table uses a build-time executable.
              mkdir -p include/private
              "$CC_FOR_BUILD" tools/gen_test_char.c -o gen_test_char_for_build
              LC_ALL=C ./gen_test_char_for_build > include/private/apr_escape_test_char.h
              sed -i 's|^include/private/apr_escape_test_char.h: tools/gen_test_char.*$|include/private/apr_escape_test_char.h:|' Makefile
            ''
            else ""
          }
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          test -f .libs/libapr-1.a
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > apr-smoke.c <<'C'
              #include <apr_general.h>
              #include <apr_pools.h>

              int main(void) {
                  apr_pool_t *pool = 0;
                  if (apr_initialize() != APR_SUCCESS) return 1;
                  if (apr_pool_create(&pool, 0) != APR_SUCCESS) return 2;
                  apr_pool_destroy(pool);
                  apr_terminate();
                  return 0;
              }
              C
              cc -Iinclude apr-smoke.c .libs/libapr-1.a -pthread -o apr-smoke
              ./apr-smoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install
          # Installed helper scripts execute on the target platform.
          sed -i 's|/bin/sh|${bash}/bin/bash|g' \
            "$out/bin/apr-1-config" \
            "$out/build-1/mkdir.sh" \
            "$out/build-1/libtool"
        '';
      }
    ];

    meta = {
      description = "Portable operating system interfaces for native libraries";
      homepage = "https://apr.apache.org/";
      license = "Apache-2.0";
    };
  }
