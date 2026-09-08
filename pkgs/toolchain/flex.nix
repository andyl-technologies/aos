##! flex — Fast lexical analyzer generator
{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  stdenv,
}: let
  version = "2.6.4";
in
  mkDerivation {
    pname = "flex";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/westes/flex/releases/download/v${version}/flex-${version}.tar.gz"
      ];
      hash = "sha256-6HquAyvwfCb4WsDtMlCZjDdiHZX4vXSLMfFbM8Re6ZU=";
    };

    buildDeps = [
      gnumake
      m4
    ];
    # flex exec()s m4 at runtime to expand the generated scanner skeleton
    # templates; without m4 in runtimeDeps, the scrubPhase nuke-refs pass
    # would rewrite flex's hardcoded m4 path and break every downstream
    # `make flex` invocation.
    runtimeDeps = [m4];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd flex-${version}
        '';
      }
      {
        name = "configure";
        script =
          (
            if stdenv.isCross || stdenv.hostPlatform.isDarwin
            then ''
              # Flex builds stage1flex for the build machine. Autoconf already
              # separates its flags, but CC_FOR_BUILD must retain the native
              # build dependency closure while excluding target search paths
              # and hardening settings inherited by the configure process.
              native_cc="$BUILD_CC"
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc-for-build <<EOF
              #!$CONFIG_SHELL
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc-for-build
              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"
              export CFLAGS_FOR_BUILD=
              export CPPFLAGS_FOR_BUILD=
              export LDFLAGS_FOR_BUILD=

            ''
            else ""
          )
          + (
            if stdenv.hostPlatform.isDarwin
            then ''
              # Preserve the established Darwin ABI cache: malloc(0) and
              # realloc(0) return usable allocations on the target platform.
              export ac_cv_func_malloc_0_nonnull=yes
              export ac_cv_func_realloc_0_nonnull=yes
            ''
            else if stdenv.isCross && stdenv.targetRunner != null
            then ''
              # Run Flex's exact Autoconf tests against target libc before
              # caching their results. config.h is also consumed by the native
              # stage1 generator, so an unmeasured cross guess is unsafe.
              cat > .aos-build-tools/malloc-zero-probe.c <<'EOF'
              #include <stdlib.h>

              int
              main ()
              {
                return ! malloc (0);
              }
              EOF

              cat > .aos-build-tools/realloc-zero-probe.c <<'EOF'
              #include <stdlib.h>

              int
              main ()
              {
                return ! realloc (0, 0);
              }
              EOF

              "$CC" .aos-build-tools/malloc-zero-probe.c \
                -o .aos-build-tools/malloc-zero-probe
              "$CC" .aos-build-tools/realloc-zero-probe.c \
                -o .aos-build-tools/realloc-zero-probe

              if ${stdenv.targetRunner}/bin/aos-run-${stdenv.hostPlatform.system} \
                .aos-build-tools/malloc-zero-probe; then
                ac_cv_func_malloc_0_nonnull=yes
              else
                probe_status=$?
                if test "$probe_status" -eq 1; then
                  ac_cv_func_malloc_0_nonnull=no
                else
                  echo "target malloc(0) probe failed with status $probe_status" >&2
                  exit 1
                fi
              fi

              if ${stdenv.targetRunner}/bin/aos-run-${stdenv.hostPlatform.system} \
                .aos-build-tools/realloc-zero-probe; then
                ac_cv_func_realloc_0_nonnull=yes
              else
                probe_status=$?
                if test "$probe_status" -eq 1; then
                  ac_cv_func_realloc_0_nonnull=no
                else
                  echo "target realloc(0, 0) probe failed with status $probe_status" >&2
                  exit 1
                fi
              fi

              export ac_cv_func_malloc_0_nonnull
              export ac_cv_func_realloc_0_nonnull
            ''
            else if stdenv.isCross
            then ''
              echo 'cross build cannot run target malloc/realloc probes' >&2
              exit 1
            ''
            else ""
          )
          + (
            if stdenv.hostPlatform.isDarwin
            then ''
              # libfl intentionally supplies main() while leaving yylex() to
              # the generated scanner linked by its consumer. Mach-O requires
              # that plugin-style unresolved symbol policy to be explicit.
              sed -i \
                's/^libfl_la_LDFLAGS = \(.*\)$/libfl_la_LDFLAGS = \1 -Wl,-undefined,dynamic_lookup/' \
                src/Makefile.in
            ''
            else ""
          )
          + ''
            ./configure \
              $configureFlags \
              --prefix=$out
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "flex — fast lexical analyzer generator";
      homepage = "https://github.com/westes/flex";
      license = "BSD-2-Clause";
    };
  }
