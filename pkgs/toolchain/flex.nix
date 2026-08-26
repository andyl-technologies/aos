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
            if stdenv.hostPlatform.isDarwin
            then ''
              # Flex builds stage1flex for the build machine. Autoconf already
              # separates its flags, but the native AOS compiler wrapper would
              # otherwise still inherit the target SDK and hardening settings.
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

              # Darwin malloc(0) and realloc(0) return usable allocations.
              # Avoid configuring target replacement functions into the
              # config.h shared with the native stage1 generator.
              export ac_cv_func_malloc_0_nonnull=yes
              export ac_cv_func_realloc_0_nonnull=yes

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
