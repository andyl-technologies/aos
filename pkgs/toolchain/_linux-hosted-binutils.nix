##! GNU binutils hosted on the selected Linux target.
##!
##! The Linux cross stdenv keeps a scheduler-native binutils internally so
##! package builds can execute the assembler and linker.  This derivation is
##! the distinct public toolchain: its programs execute on the selected target
##! and produce binaries for that same target.
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  bash,
  zlib,
}: let
  version = "2.41";
  objdumpArchitecture =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else if stdenv.hostPlatform.isx86_64
    then "i386:x86-64"
    else throw "linux-hosted-binutils: unsupported target '${stdenv.hostPlatform.system}'";
in
  mkDerivation {
    pname = "binutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"
      ];
      hash = "sha256-rppXieI0WeWWBuZxRyPy0//DHAMXQZHvDQFb3wYAdFA=";
    };

    buildDeps = [
      buildPackages.gnumake
      buildPackages.perl
      buildPackages.texinfo
    ];
    runtimeDeps = [
      bash
      zlib
    ];
    propagatedDeps = [];

    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd binutils-${version}

          # Preserve the release-generated parsers and Autotools output.
          find . -type f \( -name '*.y' -o -name '*.l' -o -name Makefile.am -o -name configure.ac \) \
            -exec touch -t 200001010000.00 {} + 2>/dev/null || true
          find . -type f \( -name '*.c' -o -name '*.h' \) \
            -exec touch -t 200001010030.00 {} + 2>/dev/null || true
          find . \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) \
            -exec touch -t 200001010100.00 {} + 2>/dev/null || true
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir "$TMPDIR/binutils-build"
          cd "$TMPDIR/binutils-build"

          "$TMPDIR/binutils-${version}/configure" \
            --prefix="$out" \
            --build=${stdenv.buildPlatform.config} \
            --host=${stdenv.hostPlatform.config} \
            --target=${stdenv.hostPlatform.config} \
            --disable-gdb \
            --disable-gdbserver \
            --disable-gprofng \
            --disable-libdecnumber \
            --disable-nls \
            --disable-readline \
            --disable-shared \
            --disable-sim \
            --disable-werror \
            --enable-gold \
            --with-system-zlib \
            --with-sysroot=/ \
            --program-transform-name=
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" MAKEINFO=true
        '';
      }
      {
        name = "install";
        script = ''
          make install MAKEINFO=true

          for tool in ar as ld nm objcopy objdump ranlib readelf size strings strip; do
            test -x "$out/bin/$tool"
          done
          test -x "$out/bin/ld.gold"

          for executable in as ld objdump; do
            if ! "$OBJDUMP" -f "$out/bin/$executable" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
              echo "$out/bin/$executable does not execute on ${stdenv.hostPlatform.system}" >&2
              exit 1
            fi
          done

          # Installed helper scripts execute on the target with AOS bash.
          find "$out" -type f -perm -0100 | while read -r file; do
            if ! head -c 2 "$file" | grep -Fq '#!'; then
              continue
            fi

            IFS= read -r firstLine < "$file" || true
            case "$firstLine" in
              '#!'*'/sh'|'#!'*'/bash')
                sed -i "1c #!${bash}/bin/bash" "$file"
                ;;
            esac
          done
        '';
      }
    ];

    meta = {
      description = "GNU binutils ${version} hosted on ${stdenv.hostPlatform.system}";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      mainProgram = "ld";
      build = {
        os = "linux";
        cpu = [stdenv.buildPlatform.constraints.cpu];
      };
      execute = {
        os = "linux";
        cpu = [stdenv.hostPlatform.constraints.cpu];
      };
      target = {
        os = "linux";
        cpu = [stdenv.hostPlatform.constraints.cpu];
      };
    };
  }
