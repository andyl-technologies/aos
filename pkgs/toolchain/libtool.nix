##! libtool — GNU portable library tool
##!
##! Provides `libtoolize` (called from packages' `autogen.sh`/`autoreconf`
##! to copy `ltmain.sh` + supporting m4 macros into the source tree
##! before `autoconf` runs) and the `libtool` script that wraps
##! shared-library link commands. The first AOS consumer is
##! `pkgs.erofs-utils`, whose snapshot tarball ships only
##! `configure.ac` and needs the full autotools bootstrap.
{
  mkDerivation,
  fetchurl,
  m4,
  gnumake,
  sed,
  grep,
  gawk,
  coreutils,
  bzip2,
  xz,
  gzip,
  bash,
  stdenv,
}: let
  version = "2.5.4";
in
  mkDerivation {
    pname = "libtool";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/libtool/libtool-${version}.tar.xz"
      ];
      hash = "sha256-+B9YYGZrC8fYS63e+mDRy5+m/OsjmMw7rKavqmAmZnU=";
    };

    buildDeps = [
      gnumake
      m4
      sed
      grep
      gawk
      coreutils
      bzip2
      xz
      gzip
      bash
    ];
    # libtool's `./configure` bakes the absolute paths of the build-time
    # sed/grep/awk/coreutils/etc. into both the installed `bin/libtool`
    # wrapper script and the `bin/libtoolize` Perl-driver-as-shell script.
    # Without these as runtimeDeps, the scrubPhase rewrites every hash to
    # `eeee…eeee` and the installed scripts fail at first invocation
    # (`libtoolize: line N: /nix/store/eeee…/bin/sed: No such file`).
    # m4 is needed at runtime because libtoolize copies macros that
    # downstream `aclocal` later feeds back into m4.
    runtimeDeps = [
      m4
      sed
      grep
      gawk
      coreutils
      bzip2
      xz
      gzip
      bash
    ];
    propagatedDeps = [m4];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtool-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags --prefix=$out
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
        # Upstream tarball ships `libtoolize` and `ltmain.sh` with a
        # `#! /usr/bin/env sh` shebang; the AOS hermetic rule forbids
        # `/usr/bin/env`. Rewrite to the stdenv bash absolute path so
        # the installed scripts work regardless of PATH/$out layout in
        # downstream sandboxes. (`bin/libtool` already gets a hard-coded
        # bash path from libtool's own `./configure`.)
        script = ''
          make install
          for f in $out/bin/libtool \
                   $out/bin/libtoolize \
                   $out/share/libtool/build-aux/ltmain.sh; do
            [ -f "$f" ] || continue
            sed -i "1c #!${bash}/bin/bash" "$f"
          done

          # Configure must execute native tools on the Linux builder, but its
          # generated scripts record their absolute paths. Retarget references
          # that are present to the corresponding host-platform tools.
          retarget_tool_root() {
            nativeTool=$(command -v "$1")
            nativeRoot=$(dirname "$(dirname "$nativeTool")")
            targetRoot=$2
            [ "$nativeRoot" = "$targetRoot" ] && return
            { grep -IrlZ -F "$nativeRoot" "$out" 2>/dev/null || [ "$?" -eq 1 ]; } \
              | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
          }
          retarget_tool_root m4 ${m4}
          retarget_tool_root sed ${sed}
          retarget_tool_root grep ${grep}
          retarget_tool_root gawk ${gawk}
          retarget_tool_root dirname ${coreutils}
          retarget_tool_root bzip2 ${bzip2}
          retarget_tool_root xz ${xz}
          retarget_tool_root gzip ${gzip}

          nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
          { grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null || [ "$?" -eq 1 ]; } \
            | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"

          # A cross-built libtool must select the compiler present on its host
          # platform rather than retaining the Linux cross-wrapper executable.
          { grep -IrlZ -F "${stdenv.cc}/bin/" "$out" 2>/dev/null || [ "$?" -eq 1 ]; } \
            | xargs -0 -r sed -i "s|${stdenv.cc}/bin/||g"
        '';
      }
    ];

    meta = {
      description = "GNU libtool — generic library support";
      homepage = "https://www.gnu.org/software/libtool/";
      license = "GPL-2.0-or-later";
    };
  }
