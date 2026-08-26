##! Tcl — Tool Command Language runtime and development library
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  buildPackages,
  stdenv,
  bash,
}: let
  version = "9.0.2";
in
  mkDerivation {
    pname = "tcl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://prdownloads.sourceforge.net/tcl/tcl${version}-src.tar.gz"
      ];
      hash = "sha256-4HTGqNm6LN35FLqXtmd6VS16UqPKECkkOJoFzLJJtSA=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.tcl]
        else []
      );
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tcl${version}/unix
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross
            then ''
              export ac_cv_path_tclsh="${buildPackages.tcl}/bin/tclsh9.0"
              ${
                if stdenv.hostPlatform.isDarwin
                then ''
                  tcl_source_root=$(cd .. && pwd)
                  export CFLAGS="$CFLAGS \
                    -ffile-prefix-map=$tcl_source_root=. \
                    -fdebug-prefix-map=$tcl_source_root=."

                  # Tcl's platform macro unconditionally calls build-machine
                  # uname, even when Autoconf is cross-compiling. Seed the
                  # target system so it selects Mach-O dynamic-library flags
                  # instead of Linux's --export-dynamic/shared-object rules.
                  export tcl_cv_sys_version=Darwin-20.0.0

                  # Its Darwin 64-bit probe likewise shells out to `arch`,
                  # which would report the Linux builder even if it existed.
                  # Provide the target answer to Tcl and every bundled TEA
                  # extension configure script.
                  mkdir -p .aos-build-tools
                  cat > .aos-build-tools/arch <<ARCH_WRAPPER
                  #!$CONFIG_SHELL
                  printf '%s\n' '${stdenv.hostPlatform.darwinArch}'
                  ARCH_WRAPPER
                  chmod +x .aos-build-tools/arch
                  export PATH="$PWD/.aos-build-tools:$PATH"

                  # Tcl also builds minizip objects for its native zipfs
                  # generator. Keep that compiler isolated from the target
                  # SDK and architecture flags exported by the cross stdenv.
                  native_cc="$BUILD_CC"
                  cat > .aos-build-tools/cc-for-build <<EOF
                  #!$CONFIG_SHELL
                  unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
                  unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
                  unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
                  exec "$native_cc" "\$@"
                  EOF
                  chmod +x .aos-build-tools/cc-for-build
                  export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"

                  # Bundled extensions normally choose the just-linked Tcl
                  # interpreter from TCL_BIN_DIR. That is a Darwin executable,
                  # so make their ZipFS generators use the source-built native
                  # Tcl while leaving all extension objects target-compiled.
                  find ../pkgs -type f -name configure -exec sed -i \
                    's|TCLSH_PROG="''${TCL_BIN_DIR}/tclsh"|TCLSH_PROG="${buildPackages.tcl}/bin/tclsh9.0"|' \
                    {} +

                  export ac_cv_func_getnameinfo=yes
                  export ac_cv_func_getaddrinfo=yes
                  export ac_cv_func_freeaddrinfo=yes
                  export ac_cv_func_gai_strerror=yes
                ''
                else ""
              }
            ''
            else ""
          }
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --enable-threads \
            --enable-64bit
        '';
      }
      {
        name = "build";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # Darwin's linker otherwise uses each output basename as its
            # install name. Give the core and TEA extension libraries their
            # final immutable IDs while linking, so consumers record those
            # names without mutating completed Mach-O load commands.
            # Bundled TEA extensions configure lazily from Makefile.in during
            # the main build, so patch both generated Makefiles and templates.
            for makefile in $(find .. -type f \( -name Makefile -o -name Makefile.in \)); do
              if grep -q '^pkglibdir[[:space:]]*=' "$makefile"; then
                sed -i \
                  '/^SHLIB_LD[[:space:]]*=/ s|$| -Wl,-install_name,$(pkglibdir)/$@|' \
                  "$makefile"
              else
                sed -i \
                  '/^SHLIB_LD[[:space:]]*=/ s|$| -Wl,-install_name,__AOS_TCL_LIBDIR__/$@|' \
                  "$makefile"
                sed -i "s|__AOS_TCL_LIBDIR__|$out/lib|g" "$makefile"
              fi
            done
            make -j$NIX_BUILD_CORES
          ''
          else ''
            make -j$NIX_BUILD_CORES
          '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            tcl_source_root=$(cd .. && pwd)
            make install
            make install-private-headers

            # The bundled analyzer is a Tcl script. Point it at the target
            # shell explicitly instead of leaving an impermissible /bin/sh
            # shebang in the Darwin output.
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/sqlite3_analyzer"

            # Installed *Config.sh files contain parallel BUILD_* variables
            # for in-tree consumers. Redirect those to the corresponding
            # installed libraries and headers so they remain useful without
            # retaining the ephemeral source directory.
            sed -i \
              -e "s|$tcl_source_root/unix/pkgs/itcl4.3.3|$out/lib/itcl4.3.3|g" \
              -e "s|$tcl_source_root/pkgs/itcl4.3.3/generic|$out/include|g" \
              -e "s|$tcl_source_root/pkgs/itcl4.3.3|$out/include|g" \
              "$out/lib/itcl4.3.3/itclConfig.sh"
            sed -i \
              -e "s|$tcl_source_root/unix/pkgs/tdbc1.1.11|$out/lib/tdbc1.1.11|g" \
              -e "s|$tcl_source_root/pkgs/tdbc1.1.11/generic|$out/include|g" \
              -e "s|$tcl_source_root/pkgs/tdbc1.1.11/library|$out/lib/tdbc1.1.11|g" \
              -e "s|$tcl_source_root/pkgs/tdbc1.1.11|$out/include|g" \
              "$out/lib/tdbc1.1.11/tdbcConfig.sh"
            sed -i \
              -e "s|$tcl_source_root/unix|$out/lib|g" \
              -e "s|$tcl_source_root|$out/include|g" \
              "$out/lib/tclConfig.sh"
          ''
          else ''
            make install
            make install-private-headers
          '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-tclsh";
        tool = self;
        command = ''printf 'puts [info patchlevel]\n' | tclsh9.0'';
        expectedOutput = version;
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libtcl9.0.so"];
      };
    };

    meta = {
      description = "Tcl embeddable scripting language and runtime";
      homepage = "https://www.tcl-lang.org/";
      license = "TCL";
    };
  }
