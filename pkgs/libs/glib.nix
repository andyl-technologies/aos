##! glib — GLib core library (data structures, type system, event loop)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  libffi,
  pcre2,
  zlib,
  util-linux,
  gettext,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "2.82.4";
  majorMinor = builtins.concatStringsSep "." (
    builtins.genList (i: builtins.elemAt (builtins.split "\\." version) (i * 2)) 2
  );
in
  mkDerivation {
    pname = "glib";
    inherit version;
    outputs = ["out" "dev" "tools"];

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/glib/${majorMinor}/glib-${version}.tar.xz"
      ];
      hash = "sha256-N90Id/6WTNFemicQsEShgw+xvZNlKm0Mtriy3/GHxwk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
      python3
    ];
    runtimeDeps =
      [
        libffi
        pcre2
        zlib
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash gettext]
        else [util-linux]
      );
    propagatedDeps =
      [
        libffi
        pcre2
        zlib
      ]
      ++ (
        # Darwin libc does not provide gettext. GLib's public gi18n header
        # includes libintl.h, so the source-built implementation must remain
        # visible to both GLib itself and downstream consumers.
        if stdenv.hostPlatform.isDarwin
        then [gettext]
        else []
      );
    # The installed generators retain their Python interpreter in the tools
    # output. Keep that reference during the generic runtime scrub. The image
    # closure audit below the package layer proves it cannot escape through
    # the runtime library output.
    nukeRefsKeep = [python3];

    phases = [
      {
        name = "unpack";
        script =
          ''
            tar xf $src
            cd glib-${version}
          ''
          + (
            if stdenv.hostPlatform.isDarwin
            then ''
              # Upstream nests the deployment-target probe under its legacy
              # Carbon probe. The public SDK provides Carbon's header-only
              # keyboard constants, but deliberately has no linkable legacy
              # Carbon framework, while AvailabilityMacros still makes
              # giomodule.c reference the 10.9+ notification backend. Our
              # minimum target is 11.0, so keep the matching Cocoa
              # implementation in libgio.
              sed -i \
                's/    if glib_have_os_x_9_or_later/    if true/' \
                gio/meson.build

              # Carbon.h is intentionally a header-only compatibility
              # surface for consumers of the legacy keyboard constants. It
              # does not imply that the removed Carbon framework is linkable.
              # Upstream treats a successful header compile as proof of the
              # framework and later makes the framework dependency required;
              # keep its probe result aligned with the SDK's actual ABI.
              sed -i \
                "/name : 'Mac OS X Carbon support')/a\\  glib_have_carbon = false" \
                meson.build

              # Meson links GLib and GIO with the C driver after compiling
              # their Cocoa sources separately. Unlike a combined
              # Objective-C link, that driver does not add libobjc
              # automatically, so declare the runtime alongside the Apple
              # frameworks which use it in both libraries.
              sed -i \
                's/platform_deps += \[framework_dep\]/platform_deps += [framework_dep, objcc.find_library('"'"'objc'"'"')]/' \
                glib/meson.build gio/meson.build
            ''
            else ""
          )
          + ''
            # Meson executes source-tree generators during the build, so their
            # shebangs must name native Python until installation is complete.
            nativePython=$(command -v python3)
            find . -type f -name '*.py' | while read f; do
              if head -1 "$f" | grep -q '^#!'; then
                sed -i "1s|#!/usr/bin/env python3|#!$nativePython|" "$f"
                sed -i "1s|#!/usr/bin/python3|#!$nativePython|" "$f"
              fi
            done
          '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --buildtype=release \
            -Dselinux=disabled \
            -Dxattr=false \
            -Dlibmount=${
            if stdenv.hostPlatform.isDarwin
            then "disabled"
            else "enabled"
          } \
            -Dman-pages=disabled \
            -Ddtrace=disabled \
            -Dsystemtap=disabled \
            -Ddocumentation=false \
            -Dinstalled_tests=false \
            -Dnls=disabled \
            -Doss_fuzz=disabled \
            -Dglib_checks=true \
            -Dglib_assert=false \
            -Dtests=false
        '';
      }
      {
        name = "build";
        script = ''
          # Meson records its Python module invocation in build.ninja, not the
          # environment-setting launcher used during setup.
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install

          # Keep the default output library-only. Python-backed generators
          # are build tools, while headers, static archives, and package
          # metadata belong to the development output. A runtime consumer of
          # libglib must not retain either class transitively.
          mkdir -p "$dev/lib" "$dev/share" "$tools"
          if [ -d "$out/include" ]; then
            mv "$out/include" "$dev/include"
          fi
          for directory in pkgconfig cmake; do
            if [ -d "$out/lib/$directory" ]; then
              mv "$out/lib/$directory" "$dev/lib/$directory"
            fi
          done
          find "$out/lib" -maxdepth 1 -type f \( -name '*.a' -o -name '*.la' \) \
            -exec mv {} "$dev/lib/" \;
          if [ -d "$out/share/aclocal" ]; then
            mv "$out/share/aclocal" "$dev/share/aclocal"
          fi
          if [ -d "$out/bin" ]; then
            mv "$out/bin" "$tools/bin"
          fi
          if [ -d "$out/libexec" ]; then
            mv "$out/libexec" "$tools/libexec"
          fi
          if [ -d "$out/lib/glib-2.0/include" ]; then
            mkdir -p "$dev/lib/glib-2.0"
            mv "$out/lib/glib-2.0/include" "$dev/lib/glib-2.0/include"
          fi
          for link in "$out/lib/"*.${stdenv.hostPlatform.sharedLibraryExtension}; do
            [ -L "$link" ] || continue
            target=$(readlink "$link")
            name=$(basename "$link")
            rm "$link"
            ln -s "$out/lib/$target" "$dev/lib/$name"
          done
          if [ -d "$out/share/glib-2.0/codegen" ]; then
            mkdir -p "$tools/share/glib-2.0"
            mv "$out/share/glib-2.0/codegen" "$tools/share/glib-2.0/codegen"
          fi
          for directory in glib-2.0/gdb glib-2.0/valgrind gdb; do
            if [ -d "$out/share/$directory" ]; then
              mkdir -p "$dev/share/$(dirname "$directory")"
              mv "$out/share/$directory" "$dev/share/$directory"
            fi
          done
          if [ -d "$out/share/bash-completion" ]; then
            mkdir -p "$tools/share"
            mv "$out/share/bash-completion" "$tools/share/bash-completion"
          fi

          for pc in "$dev/lib/pkgconfig/"*.pc; do
            [ -e "$pc" ] || continue
            sed -i \
              -e "s|^prefix=.*|prefix=$dev|" \
              -e "s|^libdir=.*|libdir=$out/lib|" \
              -e "s|^includedir=.*|includedir=$dev/include|" \
              -e "s|^bindir=.*|bindir=$tools/bin|" \
              "$pc"
          done
          sed -i \
            -e "s|\''${libdir}/glib-2.0/include|$dev/lib/glib-2.0/include|g" \
            "$dev/lib/pkgconfig/glib-2.0.pc"
          sed -i \
            -e "s|^schemasdir=.*|schemasdir=$out/share/glib-2.0/schemas|" \
            -e "s|^dtdsdir=.*|dtdsdir=$out/share/glib-2.0/dtds|" \
            "$dev/lib/pkgconfig/gio-2.0.pc"

          nativePythonRoot=$(dirname "$(dirname "$(command -v python3)")")
          pythonRefs=$PWD/glib-python-refs
          for root in "$out" "$dev" "$tools"; do
            : > "$pythonRefs"
            grep -IrlZ -F "$nativePythonRoot" "$root" \
              > "$pythonRefs" 2>/dev/null || true
            if [ -s "$pythonRefs" ]; then
              xargs -0 -r sed -i "s|$nativePythonRoot|${python3}|g" \
                < "$pythonRefs"
            fi
          done
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              if [ -f "$tools/bin/glib-gettextize" ]; then
                sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$tools/bin/glib-gettextize"
              fi
            ''
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "glib — GLib core library providing data structures, type system, and event loop";
      homepage = "https://wiki.gnome.org/Projects/GLib";
      license = "LGPL-2.1-or-later";
    };
  }
