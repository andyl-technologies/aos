##! GDK-Pixbuf image loading, transformation, and thumbnail generation.
{
  mkDerivation,
  lib,
  fetchurl,
  buildPackages,
  stdenv,
  gobject-introspection,
  callPackage,
  libpng,
  mozjpeg,
  libtiff,
  shared-mime-info,
  util-linux,
  libglycin,
  glycin-image-rs,
}: let
  version = "2.44.8";
  glib = callPackage ./_image-glib.nix {};
  runtimePackages =
    [glib libpng mozjpeg libtiff shared-mime-info]
    ++ (
      if stdenv.hostPlatform.isLinux
      then [util-linux libglycin glycin-image-rs]
      else []
    );
  runtimeClosureManifest = builtins.concatStringsSep "\n" (map builtins.toString runtimePackages);
  probeScript = ''
    import pathlib
    import struct
    import subprocess
    import sys
    import zlib

    command = ["@out@/bin/gdk-pixbuf-csource", "--raw", "--name=aos_pixel"]

    if sys.argv[1] == "primary":
        def chunk(kind, data):
            length = struct.pack(">I", len(data))
            checksum = struct.pack(">I", zlib.crc32(kind + data))
            return length + kind + data + checksum

        header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
        pixel = zlib.compress(b"\x00\xff\x00\x00\xff")
        image = b"\x89PNG\r\n\x1a\n"
        image += chunk(b"IHDR", header) + chunk(b"IDAT", pixel) + chunk(b"IEND", b"")
        pathlib.Path("pixel.png").write_bytes(image)

        result = subprocess.run(command + ["pixel.png"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
        assert "aos_pixel" in result.stdout
        assert "/* width (1) */" in result.stdout
        assert "/* height (1) */" in result.stdout
        assert r"\377\0\0\377" in result.stdout
        print("decoded red PNG pixel")
    elif sys.argv[1] == "bad-input":
        pathlib.Path("bad.png").write_text("not a png")
        result = subprocess.run(command + ["bad.png"], capture_output=True, text=True)
        assert result.returncode != 0
        assert result.stdout == ""
        assert "failed to load" in result.stderr
        assert "bad.png" in result.stderr
        print("rejected malformed PNG")
    else:
        raise ValueError("unknown qualification operation")
  '';
  glycinDataDirPrefix =
    if stdenv.hostPlatform.isLinux
    then "${glycin-image-rs}/share:"
    else "";
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
    pname = "gdk-pixbuf";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A one-pixel red RGBA PNG image.";
        operation = "Decode the image and emit its GdkPixdata C representation.";
        expected = "The generated pixdata contains the expected dimensions and red pixel.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "primary"];
            exit_code = 0;
            stdout.exact = "decoded red PNG pixel\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Text mislabeled as a PNG image.";
        operation = "Decode the malformed file through the GDK-Pixbuf command.";
        expected = "The image loader rejects the malformed data.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "bad-input"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "rejected malformed PNG\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://download.gnome.org/sources/gdk-pixbuf/2.44/gdk-pixbuf-${version}.tar.xz"];
      hash = "0g5saar4zk8kcl6336kzkr336fcclikb9d6l3kl146ln2aam57wi";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.gobject-introspection buildPackages.docutils buildPackages.glib.tools];
    runtimeDeps = runtimePackages;
    # Expose the complete Requires and Requires.private pkg-config contract.
    propagatedDeps =
      [glib libpng mozjpeg libtiff shared-mime-info]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [libglycin]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd gdk-pixbuf-${version}
            # Bind executable generators without changing the image test fixtures.
            find build-aux -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:${shared-mime-info}/share/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            export XDG_DATA_DIRS="${glycinDataDirPrefix}${shared-mime-info}/share:${glib}/share:${buildPackages.gobject-introspection}/share"
            ${
              if stdenv.isCross
              then ''
                # Use native scanner programs while describing target GI libraries.
                mkdir -p .aos-introspection
                cat > .aos-introspection/ldd-target <<'EOF'
                #!${buildPackages.bash}/bin/bash
                exec ${stdenv.glibc}/lib/${stdenv.hostPlatform.dynamicLinker} --list "$@"
                EOF
                cat > .aos-introspection/g-ir-scanner <<EOF
                #!${buildPackages.bash}/bin/bash
                exec ${buildPackages.gobject-introspection}/bin/g-ir-scanner --use-ldd-wrapper="$PWD/.aos-introspection/ldd-target" "\$@"
                EOF
                chmod +x .aos-introspection/ldd-target .aos-introspection/g-ir-scanner
                cp ${gobject-introspection}/lib/pkgconfig/gobject-introspection-1.0.pc .aos-introspection/
                sed -i \
                  -e "s|^g_ir_scanner=.*|g_ir_scanner=$PWD/.aos-introspection/g-ir-scanner|" \
                  -e 's|^g_ir_compiler=.*|g_ir_compiler=${buildPackages.gobject-introspection}/bin/g-ir-compiler|' \
                  .aos-introspection/gobject-introspection-1.0.pc
                export PKG_CONFIG_PATH="$PWD/.aos-introspection:$PKG_CONFIG_PATH"
              ''
              else ""
            }
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Dpng=enabled -Djpeg=enabled -Dtiff=enabled -Dgif=enabled -Dintrospection=enabled
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/gdk-pixbuf"
            cp COPYING "$out/share/licenses/gdk-pixbuf/"

            # Codec discovery reads data files rather than linked libraries.
            # Keep their package roots in the runtime closure as well.
            mkdir -p "$out/nix-support"
            cat > "$out/nix-support/runtime-closure" <<'EOF'
            ${runtimeClosureManifest}
            EOF
          '';
        }
      ];

    meta = {
      description = "Image loading, transformation, and thumbnail library";
      homepage = "https://gitlab.gnome.org/GNOME/gdk-pixbuf";
      license = "LGPL-2.1-or-later";
    };
  }
