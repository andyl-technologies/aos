##! Glycin base C library and introspection bindings.
{
  mkDerivation,
  callPackage,
  buildPackages,
  stdenv,
  lib,
  rust,
  gobject-introspection,
  fontconfig,
  libseccomp,
  bubblewrap,
  coreutils,
  util-linux,
}: let
  sources = callPackage ./_glycin-sources.nix {};
  glib = callPackage ./_image-glib.nix {};
  rustTool =
    if stdenv.isCross
    then rust.passthru.buildTool
    else buildPackages.rust;
  buildCargoPrefix = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
  probeScript = ''
    import ctypes
    import sys

    library = ctypes.CDLL("@out@/lib/libglycin-2.so.0")
    has_alpha = library.gly_memory_format_has_alpha
    has_alpha.argtypes = [ctypes.c_int]
    has_alpha.restype = ctypes.c_int

    is_premultiplied = library.gly_memory_format_is_premultiplied
    is_premultiplied.argtypes = [ctypes.c_int]
    is_premultiplied.restype = ctypes.c_int

    if sys.argv[1] == "primary":
        assert has_alpha(5) == 1
        assert has_alpha(7) == 0
        assert is_premultiplied(2) == 1
        assert is_premultiplied(5) == 0
        print("classified image memory formats")
    elif sys.argv[1] == "bad-input":
        assert has_alpha(999) == 0
        assert is_premultiplied(999) == 0
        print("rejected unknown memory format")
    else:
        raise ValueError("unknown qualification operation")
  '';
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "libglycin";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "RGBA, premultiplied RGBA, and RGB memory-format values.";
        operation = "Classify alpha and premultiplication through the public C ABI.";
        expected = "The formats report their documented channel properties.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "primary"];
            exit_code = 0;
            stdout.exact = "classified image memory formats\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An undefined memory-format value.";
        operation = "Classify the unsupported value through both C ABI functions.";
        expected = "Both functions return false without aborting the calling process.";
        artifacts = [];
        files."probe.py" = probeScript;
        steps = [
          {
            argv = ["@python@" "probe.py" "bad-input"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "rejected unknown memory format\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit (sources) version src;
    passthru.evidenceSources = [sources.src sources.cargoDeps];

    buildDeps = [buildPackages.meson buildPackages.ninja rustTool buildPackages.pkg-config buildPackages.python3 buildPackages.gobject-introspection buildPackages.vala];
    runtimeDeps = [glib fontconfig libseccomp bubblewrap coreutils util-linux];
    # These libraries appear in the installed glycin-2.pc contract.
    propagatedDeps = [glib util-linux fontconfig libseccomp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd glycin-${sources.version}
          # Unknown C enum values must not abort across the Rust FFI boundary.
          patch --fuzz=0 -p1 < ${./libglycin-invalid-memory-format.patch}
          cp -R ${sources.cargoDeps} vendor
          chmod -R u+w vendor
          mkdir -p .cargo
          sed "s|@vendor@|$PWD/vendor|g" vendor/.cargo/config.toml > .cargo/config.toml
          # Bind sandbox helpers to the corresponding AOS runtime closure.
          # Update Cargo's per-file checksum after the reviewed source patch.
          ${buildPackages.python3}/bin/python3 - <<'PY'
          import hashlib
          import json
          from pathlib import Path

          crate = Path('vendor/source-registry-0/glycin-core-4.0.0')
          relative = 'src/sandbox.rs'
          source = crate / relative
          contents = source.read_text()
          assert 'Command::new("bwrap")' in contents
          assert 'PathBuf::from("/usr/bin/true")' in contents
          contents = contents.replace('Command::new("bwrap")', 'Command::new("${bubblewrap}/bin/bwrap")')
          contents = contents.replace('PathBuf::from("/usr/bin/true")', 'PathBuf::from("${coreutils}/bin/true")')
          # AOS libraries live in /nix/store; a source-build sandbox can lack
          # /usr entirely. Retain its read-only mount whenever it exists.
          usr_mount = '"--ro-bind",\n            "/usr",\n            "/usr",'
          assert usr_mount in contents
          contents = contents.replace(usr_mount, usr_mount.replace('"--ro-bind"', '"--ro-bind-try"'))
          source.write_text(contents)
          checksum = crate / '.cargo-checksum.json'
          manifest = json.loads(checksum.read_text())
          manifest['files'][relative] = hashlib.sha256(source.read_bytes()).hexdigest()
          checksum.write_text(json.dumps(manifest))
          PY
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_NET_OFFLINE=true
          export CARGO_BUILD_JOBS="$NIX_BUILD_CORES"
          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
          export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
          export XDG_DATA_DIRS="${glib}/share:${buildPackages.gobject-introspection}/share:${buildPackages.vala}/share"
          export RUSTFLAGS="-C linker=$CC -L native=${glib.dev}/lib"
          ${
            if stdenv.isCross
            then ''
              # Build scripts and proc macros are native executables. Clear
              # target search paths before invoking the native C linker.
              mkdir -p native-tools
              cat > native-tools/cc <<'EOF'
              #!${buildPackages.bash}/bin/bash
              unset AOS_CROSS_COMPILING AOS_GOARCH AOS_GOOS
              unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
              unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
              unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
              exec ${buildPackages.cc}/bin/cc "$@"
              EOF
              chmod +x native-tools/cc
              export CARGO_TARGET_${buildCargoPrefix}_LINKER="$PWD/native-tools/cc"
              # Rust executes on the builder with the target standard library.
              cat > rust-cross.ini <<EOF
              [binaries]
              rust = ['${rustTool}/bin/rustc', '--target=${stdenv.hostPlatform.config}']
              [properties]
              rust_target = '${stdenv.hostPlatform.config}'
              EOF
              mesonFlags="$mesonFlags --cross-file=$PWD/rust-cross.ini"
              export PKG_CONFIG_ALLOW_CROSS=1
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
          # Package the base ABI separately to break the loader/GDK dependency
          # cycle. Loaders, GTK bindings, and thumbnailer are separate components.
          meson setup build $mesonFlags --prefix="$out" --libdir=lib \
            -Dlibglycin=true -Dintrospection=true -Dvapi=true \
            -Dlibglycin-gtk4=false -Dglycin-loaders=false -Dglycin-thumbnailer=false
        '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
          mkdir -p "$out/share/licenses/libglycin"
          cp LICENSE* "$out/share/licenses/libglycin/"
          test -s "$out/share/gir-1.0/Gly-2.gir"
          test -s "$out/lib/girepository-1.0/Gly-2.typelib"
          test -s "$out/share/vala/vapi/glycin-2.vapi"
        '';
      }
    ];

    meta = {
      description = "Glycin base C library and introspection bindings";
      homepage = "https://gitlab.gnome.org/GNOME/glycin";
      license = "MPL-2.0 OR LGPL-2.1-or-later";
    };
  }
