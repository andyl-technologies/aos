# stdenv/phases.nix — Build phase templates for common build systems
#
# Provides pre-built phase lists for:
#   autoconfPhases  — configure / make / make install
#   cmakePhases     — cmake -B build / cmake --build / cmake --install
#   mesonPhases     — meson setup / meson compile / meson install
#   goPhases        — go build
#   cargoPhases     — cargo build --release
#
# Each is a list of { name :: string; script :: string; } records,
# compatible with mkDerivation's `phases` parameter.
#
# Usage:
#   stdenv.mkDerivation {
#     phases = phases.cmakePhases;
#     ...
#   };
#
# Available pre/post hooks (set in mkDerivation):
#   preConfigure  — runs before the configure phase
#   postConfigure — runs after the configure phase
#   preBuild      — runs before the build phase
#   postBuild     — runs after the build phase
#   preInstall    — runs before the install phase
#   postInstall   — runs after the install phase
#

let
  # Shared unpack phase used by all build systems
  unpackPhase = {
    name = "unpack";
    script = ''
      if [ -d "$src" ]; then
        cp -r "$src" source
        chmod -R u+w source
      elif [ -f "$src" ]; then
        case "$src" in
          *.tar.gz|*.tgz)   tar xzf "$src" ;;
          *.tar.bz2|*.tbz2) tar xjf "$src" ;;
          *.tar.xz|*.txz)   tar xJf "$src" ;;
          *.tar.zst)         tar --zstd -xf "$src" ;;
          *.tar)             tar xf "$src" ;;
          *.zip)             unzip "$src" ;;
          *)                 echo "Unknown archive format: $src"; exit 1 ;;
        esac
      else
        echo "Source not found: $src"
        exit 1
      fi

      # Enter the source directory
      if [ -d source ]; then
        cd source
      else
        dirs=( */ )
        if [ "''${#dirs[@]}" -eq 1 ]; then
          cd "''${dirs[0]}"
        fi
      fi
    '';
  };

  # Shared fixup phase
  fixupPhase = {
    name = "fixup";
    script = ''
      # Run fixup (stripping, patching shebangs, etc.)
      if type _fixupPhase &>/dev/null; then
        _fixupPhase
      fi
    '';
  };

in
rec {
  # ---------------------------------------------------------------------------
  # GNU Autoconf (configure / make / make install)
  # ---------------------------------------------------------------------------
  autoconfPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        if [ -x configure ]; then
          ./configure \
            --prefix="$out" \
            $configureFlags
        elif [ -x autogen.sh ]; then
          ./autogen.sh
          ./configure \
            --prefix="$out" \
            $configureFlags
        else
          echo "No configure script found"
          exit 1
        fi
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES $makeFlags
      '';
    }
    {
      name = "install";
      script = ''
        make install DESTDIR="" $installFlags
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # CMake
  # ---------------------------------------------------------------------------
  cmakePhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        cmake -B build \
          -DCMAKE_INSTALL_PREFIX="$out" \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DCMAKE_C_FLAGS="-O2 -pipe" \
          -DCMAKE_CXX_FLAGS="-O2 -pipe" \
          $cmakeFlags
      '';
    }
    {
      name = "build";
      script = ''
        cmake --build build -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        cmake --install build
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # Meson + Ninja
  # ---------------------------------------------------------------------------
  mesonPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        meson setup build \
          --prefix="$out" \
          --buildtype=release \
          --libdir=lib \
          -Ddefault_library=both \
          $mesonFlags
      '';
    }
    {
      name = "build";
      script = ''
        meson compile -C build -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        meson install -C build --no-rebuild
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # Go
  # ---------------------------------------------------------------------------
  goPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        # Set up Go environment
        export GOPATH="$TMPDIR/go"
        export GOCACHE="$TMPDIR/go-cache"
        export GOFLAGS="-trimpath"
        mkdir -p "$GOPATH" "$GOCACHE"
      '';
    }
    {
      name = "build";
      script = ''
        # Build Go binary
        # Default: build the main package in the current directory
        go build \
          -ldflags "-s -w -X main.version=''${version:-unknown}" \
          -o "''${goOutput:-$pname}" \
          ''${goPackage:-.}
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        install -m 755 "''${goOutput:-$pname}" "$out/bin/"
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # Rust (Cargo)
  # ---------------------------------------------------------------------------
  cargoPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
                # Set up Cargo environment
                export CARGO_HOME="$TMPDIR/cargo"
                mkdir -p "$CARGO_HOME"

                # Use vendored dependencies if available
                if [ -d vendor ]; then
                  mkdir -p .cargo
                  cat > .cargo/config.toml << 'CARGO_CONF'
        [source.crates-io]
        replace-with = "vendored-sources"

        [source.vendored-sources]
        directory = "vendor"
        CARGO_CONF
                fi
      '';
    }
    {
      name = "build";
      script = ''
        cargo build \
          --release \
          --frozen \
          -j$NIX_BUILD_CORES \
          $cargoFlags
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"

        # Install all binaries from the release directory
        for bin in target/release/*; do
          if [ -f "$bin" ] && [ -x "$bin" ] && ! [[ "$bin" == *.d ]]; then
            # Skip .d files and non-executables
            case "$(file "$bin")" in
              *ELF*) install -m 755 "$bin" "$out/bin/" ;;
            esac
          fi
        done
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # Python (setuptools / PEP 517)
  # ---------------------------------------------------------------------------
  pythonPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        # Set up Python environment
        export PYTHONDONTWRITEBYTECODE=1
      '';
    }
    {
      name = "build";
      script = ''
        if [ -f pyproject.toml ]; then
          python3 -m build --no-isolation --wheel
        elif [ -f setup.py ]; then
          python3 setup.py build
        fi
      '';
    }
    {
      name = "install";
      script = ''
        if [ -f pyproject.toml ]; then
          python3 -m installer --destdir="$out" dist/*.whl
        elif [ -f setup.py ]; then
          python3 setup.py install --prefix="$out" --optimize=1
        fi
      '';
    }
    fixupPhase
  ];

  # ---------------------------------------------------------------------------
  # Convenience: get the default phases (autoconf)
  # ---------------------------------------------------------------------------
  defaultPhases = autoconfPhases;

  # ---------------------------------------------------------------------------
  # Phase helper: create a simple "copy-only" phase list for pre-built binaries
  # ---------------------------------------------------------------------------
  copyPhases = [
    unpackPhase
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp -r . "$out/"
      '';
    }
  ];

  # ---------------------------------------------------------------------------
  # Phase helper: kernel-style build (make with ARCH, make modules_install, etc.)
  # ---------------------------------------------------------------------------
  kernelPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
        # TODO: kernel configuration
        # make defconfig or use a provided .config
        if [ -f "$kernelConfig" ]; then
          cp "$kernelConfig" .config
        else
          make defconfig ARCH=x86
        fi
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES \
          ARCH=x86 \
          bzImage modules \
          $makeFlags
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/boot" "$out/lib/modules"
        make modules_install \
          INSTALL_MOD_PATH="$out" \
          ARCH=x86

        # Install kernel image
        cp arch/x86/boot/bzImage "$out/boot/vmlinuz"
        cp System.map "$out/boot/System.map"
        cp .config "$out/boot/config"
      '';
    }
  ];
}
