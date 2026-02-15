# stdenv/phases.nix — Build phase templates for common build systems
#
# Provides parameterized phase functions for:
#   autoconfPhases  — configure / make / make install
#   cmakePhases     — cmake -B build / cmake --build / cmake --install
#   mesonPhases     — meson setup / meson compile / meson install
#   goPhases        — go build
#   cargoPhases     — cargo build --release
#
# Each is a function returning a list of { name :: string; script :: string; }
# records, compatible with mkDerivation's `phases` parameter.
#
# Usage:
#   stdenv.mkDerivation {
#     phases = phases.cmakePhases {};
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
        ndirs=$(ls -d */ 2>/dev/null | wc -l)
        if [ "$ndirs" -eq 1 ]; then
          cd "$(ls -d */)"
        fi
      fi
    '';
  };

  # Shared fixup phase — strip, patchShebangs, patchELF, validate-runpath, moveDocs
  fixupPhase = {
    name = "fixup";
    script = ''
      # --- Strip debug symbols ---
      if [ -z "''${dontStrip:-}" ]; then
        echo "stripping debug symbols..."
        find "$out" -type f -name '*.so*' -exec strip -S {} \; 2>/dev/null || true
        find "$out" -type f -name '*.a' -exec strip -S {} \; 2>/dev/null || true
        if [ -d "$out/bin" ]; then
          find "$out/bin" -type f -exec strip -s {} \; 2>/dev/null || true
        fi
        if [ -d "$out/sbin" ]; then
          find "$out/sbin" -type f -exec strip -s {} \; 2>/dev/null || true
        fi
        if [ -d "$out/libexec" ]; then
          find "$out/libexec" -type f -exec strip -s {} \; 2>/dev/null || true
        fi
      fi

      # --- Patch shebangs ---
      if [ -z "''${dontPatchShebangs:-}" ]; then
        echo "patching shebangs..."
        find "$out" -type f -executable | while read f; do
          # Read first two bytes to check for #!
          header=$(dd if="$f" bs=1 count=2 2>/dev/null) || continue
          case "$header" in
            '#!') ;;
            *) continue ;;
          esac
          interp=$(head -1 "$f" | sed 's/^#! *//' | sed 's/ .*//')
          case "$interp" in
            /usr/bin/env)
              prog=$(head -1 "$f" | sed 's|^#! */usr/bin/env  *||' | sed 's/ .*//')
              abs=$(command -v "$prog" 2>/dev/null || true)
              if [ -n "$abs" ]; then
                sed -i "1s|.*|#!$abs|" "$f"
              fi
              ;;
            /usr/bin/*|/bin/*|/usr/local/bin/*)
              prog=$(basename "$interp")
              abs=$(command -v "$prog" 2>/dev/null || true)
              if [ -n "$abs" ]; then
                sed -i "1s|.*|#!$abs|" "$f"
              fi
              ;;
          esac
        done
      fi

      # --- Patch ELF RPATH ---
      if [ -z "''${dontPatchELF:-}" ] && command -v patchelf >/dev/null 2>&1; then
        echo "shrinking ELF RPATHs..."
        find "$out" -type f \( -name '*.so*' -o -perm -u+x \) | while read f; do
          patchelf --shrink-rpath "$f" 2>/dev/null || true
        done
      fi

      # --- Validate runpath ---
      if [ -z "''${dontValidateRunpath:-}" ] && command -v patchelf >/dev/null 2>&1; then
        echo "validating ELF runpaths..."
        find "$out" -type f -perm -u+x | while read f; do
          file "$f" 2>/dev/null | grep -q ELF || continue
          needed=$(patchelf --print-needed "$f" 2>/dev/null) || continue
          rpath=$(patchelf --print-rpath "$f" 2>/dev/null) || continue
          for lib in $needed; do
            found=0
            # Check each rpath directory (colon-separated)
            _old_IFS="$IFS"
            IFS=':'
            for dir in $rpath; do
              if [ -f "$dir/$lib" ]; then
                found=1
                break
              fi
            done
            IFS="$_old_IFS"
            # Also check $out/lib
            if [ "$found" = 0 ] && [ -f "$out/lib/$lib" ]; then
              found=1
            fi
            if [ "$found" = 0 ]; then
              echo "WARNING: $f needs $lib but it's not in RPATH"
            fi
          done
        done
      fi

      # --- Move docs ---
      if [ -z "''${dontMoveDocs:-}" ]; then
        for d in man doc info; do
          if [ -d "$out/$d" ]; then
            mkdir -p "$out/share"
            mv "$out/$d" "$out/share/"
          fi
        done
      fi
    '';
  };

in
rec {
  # ---------------------------------------------------------------------------
  # GNU Autoconf (configure / make / make install)
  # ---------------------------------------------------------------------------
  autoconfPhases =
    {
      doCheck ? true,
      checkTarget ? "check",
    }:
    [
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
    ]
    ++ (
      if doCheck then
        [
          {
            name = "check";
            script = ''
              make ${checkTarget} -j$NIX_BUILD_CORES
            '';
          }
        ]
      else
        [ ]
    )
    ++ [
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
  cmakePhases =
    {
      doCheck ? true,
    }:
    [
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
    ]
    ++ (
      if doCheck then
        [
          {
            name = "check";
            script = ''
              cd build && ctest --output-on-failure -j$NIX_BUILD_CORES
            '';
          }
        ]
      else
        [ ]
    )
    ++ [
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
  mesonPhases =
    {
      doCheck ? true,
      mesonTestFlags ? "",
    }:
    [
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
    ]
    ++ (
      if doCheck then
        [
          {
            name = "check";
            script = ''
              meson test -C build --no-rebuild ${mesonTestFlags}
            '';
          }
        ]
      else
        [ ]
    )
    ++ [
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
  goPhases =
    {
      goModules ? null,
      goPackage ? ".",
      goOutput,
      cgoEnabled ? false,
      ldflags ? "-s -w",
      tags ? [ ],
      doCheck ? true,
      goTestFlags ? "./...",
      doParallelCheck ? true,
    }:
    let
      tagsFlag = if tags != [ ] then "-tags ${builtins.concatStringsSep "," tags}" else "";
    in
    [
      unpackPhase
      {
        name = "configure";
        script = ''
          export GOPATH="$TMPDIR/go"
          export GOCACHE="$TMPDIR/go-cache"
          export GOFLAGS="-trimpath"
          export CGO_ENABLED=${if cgoEnabled then "1" else "0"}
          export GONOSUMDB="*"
          export GONOSUMCHECK="*"
          mkdir -p "$GOPATH" "$GOCACHE"

        ''
        + (
          if goModules != null then
            ''
              # Use pre-fetched modules
              export GOPATH="${goModules}"
              export GOFLAGS="$GOFLAGS -mod=readonly"
              export GOPROXY=off
            ''
          else
            ''
              # Use vendored deps from source if available
              if [ -d vendor ]; then
                export GOFLAGS="$GOFLAGS -mod=vendor"
                export GOPROXY=off
              else
                export GOPROXY="https://proxy.golang.org,direct"
              fi
            ''
        );
      }
      {
        name = "build";
        script = ''
          go build \
            -ldflags "${ldflags}" \
            ${tagsFlag} \
            -o "${goOutput}" \
            ${goPackage}
        '';
      }
    ]
    ++ (
      if doCheck then
        [
          {
            name = "check";
            script = ''
              go test \
                -v \
                ${if !doParallelCheck then "-p 1" else ""} \
                ${tagsFlag} \
                ${goTestFlags}
              go vet ${goTestFlags}
            '';
          }
        ]
      else
        [ ]
    )
    ++ [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 755 "${goOutput}" "$out/bin/"
        '';
      }
      fixupPhase
    ];

  # ---------------------------------------------------------------------------
  # Rust (Cargo)
  # ---------------------------------------------------------------------------
  cargoPhases =
    {
      cargoDeps,
      cargoFlags ? "",
      buildType ? "release",
      checkType ? buildType,
      cargoTestFlags ? "",
      buildFeatures ? [ ],
      buildNoDefaultFeatures ? false,
      installBins ? true,
      installLibs ? false,
      doCheck ? true,
      doParallelCheck ? true,
    }:
    let
      featuresFlag =
        if buildFeatures != [ ] then "--features ${builtins.concatStringsSep "," buildFeatures}" else "";
      noDefaultFlag = if buildNoDefaultFeatures then "--no-default-features" else "";
      profileFlag = if buildType == "release" then "--release" else "";
      checkProfileFlag = if checkType == "release" then "--release" else "";
    in
    [
      unpackPhase
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME"

          # Point cargo at vendored deps
          mkdir -p .cargo
          cat > .cargo/config.toml << 'EOF'
          [source.crates-io]
          replace-with = "vendored-sources"

          [source.vendored-sources]
          directory = "${cargoDeps}"
          EOF
        '';
      }
      {
        name = "build";
        script = ''
          cargo build \
            ${profileFlag} \
            --frozen \
            --offline \
            ${noDefaultFlag} \
            ${featuresFlag} \
            -j$NIX_BUILD_CORES \
            ${cargoFlags}
        '';
      }
    ]
    ++ (
      if doCheck then
        [
          {
            name = "check";
            script = ''
              cargo test \
                ${checkProfileFlag} \
                --frozen \
                --offline \
                ${if !doParallelCheck then "-- --test-threads=1" else ""} \
                ${cargoTestFlags}
            '';
          }
        ]
      else
        [ ]
    )
    ++ [
      {
        name = "install";
        script =
          (
            if installBins then
              ''
                mkdir -p "$out/bin"
                find target/${buildType} -maxdepth 1 -type f -executable \
                  ! -name '*.d' | while read bin; do
                  file "$bin" 2>/dev/null | grep -q ELF && install -m 755 "$bin" "$out/bin/" || true
                done
              ''
            else
              ""
          )
          + (
            if installLibs then
              ''
                mkdir -p "$out/lib"
                find target/${buildType} -maxdepth 1 \
                  \( -name '*.so' -o -name '*.a' -o -name '*.dylib' \) | while read lib; do
                  install -m 644 "$lib" "$out/lib/"
                done
              ''
            else
              ""
          );
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
  # Convenience: get the default phases (autoconf with defaults)
  # ---------------------------------------------------------------------------
  defaultPhases = autoconfPhases { };

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
