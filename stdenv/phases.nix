# stdenv/phases.nix — Build phase templates for common build systems
#
# Provides parameterized phase functions for:
#   autoconfPhases  — configure / make / make install
#   cmakePhases     — cmake -B build / cmake --build / cmake --install
#   mesonPhases     — meson setup / meson compile / meson install
#   goPhases        — go build
#   cargoPhases     — cargo build --release
#
# Each returns a list of { name; script; } records for mkDerivation's `phases`.
#
let
  unpackPhaseFor = {unpackMode ? "copy"}: let
    dirUnpack =
      if unpackMode == "copy"
      then ''
        cp -r "$src" source
        chmod -R u+w source
      ''
      else if unpackMode == "tar-pipe"
      then ''
        mkdir source
        (cd "$src" && tar cf - .) | (cd source && tar xf -)
        chmod -R u+w source
      ''
      else throw "stdenv/phases.nix: unsupported unpackMode '${unpackMode}'";
  in {
    name = "unpack";
    script = ''
      if [ -d "$src" ]; then
        ${dirUnpack}
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

  unpackPhase = unpackPhaseFor {};

  freezeAutotoolsTimestampsPhase = {
    name = "freeze-autotools-timestamps";
    script = ''
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      : "''${MAKEINFO:=true}"
      export MAKEINFO

      if [ -d doc ]; then
        find doc -type f -links +1 -exec "''${CONFIG_SHELL:-bash}" -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true
      fi

      # Touch autotools inputs first, generated C/header files next, then
      # configure and Makefile outputs. This keeps older tarballs from
      # regenerating with whichever autotools happen to be on PATH.
      find . -type f \( -name '*.y' -o -name '*.l' -o -name '*.gperf' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.hh' -o -name '*.hpp' -o -name '*-kw.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . \( -name '*.1' -o -name '*.info' \) -exec touch {} + 2>/dev/null || true
    '';
  };

  fixupPhase = {
    name = "fixup";
    script = ''
      # Strip debug info. --strip-unneeded on .so removes debug sections
      # (including DWARF .debug_line that embeds gcc include paths as
      # /nix/store/<hash>-gcc-stage2/...) while preserving the dynamic
      # symbol table needed for linking. -s on executables strips
      # everything. Without this, every compiled object drags the ~230 MB
      # gcc-stage2 into its runtime closure via Nix's reference scanner.
      if [ -z "''${dontStrip:-}" ]; then
        echo "stripping..."
        find "$out" -type f -name '*.so*' -exec strip --strip-unneeded {} \; 2>/dev/null || true
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

      # Patch shebangs
      if [ -z "''${dontPatchShebangs:-}" ]; then
        echo "patching shebangs..."
        find "$out" -type f -executable | while read f; do
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

      # Shrink ELF RPATHs
      if [ -z "''${dontPatchELF:-}" ] && command -v patchelf >/dev/null 2>&1; then
        echo "shrinking ELF RPATHs..."
        find "$out" -type f \( -name '*.so*' -o -perm -u+x \) | while read f; do
          patchelf --shrink-rpath "$f" 2>/dev/null || true
        done
      fi

      # Validate runpaths
      if [ -z "''${dontValidateRunpath:-}" ] && command -v patchelf >/dev/null 2>&1; then
        echo "validating ELF runpaths..."
        find "$out" -type f -perm -u+x | while read f; do
          file "$f" 2>/dev/null | grep -q ELF || continue
          needed=$(patchelf --print-needed "$f" 2>/dev/null) || continue
          rpath=$(patchelf --print-rpath "$f" 2>/dev/null) || continue
          for lib in $needed; do
            found=0
            _old_IFS="$IFS"
            IFS=':'
            for dir in $rpath; do
              if [ -f "$dir/$lib" ]; then
                found=1
                break
              fi
            done
            IFS="$_old_IFS"
            if [ "$found" = 0 ] && [ -f "$out/lib/$lib" ]; then
              found=1
            fi
            if [ "$found" = 0 ]; then
              echo "WARNING: $f needs $lib but it's not in RPATH"
            fi
          done
        done
      fi

      # Move docs
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
in rec {
  # GNU Autoconf (configure / make / make install)
  autoconfPhases = {
    doCheck ? true,
    checkTarget ? "check",
    unpackMode ? "copy",
    freezeAutotoolsTimestamps ? false,
  }:
    [
      (unpackPhaseFor {inherit unpackMode;})
    ]
    ++ (
      if freezeAutotoolsTimestamps
      then [freezeAutotoolsTimestampsPhase]
      else []
    )
    ++ [
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
      if doCheck
      then [
        {
          name = "check";
          script = ''
            make ${checkTarget} -j$NIX_BUILD_CORES
          '';
        }
      ]
      else []
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

  # CMake
  cmakePhases = {doCheck ? true}:
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
      if doCheck
      then [
        {
          name = "check";
          script = ''
            cd build && ctest --output-on-failure -j$NIX_BUILD_CORES
          '';
        }
      ]
      else []
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

  # Meson + Ninja
  mesonPhases = {
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
      if doCheck
      then [
        {
          name = "check";
          script = ''
            meson test -C build --no-rebuild ${mesonTestFlags}
          '';
        }
      ]
      else []
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

  # Go
  goPhases = {
    goModules ? null,
    goPackage ? ".",
    goOutput,
    cgoEnabled ? false,
    ldflags ? "-s -w",
    tags ? [],
    doCheck ? true,
    goTestFlags ? "./...",
    doParallelCheck ? true,
  }: let
    tagsFlag =
      if tags != []
      then "-tags ${builtins.concatStringsSep "," tags}"
      else "";
  in
    [
      unpackPhase
      {
        name = "configure";
        script =
          ''
            export GOPATH="$TMPDIR/go"
            export GOCACHE="$TMPDIR/go-cache"
            export GOFLAGS="-trimpath"
            export CGO_ENABLED=${
              if cgoEnabled
              then "1"
              else "0"
            }
            export GONOSUMDB="*"
            export GONOSUMCHECK="*"
            mkdir -p "$GOPATH" "$GOCACHE"

          ''
          + (
            if goModules != null
            then ''
              export GOPATH="${goModules}"
              export GOFLAGS="$GOFLAGS -mod=readonly"
              export GOPROXY=off
            ''
            else ''
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
      if doCheck
      then [
        {
          name = "check";
          script = ''
            go test \
              -v \
              ${
              if !doParallelCheck
              then "-p 1"
              else ""
            } \
              ${tagsFlag} \
              ${goTestFlags}
            go vet ${goTestFlags}
          '';
        }
      ]
      else []
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

  # Rust (Cargo)
  cargoPhases = {
    cargoDeps,
    cargoArtifacts ? null,
    cargoRoot ? ".",
    cargoEnv ? {},
    cargoBuildCommands ? [],
    installCargoArtifacts ? false,
    cargoArtifactContract ? {},
    cargoNextest ? null,
    nextestFlags ? "",
    cargoFlags ? "",
    buildType ? "release",
    checkType ? buildType,
    cargoTestFlags ? "",
    buildFeatures ? [],
    buildNoDefaultFeatures ? false,
    installBins ? true,
    installLibs ? false,
    doCheck ? true,
    doParallelCheck ? true,
    gitDeps ? [],
  }: let
    shellQuote = value: "'${builtins.replaceStrings ["'"] ["'\"'\"'"] (toString value)}'";
    cargoEnvExports = builtins.concatStringsSep "\n" (
      builtins.map
      (name: "export ${name}=${shellQuote cargoEnv.${name}}")
      (builtins.attrNames cargoEnv)
    );
    featuresFlag =
      if buildFeatures != []
      then "--features ${builtins.concatStringsSep "," buildFeatures}"
      else "";
    noDefaultFlag =
      if buildNoDefaultFeatures
      then "--no-default-features"
      else "";
    profileFlag =
      if buildType == "release"
      then "--release"
      else "";
    checkProfileFlag =
      if checkType == "release"
      then "--release"
      else "";

    gitSourceLines = builtins.concatStringsSep "" (
      builtins.map (
        dep: "printf '[source.\"git+${dep.url}\"]\\ngit = \"${dep.url}\"\\nreplace-with = \"vendored-sources\"\\n\\n' >> .cargo/config.toml\n"
      )
      gitDeps
    );
    defaultBuildCommand = "build ${profileFlag} --frozen --offline ${noDefaultFlag} ${featuresFlag} -j$NIX_BUILD_CORES ${cargoFlags}";
    effectiveBuildCommands =
      if cargoBuildCommands == []
      then [defaultBuildCommand]
      else cargoBuildCommands;
    loggedBuildCommands = builtins.concatStringsSep "\n" (
      builtins.map (command: ''
        cargo ${command} --message-format=json-render-diagnostics > "$cargoBuildLogPart"
        jq -r '.message.rendered // empty' "$cargoBuildLogPart" >&2
        cat "$cargoBuildLogPart" >> "$cargoBuildLog"
        cargoBuildLogPart="$cargoBuildLogPart.next"
      '')
      effectiveBuildCommands
    );
  in
    [
      unpackPhase
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export CARGO_INCREMENTAL=0
          ${cargoEnvExports}
          mkdir -p "$CARGO_HOME"
          mkdir -p .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            # fetchCargoVendor layout: .cargo/config.toml ships pre-baked with
            # @vendor@ placeholders for the absolute vendor directory.
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            # fetchCargoDeps layout: raw vendor dir, write config inline.
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' > .cargo/config.toml
              ${gitSourceLines}
          fi
          if [ "${cargoRoot}" != "." ]; then
            cd "${cargoRoot}"
          fi
          if [ -n "${
            if cargoArtifacts == null
            then ""
            else toString cargoArtifacts
          }" ]; then
            mkdir -p target
            tar xf "${
            if cargoArtifacts == null
            then "/dev/null"
            else "${cargoArtifacts}/target.tar"
          }" -C target
            chmod -R u+w target
            # Nix builders reuse /build/source and normalize source mtimes.
            # Without an explicit freshness boundary Cargo can mistake dummy
            # first-party units for the real source. Force workspace targets
            # dirty while leaving restored registry dependencies reusable.
            find . -path ./target -prune -o -type f -name '*.rs' -exec touch {} +
          fi
        '';
      }
      {
        name = "build";
        script = ''
          cargoBuildLog="$NIX_BUILD_TOP/cargo-build-messages.jsonl"
          cargoBuildLogPart="$cargoBuildLog.part"
          : > "$cargoBuildLog"
          ${loggedBuildCommands}
        '';
      }
    ]
    ++ (
      if doCheck
      then [
        {
          name = "check";
          script = ''
            ${
              if cargoNextest != null
              then ''
                cargo nextest run \
                  ${
                  if checkType == "release"
                  then "--cargo-profile release"
                  else ""
                } \
                  --frozen \
                  --offline \
                  ${noDefaultFlag} \
                  ${featuresFlag} \
                  ${cargoTestFlags} \
                  ${nextestFlags}
              ''
              else ''
                cargo test \
                  ${checkProfileFlag} \
                  --frozen \
                  --offline \
                  ${
                  if !doParallelCheck
                  then "-- --test-threads=1"
                  else ""
                } \
                  ${cargoTestFlags}
              ''
            }
          '';
        }
      ]
      else []
    )
    ++ [
      {
        name = "install";
        script =
          (
            if installCargoArtifacts
            then ''
              mkdir -p "$out"
              tar cf "$out/target.tar" -C target .
              cp "$NIX_BUILD_TOP/cargo-build-messages.jsonl" "$out/build-messages.jsonl"
              printf '%s\n' '${builtins.toJSON cargoArtifactContract}' > "$out/contract.json"
            ''
            else ""
          )
          + (
            if !installCargoArtifacts
            then ''
              mkdir -p "$out/nix-support"
              # Keep the useful compiler-artifact/freshness evidence without
              # turning diagnostic source paths into runtime Nix references.
              # `walk` also covers future Cargo message fields instead of
              # relying on a brittle list of currently path-bearing keys.
              jq -c '
                walk(
                  if type == "string"
                  then gsub("/nix/store/[0-9a-z]{32}-[^/[:space:]]+"; "/nix/store/00000000000000000000000000000000-redacted")
                  else .
                  end
                )
              ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" \
                > "$out/nix-support/cargo-build-messages.jsonl"
            ''
            else ""
          )
          + (
            if installBins
            then ''
              mkdir -p "$out/bin"
              jq -r 'select(.reason == "compiler-artifact") | .executable // empty' \
                "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u | while read bin; do
                test -n "$bin" || continue
                install -m 755 "$bin" "$out/bin/"
              done
            ''
            else ""
          )
          + (
            if installLibs
            then ''
              mkdir -p "$out/lib"
              jq -r 'select(.reason == "compiler-artifact") | .filenames[]? | select(endswith(".so") or endswith(".a") or endswith(".dylib"))' \
                "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u | while read lib; do
                install -m 644 "$lib" "$out/lib/"
              done
            ''
            else ""
          );
      }
      fixupPhase
    ];

  # Python (setuptools / PEP 517)
  pythonPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
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

  defaultPhases = autoconfPhases {};

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

  kernelPhases = [
    unpackPhase
    {
      name = "configure";
      script = ''
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
        cp arch/x86/boot/bzImage "$out/boot/vmlinuz"
        cp System.map "$out/boot/System.map"
        cp .config "$out/boot/config"
      '';
    }
  ];

  # Bazel (two-phase: fetchBazelDeps FOD + offline build)
  #
  # Returns phases that unpack deps from a fetchBazelDeps FOD, patchelf
  # downloaded ELF binaries, restore scrubbed store paths, and run
  # `bazel build` offline with --repository_disable_download.
  bazelPhases = {
    # Result of fetchBazelDeps (directory containing external/ subtree)
    bazelDeps,
    # Bazel package to use
    bazel,
    # Java runtime
    jdk,
    # Packages for PATH (same list used in fetchBazelDeps)
    tools,
    # ccWrapper (provides nix-support/dynamic-linker)
    bootstrapTools,
    # For patchelfing downloaded ELF binaries
    patchelf,
    # Bash package (for wrapper script)
    bash,
    # CA cert bundle (optional)
    caCertificates ? null,
    # Build target (e.g. "//source/exe:envoy-static")
    bazelTarget,
    # Common bazel flags (shared with fetch)
    bazelFlags ? [],
    # Build-specific flags (e.g. "-c opt", "--config=gcc")
    bazelBuildFlags ? [],
    # Store path scrubbing map (same as fetchBazelDeps, used for restoration)
    scrubMap ? {},
    # Pre-build setup script
    preBuild ? "",
    # Install script (required — no reasonable default for Bazel outputs)
    installPhase,
  }: let
    toolsPath = builtins.concatStringsSep ":" (
      builtins.map (d: "${builtins.toString d}/bin") tools
    );
    flagsStr = builtins.concatStringsSep " " bazelFlags;
    buildFlagsStr = builtins.concatStringsSep " " bazelBuildFlags;
    restoreSedArgs = builtins.concatStringsSep " " (
      builtins.attrValues (
        builtins.mapAttrs (
          path: placeholder: "-e 's|${placeholder}|${path}|g'"
        )
        scrubMap
      )
    );
  in [
    unpackPhase
    {
      name = "configure";
      script = ''
        # Unpack deps from FOD
        bazelOut="$TMPDIR/output"
        mkdir -p "$bazelOut"
        cp -a ${bazelDeps} "$bazelOut/external"
        chmod -R +w "$bazelOut"

        # Restore symlinks that reference the placeholder paths from fetchBazelDeps
        find "$bazelOut/external" -type l | while read symlink; do
          target="$(readlink "$symlink")"
          case "$target" in
            *__BAZEL_SRCDIR__*|*__BAZEL_TMPDIR__*)
              new="$(echo "$target" | sed -e "s,__BAZEL_SRCDIR__,$PWD,g" -e "s,__BAZEL_TMPDIR__,$TMPDIR,g")"
              rm "$symlink"
              ln -sf "$new" "$symlink"
              ;;
          esac
        done

        # Patchelf dynamically-linked ELF binaries from upstream
        INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
        BT_LIB=$(dirname "$INTERP")
        find "$bazelOut/external" -type f -executable | while read execbin; do
          interp=$(${patchelf}/bin/patchelf --print-interpreter "$execbin" 2>/dev/null) || continue
          case "$interp" in
            */lib64/ld-linux*|*/lib/ld-linux*)
              ${patchelf}/bin/patchelf --set-interpreter "$INTERP" --set-rpath "$BT_LIB" \
                "$execbin" 2>/dev/null || true
              ;;
          esac
        done

        ${
          if scrubMap != {}
          then ''
            # Restore store paths from placeholders
            find "$bazelOut/external" -type f | while read f; do
              sed -i ${restoreSedArgs} "$f" 2>/dev/null || true
            done
          ''
          else ""
        }

        # Configure .bazelrc for offline build
        echo "common --repository_cache=\"$bazelOut/external/repository_cache\"" >> .bazelrc
        echo "common --repository_disable_download" >> .bazelrc

        # Generate --override_repository for all repos in the deps
        # Copy repos outside output_base to avoid Bazel cycles
        mkdir -p "$TMPDIR/repo-overrides"
        for repo in "$bazelOut/external"/*/; do
          repo_name="$(basename "$repo")"
          case "$repo_name" in
            repository_cache) continue ;;
          esac
          cp -a "$repo" "$TMPDIR/repo-overrides/$repo_name"
          chmod -R u+rwx "$TMPDIR/repo-overrides/$repo_name"
          echo "common --override_repository=$repo_name=$TMPDIR/repo-overrides/$repo_name" >> .bazelrc
        done
      '';
    }
    {
      name = "build";
      script = ''
                  # Set up environment
                  INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
                  BT_LIB=$(dirname "$INTERP")
                  mkdir -p "$TMPDIR/rust-link-libs"
                  for compat_lib in util:1 rt:1 dl:2 pthread:0; do
                    compat_name="''${compat_lib%%:*}"
                    compat_soname="''${compat_lib##*:}"
                    if [ -e "$BT_LIB/lib$compat_name.so.$compat_soname" ]; then
                      ln -sf "$BT_LIB/lib$compat_name.so.$compat_soname" "$TMPDIR/rust-link-libs/lib$compat_name.so"
                    fi
                  done
                  export CARGO_BUILD_RUSTFLAGS="-Lnative=$TMPDIR/rust-link-libs -Lnative=$BT_LIB -C link-arg=-Wl,-dynamic-linker,$INTERP -C link-arg=-Wl,-rpath,$BT_LIB"
                  echo "build --linkopt=-L$TMPDIR/rust-link-libs" >> .bazelrc
                  echo "build --host_linkopt=-L$TMPDIR/rust-link-libs" >> .bazelrc

                  # Create bash wrapper with PATH for genrules
                  mkdir -p $TMPDIR/bazel-tools
                  cat > $TMPDIR/bazel-tools/bash-with-path << BASHWRAP
        #!${bash}/bin/bash
        export PATH="${toolsPath}:\$PATH"
        export LD_LIBRARY_PATH="$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
        exec ${bash}/bin/bash "\$@"
        BASHWRAP
                  chmod +x $TMPDIR/bazel-tools/bash-with-path

                  export HOME="$TMPDIR/bazel-home"
                  mkdir -p "$HOME"
                  export JAVA_HOME="${jdk}"
                  ${
          if caCertificates != null
          then ''export SSL_CERT_FILE="${caCertificates}/etc/ssl/certs/ca-certificates.crt"''
          else ""
        }
                  export PATH="${toolsPath}:${jdk}/bin:${bazel}/bin:$PATH"
                  export CMAKE_POLICY_VERSION_MINIMUM=3.5

                  # Unset C_INCLUDE_PATH to prevent #include_next breakage
                  unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH

                  ${preBuild}

                  BAZEL_USE_CPP_ONLY_TOOLCHAIN=1 \
                  USER=nix \
                  bazel --batch \
                    --output_base="$TMPDIR/output" \
                    --output_user_root="$TMPDIR/tmp" \
                    --server_javabase="${jdk}" \
                    build ${bazelTarget} \
                    --curses=no \
                    --verbose_failures \
                    --jobs $NIX_BUILD_CORES \
                    ${flagsStr} \
                    ${buildFlagsStr} \
                    --action_env=PATH=${toolsPath} \
                    --host_action_env=PATH=${toolsPath} \
                    --action_env=LD_LIBRARY_PATH=$BT_LIB \
                    --host_action_env=LD_LIBRARY_PATH=$BT_LIB \
                    --shell_executable=$TMPDIR/bazel-tools/bash-with-path
      '';
    }
    {
      name = "install";
      script = installPhase;
    }
    fixupPhase
  ];
}
