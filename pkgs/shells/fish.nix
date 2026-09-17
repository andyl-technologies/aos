##! fish — User-friendly interactive shell
{
  mkDerivation,
  fetchurl,
  fetchCargoDeps,
  lib,
  stdenv,
  buildPackages,
  rust,
  cmake,
  ninja,
  gettext,
  pkg-config,
  python3,
  pcre2,
  ncurses,
  coreutils,
  grep,
  sed,
  gawk,
  procps-ng,
  getent,
}: let
  version = "4.9.2";

  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  nativeCargoTarget = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
  rustForBuild =
    if isLinuxCross
    then rust.passthru.buildTool
    else rust;
  crossRustCmakeFlags = lib.optionalString isLinuxCross (
    lib.concatMapStrings (flag: " " + flag) [
      "-DRust_COMPILER=${rustForBuild}/bin/rustc"
      "-DRust_CARGO=${rustForBuild}/bin/cargo"
      "-DRust_CARGO_TARGET=${stdenv.hostPlatform.config}"
    ]
  );

  src = fetchurl {
    urls = ["https://github.com/fish-shell/fish-shell/releases/download/${version}/fish-${version}.tar.xz"];
    hash = "sha256-JrlXac4XqJYrIguj8gdxEX2/6cssO6b07ROeDL/fArE=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-BHPHlOJ4y0YcwAJT7ZPp9KCFpS4ts6WlkHpUcnxZqEg=";
  };
in
  mkDerivation {
    pname = "fish";
    inherit version src;

    buildDeps =
      [rust cmake ninja gettext pkg-config python3]
      ++ lib.optionals isLinuxCross [rustForBuild];
    runtimeDeps = [
      pcre2
      ncurses
      coreutils
      grep
      sed
      gawk
      gettext
      procps-ng
      getent
    ];
    propagatedDeps = [];
    disallowedReferences = [cargoDeps rust];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd fish-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i "s|/usr/bin/e|${coreutils}/bin/e|" src/highlight/highlight.rs
          sed -i "s|/usr/bin|${coreutils}/bin|" tests/checks/vars_as_commands.fish
          sed -i "s|ps -o|${procps-ng}/bin/ps -o|" tests/checks/jobs.fish

          sed -i "s|command grep|command ${grep}/bin/grep|g" share/functions/grep.fish
          for file in share/functions/*.fish share/completions/*.fish; do
            sed -i \
              -e "s|/usr/bin/getent|${getent}/bin/getent|g" \
              -e "s|command awk|command ${gawk}/bin/awk|g" \
              -e "s|[^/]awk |${gawk}/bin/awk |g" \
              "$file"
          done

          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" build_tools/git_version_gen.sh
          sed -i "1s|^#!.*|#!${python3}/bin/python3|" tests/test_driver.py
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export CARGO_INCREMENTAL=0
          mkdir -p "$CARGO_HOME" .cargo
          cat > .cargo/config.toml <<EOF
          [source.crates-io]
          replace-with = "vendored-sources"

          [source."git+https://github.com/fish-shell/rust-pcre2?tag=0.2.9-utf32"]
          git = "https://github.com/fish-shell/rust-pcre2"
          tag = "0.2.9-utf32"
          replace-with = "vendored-sources"

          [source."git+https://github.com/danielrainer/fluent-rs?rev=cf712bced280b217b6307edabc2089b3e57204ab"]
          git = "https://github.com/danielrainer/fluent-rs"
          rev = "cf712bced280b217b6307edabc2089b3e57204ab"
          replace-with = "vendored-sources"

          [source."git+https://codeberg.org/danielrainer/fluent-ftl-tools?rev=5917664c8f2e4928ef1e480ff5c13bbe1e226066"]
          git = "https://codeberg.org/danielrainer/fluent-ftl-tools"
          rev = "5917664c8f2e4928ef1e480ff5c13bbe1e226066"
          replace-with = "vendored-sources"

          [source.vendored-sources]
          directory = "${cargoDeps}"

          [net]
          offline = true
          EOF

          ${lib.optionalString isLinuxCross ''
            # Cargo runs build scripts on the builder. Their linker must not
            # inherit the target compiler's headers, libraries, or hardening.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<'EOF'
            #!${buildPackages.bash}/bin/bash
            unset AOS_CROSS_COMPILING AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_GOARCH AOS_GOOS
            unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
            unset LIBRARY_PATH NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
            exec ${buildPackages.cc}/bin/cc "$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export CARGO_TARGET_${nativeCargoTarget}_LINKER="$PWD/.aos-build-tools/cc-for-build"
          ''}cmake -S . -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_INSTALL_DOCDIR="$out/share/doc/fish"${crossRustCmakeFlags}
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
          cat >> "$out/etc/fish/config.fish" <<'EOF'
          if test -f /etc/fish/config.fish; and test /etc/fish/config.fish != (status filename)
              source /etc/fish/config.fish
          end
          EOF
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-fish";
        tool = self;
        command = "fish --version && fish -c 'test (math 2 + 2) -eq 4'";
      };
    };

    meta = {
      description = "Smart and user-friendly command-line shell";
      homepage = "https://fishshell.com/";
      license = "GPL-2.0-only";
      mainProgram = "fish";
    };
  }
