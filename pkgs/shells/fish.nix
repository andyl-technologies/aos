##! fish — User-friendly interactive shell
{
  mkDerivation,
  fetchurl,
  fetchCargoDeps,
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
  version = "4.7.1";
  src = fetchurl {
    urls = ["https://github.com/fish-shell/fish-shell/releases/download/${version}/fish-${version}.tar.xz"];
    hash = "sha256-b01bQ4pjOOP13NoZooJh4uznqbf/l2hmhear3DHbt98=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-pCaaYkpolNTQIrc6q7QVbc16PiU9tuAlOLxb/ykLW2s=";
  };
in
  mkDerivation {
    pname = "fish";
    inherit version src;

    buildDeps = [rust cmake ninja gettext pkg-config python3];
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

          [source.vendored-sources]
          directory = "${cargoDeps}"

          [net]
          offline = true
          EOF

          cmake -S . -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_INSTALL_DOCDIR="$out/share/doc/fish"
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
