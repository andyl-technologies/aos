##! fish — User-friendly interactive shell
{
  lib,
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
  version = "4.9.2";
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "fish";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Fish prints the selected field.";
        "files" = {};
        "input" = "A Fish program splitting a colon-delimited string.";
        "operation" = "Evaluate the program and select the second field.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/fish"
              "-c"
              "string split : alpha:beta:gamma | string match beta"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "beta\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Fish rejects the syntax error with status 127.";
        "files" = {};
        "input" = "A Fish program with an unterminated command substitution.";
        "operation" = "Parse the malformed Fish program without executing it.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/fish"
              "-n"
              "-c"
              "echo (string upper broken"
            ];
            "exit_code" = 127;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
