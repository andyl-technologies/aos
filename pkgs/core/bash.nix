##! GNU Bash — Bourne-Again SHell
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "5.3";
in
  mkDerivation {
    pname = "bash";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/bash/bash-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"
        "https://ftp.gnu.org/gnu/bash/bash-${version}.tar.gz"
      ];
      hash = "sha256-DVzYaWX4aaJs9k9Lcb57lvkKO6iz104n6OnZ1VUPMbo=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd bash-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --without-bash-malloc \
            --with-installed-readline \
            --disable-nls
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
          ln -sf bash $out/bin/sh
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-bash";
        tool = self;
        command = "bash --version";
      };

      scripting = testing.mkVMTest {
        name = "tool-bash-scripting";
        rootfsDeps = [self];
        testScript = ''
          # Test arrays, functions, string manipulation
          bash -c '
            # Arrays
            arr=(alpha beta gamma)
            test "''${#arr[@]}" -eq 3 || exit 1
            test "''${arr[1]}" = "beta" || exit 1

            # Functions
            add() { echo $(( $1 + $2 )); }
            test "$(add 3 7)" = "10" || exit 1

            # String manipulation
            str="hello-world"
            test "''${str//-/_}" = "hello_world" || exit 1

            # Loops
            sum=0
            for i in 1 2 3 4 5; do
              sum=$((sum + i))
            done
            test "$sum" -eq 15 || exit 1

            # Conditionals
            [[ "foobar" == foo* ]] || exit 1

            # Printf
            printf -v out "%05d" 42
            test "$out" = "00042" || exit 1
          '
          echo "==> bash scripting: passed"
        '';
      };

      source = testing.mkVMTest {
        name = "tool-bash-source";
        rootfsDeps = [self];
        testScript = ''
          cat > /tmp/library.sh << 'LIB'
          greet() { echo "hello $1"; }
          add() { echo $(( $1 + $2 )); }
          LIB

          cat > /tmp/main.sh << 'MAIN'
          #!/bin/bash
          source /tmp/library.sh
          GREET_RESULT=$(greet world)
          ADD_RESULT=$(add 17 25)
          test "$GREET_RESULT" = "hello world" || exit 1
          test "$ADD_RESULT" = "42" || exit 1
          MAIN
          chmod +x /tmp/main.sh

          bash /tmp/main.sh
          echo "==> bash source: passed"
        '';
      };
    };

    meta = {
      description = "GNU Bash — the Bourne-Again SHell";
      homepage = "https://www.gnu.org/software/bash/";
      license = "GPL-3.0-or-later";
    };
  }
