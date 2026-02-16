##! GNU Coreutils — Basic file, shell, and text utilities
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
}:

let
  version = "9.5";
in
mkDerivation {
  pname = "coreutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/coreutils/coreutils-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/coreutils/coreutils-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/coreutils/coreutils-${version}.tar.xz"
    ];
    hash = "sha256-zTKO3qyS9qZl3p8yPJO3Eq8YWLwuDYjz9xAEaUcKG4o=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd coreutils-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-gmp \
          --with-openssl \
          --disable-nls \
          --enable-no-install-program=groups,hostname,kill,uptime
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
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      sort = testing.mkFirecrackerTest {
        pname = "tool-coreutils-sort";
        rootfsDeps = [ self ];
        testScript = ''
          printf '3\n1\n2\n' > /tmp/nums.txt
          RESULT=$(sort /tmp/nums.txt | tr '\n' ' ')
          if [ "$RESULT" != "1 2 3 " ]; then
            echo "FAIL: expected '1 2 3 ', got '$RESULT'" >&2
            exit 1
          fi
          echo "==> coreutils sort: passed"
        '';
      };

      wc = testing.mkFirecrackerTest {
        pname = "tool-coreutils-wc";
        rootfsDeps = [ self ];
        testScript = ''
          RESULT=$(echo "hello world" | wc -w | tr -d ' ')
          if [ "$RESULT" != "2" ]; then
            echo "FAIL: expected 2, got '$RESULT'" >&2
            exit 1
          fi
          echo "==> coreutils wc: passed"
        '';
      };

      head-tail = testing.mkFirecrackerTest {
        pname = "tool-coreutils-head-tail";
        rootfsDeps = [ self ];
        testScript = ''
          printf 'a\nb\nc\nd\ne\n' > /tmp/lines.txt

          FIRST=$(head -2 /tmp/lines.txt | tr '\n' ' ')
          test "$FIRST" = "a b "

          LAST=$(tail -2 /tmp/lines.txt | tr '\n' ' ')
          test "$LAST" = "d e "

          # head + tail combo: get 3rd line
          LINE3=$(head -3 /tmp/lines.txt | tail -1)
          test "$LINE3" = "c"

          echo "==> coreutils head/tail: passed"
        '';
      };

      basic-ops = testing.mkFirecrackerTest {
        pname = "tool-coreutils-basic-ops";
        rootfsDeps = [ self ];
        testScript = ''
          mkdir -p /tmp/test-dir/sub
          echo "content" > /tmp/test-dir/file.txt

          # cp
          cp /tmp/test-dir/file.txt /tmp/test-dir/copy.txt
          test -f /tmp/test-dir/copy.txt
          test "$(cat /tmp/test-dir/copy.txt)" = "content"

          # mv
          mv /tmp/test-dir/copy.txt /tmp/test-dir/moved.txt
          test -f /tmp/test-dir/moved.txt
          test ! -f /tmp/test-dir/copy.txt

          # rm
          rm /tmp/test-dir/moved.txt
          test ! -f /tmp/test-dir/moved.txt

          # rmdir
          rmdir /tmp/test-dir/sub
          test ! -d /tmp/test-dir/sub

          # ln -s
          ln -s /tmp/test-dir/file.txt /tmp/test-dir/link.txt
          test -L /tmp/test-dir/link.txt
          test "$(cat /tmp/test-dir/link.txt)" = "content"

          # chmod
          chmod 755 /tmp/test-dir/file.txt
          test -x /tmp/test-dir/file.txt

          # chown (root only — we are root in the VM)
          chown root:root /tmp/test-dir/file.txt

          echo "==> coreutils basic ops: passed"
        '';
      };

      text-ops = testing.mkFirecrackerTest {
        pname = "tool-coreutils-text-ops";
        rootfsDeps = [ self ];
        testScript = ''
          # cat
          echo "hello" > /tmp/text-test.txt
          test "$(cat /tmp/text-test.txt)" = "hello"

          # echo and printf
          test "$(echo "world")" = "world"
          test "$(printf '%05d' 42)" = "00042"

          # tr
          test "$(echo "hello" | tr 'a-z' 'A-Z')" = "HELLO"

          # cut
          test "$(echo "a:b:c" | cut -d: -f2)" = "b"

          # paste
          printf 'a\nb\n' > /tmp/col1.txt
          printf '1\n2\n' > /tmp/col2.txt
          RESULT=$(paste /tmp/col1.txt /tmp/col2.txt | head -1)
          test "$RESULT" = "a	1"

          # uniq
          printf 'aaa\naaa\nbbb\nccc\nccc\n' > /tmp/dups.txt
          UCOUNT=$(uniq /tmp/dups.txt | wc -l | tr -d ' ')
          test "$UCOUNT" = "3"

          # tee
          echo "tee test" | tee /tmp/tee-out.txt > /dev/null
          test "$(cat /tmp/tee-out.txt)" = "tee test"

          echo "==> coreutils text ops: passed"
        '';
      };

      perms = testing.mkFirecrackerTest {
        pname = "tool-coreutils-perms";
        rootfsDeps = [ self ];
        testScript = ''
          echo "perm test" > /tmp/perm-test.txt
          chmod 755 /tmp/perm-test.txt
          PERMS=$(stat -c '%a' /tmp/perm-test.txt)
          if [ "$PERMS" != "755" ]; then
            echo "FAIL: expected 755, got '$PERMS'" >&2
            exit 1
          fi

          # chown
          chown root:root /tmp/perm-test.txt
          OWNER=$(stat -c '%U' /tmp/perm-test.txt)
          test "$OWNER" = "root"

          # id
          ID_OUT=$(id -u)
          test "$ID_OUT" = "0"

          # whoami
          WHO=$(whoami)
          test "$WHO" = "root"

          echo "==> coreutils perms: passed"
        '';
      };
    };

  meta = {
    description = "GNU Coreutils — basic file, shell, and text manipulation utilities";
    homepage = "https://www.gnu.org/software/coreutils/";
    license = "GPL-3.0-or-later";
  };
}
