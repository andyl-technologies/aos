##! GNU Tar — Archiving utility
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "1.35";
in
  mkDerivation {
    pname = "tar";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/tar/tar-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/tar/tar-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/tar/tar-${version}.tar.xz"
      ];
      hash = "sha256-TWL/NzQux67XSFNTI5MMfPlKz3HDWRiCsmp+pQ8+3BY=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tar-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
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
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-tar";
        tool = self;
        command = "tar --version";
      };

      roundtrip = testing.mkVMTest {
        name = "tool-tar-roundtrip";
        rootfsDeps = [
          self
          pkgs.gzip
        ];
        testScript = ''
          mkdir -p /tmp/tar-src
          echo "file-a-content" > /tmp/tar-src/a.txt
          echo "file-b-content" > /tmp/tar-src/b.txt
          mkdir -p /tmp/tar-src/sub
          echo "nested" > /tmp/tar-src/sub/c.txt

          tar czf /tmp/archive.tar.gz -C /tmp tar-src
          test -f /tmp/archive.tar.gz

          mkdir -p /tmp/tar-dst
          tar xzf /tmp/archive.tar.gz -C /tmp/tar-dst

          test "$(cat /tmp/tar-dst/tar-src/a.txt)" = "file-a-content"
          test "$(cat /tmp/tar-dst/tar-src/b.txt)" = "file-b-content"
          test "$(cat /tmp/tar-dst/tar-src/sub/c.txt)" = "nested"
          echo "==> tar roundtrip: passed"
        '';
      };

      xz = testing.mkVMTest {
        name = "tool-tar-xz";
        rootfsDeps = [
          self
          pkgs.xz
          pkgs.coreutils
        ];
        testScript = ''
          mkdir -p /tmp/txz-src
          echo "xz content" > /tmp/txz-src/file.txt
          echo "more xz" > /tmp/txz-src/other.txt

          tar cJf /tmp/test.tar.xz -C /tmp txz-src
          test -f /tmp/test.tar.xz

          mkdir -p /tmp/txz-dst
          tar xJf /tmp/test.tar.xz -C /tmp/txz-dst

          test "$(cat /tmp/txz-dst/txz-src/file.txt)" = "xz content"
          test "$(cat /tmp/txz-dst/txz-src/other.txt)" = "more xz"

          echo "==> tar xz: passed"
        '';
      };

      zstd = testing.mkVMTest {
        name = "tool-tar-zstd";
        rootfsDeps = [
          self
          pkgs.zstd
          pkgs.coreutils
        ];
        testScript = ''
          mkdir -p /tmp/tzst-src
          echo "zstd content" > /tmp/tzst-src/file.txt
          echo "more zstd" > /tmp/tzst-src/other.txt

          tar --zstd -cf /tmp/test.tar.zst -C /tmp tzst-src
          test -f /tmp/test.tar.zst

          mkdir -p /tmp/tzst-dst
          tar --zstd -xf /tmp/test.tar.zst -C /tmp/tzst-dst

          test "$(cat /tmp/tzst-dst/tzst-src/file.txt)" = "zstd content"
          test "$(cat /tmp/tzst-dst/tzst-src/other.txt)" = "more zstd"

          echo "==> tar zstd: passed"
        '';
      };

      bzip2 = testing.mkVMTest {
        name = "tool-tar-bzip2";
        rootfsDeps = [
          self
          pkgs.bzip2
          pkgs.coreutils
        ];
        testScript = ''
          mkdir -p /tmp/tbz-src
          echo "bzip2 content" > /tmp/tbz-src/file.txt
          echo "more bzip2" > /tmp/tbz-src/other.txt

          tar cjf /tmp/test.tar.bz2 -C /tmp tbz-src
          test -f /tmp/test.tar.bz2

          mkdir -p /tmp/tbz-dst
          tar xjf /tmp/test.tar.bz2 -C /tmp/tbz-dst

          test "$(cat /tmp/tbz-dst/tbz-src/file.txt)" = "bzip2 content"
          test "$(cat /tmp/tbz-dst/tbz-src/other.txt)" = "more bzip2"

          echo "==> tar bzip2: passed"
        '';
      };
    };

    meta = {
      description = "GNU Tar — archiving utility";
      homepage = "https://www.gnu.org/software/tar/";
      license = "GPL-3.0-or-later";
    };
  }
