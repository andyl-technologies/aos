##! libarchive — Multi-format archive and compression library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
  zlib,
  zstd,
  bzip2,
  lz4,
  expat,
  xz,
}: let
  version = "3.8.5";
in
  mkDerivation {
    pname = "libarchive";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.libarchive.org/downloads/libarchive-${version}.tar.xz"
        "https://github.com/libarchive/libarchive/releases/download/v${version}/libarchive-${version}.tar.xz"
      ];
      hash = "sha256-1oBo50vu46DsDdBK7pA31XV/zGUVkabc8bbVQvsVpwM=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      openssl
      zlib
      zstd
      bzip2
      lz4
      expat
      # Configure probes liblzma whenever the xz unpacker is visible. Keep
      # the matching host-platform library explicit so cross links never
      # fall back to the native build tool's archive.
      xz
    ];
    propagatedDeps = [];

    # libarchive still uses legacy trailing-array layouts internally. GCC's
    # strict level 3 narrows those arrays enough for Fortify to abort while
    # walking archives at runtime, so use the repo's compatibility level.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libarchive-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --with-openssl \
            --with-zlib \
            --with-zstd \
            --with-bz2lib \
            --without-xml2 \
            --with-expat \
            --with-lz4
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
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libarchive.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-libarchive";
        library = self;
        libs = ["-larchive"];
        extraDeps = [
          pkgs.zlib
          pkgs.zstd
          pkgs.bzip2
          pkgs.lz4
          pkgs.openssl
          pkgs.xz
        ];
        testSource = ''
          #include <archive.h>
          #include <stdio.h>
          int main() {
            printf("libarchive version: %s\n", archive_version_string());
            return 0;
          }
        '';
      };

      archive-chain = testing.mkVMTest {
        name = "cross-cutting-archive-chain";
        rootfsDeps = [
          pkgs.tar
          pkgs.gzip
          self
          pkgs.zlib
        ];
        testScript = ''
          export C_INCLUDE_PATH="${self}/include:${pkgs.zlib}/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="${self}/lib:${pkgs.zlib}/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"

          mkdir -p /tmp/src
          echo "file one content" > /tmp/src/one.txt
          echo "file two content" > /tmp/src/two.txt
          echo "file three content" > /tmp/src/three.txt

          echo "==> Creating tar.gz archive with tar + gzip"
          tar czf /tmp/archive.tar.gz -C /tmp/src .
          echo "    Archive size: $(ls -l /tmp/archive.tar.gz | cut -d' ' -f5) bytes"

          cat > /tmp/extract_test.c << 'EOF'
          #include <archive.h>
          #include <archive_entry.h>
          #include <stdio.h>
          #include <string.h>

          int main(void) {
              struct archive *a = archive_read_new();
              archive_read_support_filter_all(a);
              archive_read_support_format_all(a);

              int r = archive_read_open_filename(a, "/tmp/archive.tar.gz", 10240);
              if (r != ARCHIVE_OK) {
                  fprintf(stderr, "archive_read_open_filename failed: %s\n",
                          archive_error_string(a));
                  return 1;
              }

              int count = 0;
              struct archive_entry *entry;
              while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
                  const char *name = archive_entry_pathname(entry);
                  printf("  entry: %s (size: %lld)\n", name,
                         (long long)archive_entry_size(entry));
                  archive_read_data_skip(a);
                  count++;
              }

              archive_read_close(a);
              archive_read_free(a);

              if (count < 3) {
                  fprintf(stderr, "Expected at least 3 entries, got %d\n", count);
                  return 1;
              }

              printf("libarchive extracted %d entries from tar.gz\n", count);
              printf("Archive chain: PASS\n");
              return 0;
          }
          EOF

          echo "==> Compiling libarchive extraction test"
          gcc -o /tmp/extract_test /tmp/extract_test.c -larchive -lz
          echo "==> Extracting with libarchive"
          /tmp/extract_test
        '';
      };
    };

    meta = {
      description = "libarchive — multi-format archive and compression library";
      homepage = "https://www.libarchive.org";
      license = "BSD-2-Clause";
    };
  }
