##! libarchive — Multi-format archive and compression library
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
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
  version = "3.8.9";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libarchive";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The recovered entry has the declared pathname and size.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libarchive primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libarchive rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <archive.h>\n#include <archive_entry.h>\n#include <string.h>\nint main(void) {\n    char buffer[4096]; size_t used = 0;\n    struct archive *writer = archive_write_new();\n    struct archive_entry *entry = archive_entry_new();\n    archive_write_set_format_pax_restricted(writer);\n    if (archive_write_open_memory(writer, buffer, sizeof(buffer), &used) != ARCHIVE_OK) return 2;\n    archive_entry_set_pathname(entry, \"answer.txt\"); archive_entry_set_filetype(entry, AE_IFREG);\n    archive_entry_set_perm(entry, 0644); archive_entry_set_size(entry, 2);\n    if (archive_write_header(writer, entry) != ARCHIVE_OK || archive_write_data(writer, \"42\", 2) != 2) return 3;\n    archive_entry_free(entry); archive_write_free(writer);\n    struct archive *reader = archive_read_new(); archive_read_support_format_tar(reader);\n    if (archive_read_open_memory(reader, buffer, used) != ARCHIVE_OK) return 4;\n    if (archive_read_next_header(reader, &entry) != ARCHIVE_OK) return 5;\n    int ok = strcmp(archive_entry_pathname(entry), \"answer.txt\") == 0 && archive_entry_size(entry) == 2;\n    archive_read_free(reader);\n    return ok ? pass() : 6;\n}\n\n";
        };
        "input" = "An in-memory tar archive containing one regular file.";
        "operation" = "Write the archive and read its entry back through libarchive.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-larchive"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libarchive primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libarchive returns an error status instead of an entry.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libarchive primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libarchive rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <archive.h>\nint main(void) {\n    const char invalid[] = \"not an archive\";\n    struct archive *reader = archive_read_new();\n    archive_read_support_filter_all(reader); archive_read_support_format_all(reader);\n    int opened = archive_read_open_memory(reader, invalid, sizeof(invalid));\n    struct archive_entry *entry = NULL;\n    int status = opened == ARCHIVE_OK ? archive_read_next_header(reader, &entry) : opened;\n    archive_read_free(reader);\n    if (status >= ARCHIVE_OK) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "Bytes that do not encode a supported archive.";
        "operation" = "Open the bytes and request the first archive header.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-larchive"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libarchive rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.libarchive.org/downloads/libarchive-${version}.tar.xz"
        "https://github.com/libarchive/libarchive/releases/download/v${version}/libarchive-${version}.tar.xz"
      ];
      hash = "sha256-iIyTT52VZI7LkWPcjiOrgKR27LgajxFUcEoie1tnbd4=";
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
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # The native xz unpacker also supplies pkg-config metadata. Prefer
            # target compression libraries when configure resolves link flags.
            export PKG_CONFIG_PATH=${openssl}/lib/pkgconfig:${zlib}/lib/pkgconfig:${zstd}/lib/pkgconfig:${lz4}/lib/pkgconfig:${expat}/lib/pkgconfig:${xz}/lib/pkgconfig:$PKG_CONFIG_PATH
          ''
          + ''
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
