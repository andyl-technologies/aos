##! pigz — parallel gzip
##!
##! Drop-in replacement for gzip(1) that splits the input into 128 KiB
##! chunks and compresses them across N threads. Output is a standard
##! gzip stream, kernel- and gunzip-compatible. With `-n` the header
##! omits name + mtime, so the bytes are reproducible across runs and
##! across thread counts (pigz partitions the input deterministically;
##! threading only affects scheduling).
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "2.8";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "pigz";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The decompressed bytes exactly equal the original text.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A fixed text file compressed as a deterministic gzip stream.";
        "operation" = "Compress the file without name metadata and decode it back.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pigz"
              "-n"
              "-k"
              "answer.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/pigz"
              "-d"
              "-c"
              "answer.txt.gz"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "pigz reports corrupt input with a non-success status.";
        "files" = {
          "invalid.gz" = "not a gzip stream\n";
        };
        "input" = "A file carrying the gzip suffix but no gzip header.";
        "operation" = "Attempt to decompress the malformed stream.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pigz"
              "-d"
              "-c"
              "invalid.gz"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://zlib.net/pigz/pigz-${version}.tar.gz"
      ];
      hash = "sha256-64crTw4fDr5Zyfe9jFBsQgSJO6aoSS3jHfQW8NUXD9A=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pigz-${version}
        '';
      }
      {
        name = "build";
        # pigz has no ./configure; its Makefile picks up CC/CFLAGS/LDFLAGS
        # from the environment. The AOS ccWrapper already injects the
        # -isystem/-L/-Wl,-rpath flags for zlib, so a plain `make` links
        # correctly without further hints.
        script = ''
          make -j$NIX_BUILD_CORES CC="$CC"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share/man/man1
          install -m 0755 pigz $out/bin/pigz
          ln -s pigz $out/bin/unpigz
          install -m 0644 pigz.1 $out/share/man/man1/pigz.1
        '';
      }
    ];

    meta = {
      description = "pigz — parallel implementation of gzip";
      homepage = "https://zlib.net/pigz/";
      license = "Zlib";
    };
  }
