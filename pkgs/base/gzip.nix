{
  lib,
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  coreutils,
  sed,
  bash,
  grep,
}: let
  version = "1.14";
in
  mkDerivation {
    pname = "gzip";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The decompressed bytes exactly reproduce the original payload.";
        "files" = {
          "payload.txt" = "AOS qualification payload\n";
        };
        "input" = "A fixed text payload.";
        "operation" = "Compress the payload, then decompress the resulting stream through gzip.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gzip"
              "@work@/primary/payload.txt"
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
              "@out@/bin/gzip"
              "-d"
              "-c"
              "@work@/primary/payload.txt.gz"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "AOS qualification payload\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The decoder rejects the malformed stream with a failure status.";
        "files" = {
          "invalid.gz" = "not a compressed stream\n";
        };
        "input" = "A regular text file that is not a gzip stream.";
        "operation" = "Ask gzip to decompress the invalid stream.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gzip"
              "-d"
              "-c"
              "@work@/bad-input/invalid.gz"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/gzip/gzip-${version}.tar.xz"];
      hash = "sha256-Aae4gb0iC/32Ffl7hxj4C9/T9q3ThbmT3Pbv0U6MCsY=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake coreutils sed];
    runtimeDeps = [bash grep];
    postInstall = ''
      for f in "$out/bin/"*; do
        [ -f "$f" ] || continue
        [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ] || continue
        sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
      done
      if [ -f "$out/bin/zgrep" ]; then
        sed -i \
          "s|/nix/store/[a-z0-9]\\{32\\}-grep-[^/]*/bin/grep|${grep}/bin/grep|g" \
          "$out/bin/zgrep"
      fi
    '';

    meta = {
      description = "GNU gzip compression utility";
      homepage = "https://www.gnu.org/software/gzip/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
