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
  bash,
  gzip,
  bzip2,
  xz,
  zstd,
}: let
  version = "1.35";
in
  mkDerivation {
    pname = "tar";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The extracted member bytes exactly match the input.";
        "files" = {
          "payload.txt" = "answer=42\n";
        };
        "input" = "A text file stored in a new tar archive.";
        "operation" = "Create the archive, then stream the member back through tar.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/tar"
              "-cf"
              "payload.tar"
              "payload.txt"
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
              "@out@/bin/tar"
              "-xOf"
              "payload.tar"
              "payload.txt"
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
        "expected" = "Tar rejects the invalid archive with status 2.";
        "files" = {
          "invalid.tar" = "not a tar archive\n";
        };
        "input" = "Text bytes that do not form a tar archive.";
        "operation" = "Attempt to list the malformed archive.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/tar"
              "-tf"
              "invalid.tar"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/tar/tar-${version}.tar.xz"];
      hash = "05nw7q7sazkana11hnf3f77lmybw1j9j6lsk93bsxirf6hvzyqjd";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [bash gzip bzip2 xz zstd];
    configureFlags = "--disable-nls";
    postInstall = ''
      find "$out" -type f -perm -u+x | while read f; do
        [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ] || continue
        sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
      done
    '';

    meta = {
      description = "GNU tar archiving utility";
      homepage = "https://www.gnu.org/software/tar/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
