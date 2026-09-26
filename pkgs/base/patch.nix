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
    pname = "patch";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "answer.txt";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "patch succeeds and the resulting file contains answer=42.";
        "files" = {
          "answer.patch" = "--- answer.txt\n+++ answer.txt\n@@ -1 +1 @@\n-answer=41\n+answer=42\n";
          "answer.txt" = "answer=41\n";
        };
        "input" = "A one-line file and a unified diff changing 41 to 42.";
        "operation" = "Apply the diff to the named file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/patch"
              "answer.txt"
              "answer.patch"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "patch exits with its malformed-input status.";
        "files" = {};
        "input" = "Text that is not a patch in any supported format.";
        "operation" = "Attempt to apply the malformed patch stream.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/patch"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
            "stdin" = "this is not a patch\n";
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/patch/patch-${version}.tar.xz"];
      hash = "sha256-+Hzuae7CtPy/YKOWsDCtaqNBXxkqpffuhMrV4R9/WuM=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [];

    meta = {
      description = "GNU file patching utility";
      homepage = "https://www.gnu.org/software/patch/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
