##! file — determine file type using magic numbers
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  buildPackages,
  stdenv,
}: let
  version = "5.48";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "file";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "File identifies the payload as ASCII text.";
        "files" = {
          "sample.txt" = "AOS text\n";
        };
        "input" = "A newline-terminated ASCII text file.";
        "operation" = "Classify the file's contents without printing its path.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/file"
              "--brief"
              "@work@/primary/sample.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ASCII text\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "File rejects the invalid magic rule with status 1.";
        "files" = {
          "invalid.magic" = "this is not a magic rule\n";
          "sample.bin" = "x";
        };
        "input" = "A malformed magic database rule and a byte to classify.";
        "operation" = "Classify the byte using only the malformed magic database.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/file"
              "--brief"
              "-m"
              "@work@/bad-input/invalid.magic"
              "@work@/bad-input/sample.bin"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
        "https://astron.com/pub/file/file-${version}.tar.gz"
      ];
      hash = "sha256-7RRlaIOyOjZLQFfAVZXZMlLam8Rz0wEGUZUZ0NoUEoM=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.file]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd file-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure $configureFlags --prefix=$out
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

    meta = {
      description = "file — determine file type using magic numbers";
      homepage = "https://darwinsys.com/file/";
      license = "BSD-2-Clause";
    };
  }
