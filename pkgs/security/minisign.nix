##! minisign — Dead simple signing tool
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  pkg-config,
  libsodium,
}: let
  version = "0.12";
in
  mkDerivation {
    pname = "minisign";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Minisign accepts the signature made by the corresponding public key.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "The text answer=42 and a newly generated unencrypted signing key.";
        "operation" = "Generate a key, sign the file, and verify its detached signature.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/minisign"
              "-G"
              "-W"
              "-p"
              "qualification.pub"
              "-s"
              "qualification.key"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/minisign"
              "-S"
              "-s"
              "qualification.key"
              "-m"
              "answer.txt"
              "-x"
              "answer.minisig"
              "-t"
              "qualification"
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
              "@out@/bin/minisign"
              "-V"
              "-q"
              "-p"
              "qualification.pub"
              "-m"
              "answer.txt"
              "-x"
              "answer.minisig"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Minisign rejects the signature mismatch with status 1.";
        "files" = {
          "answer.txt" = "answer=42\n";
          "changed.txt" = "answer=43\n";
        };
        "input" = "A signed answer file and a second file whose contents were changed.";
        "operation" = "Verify the original signature against the changed file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/minisign"
              "-G"
              "-W"
              "-p"
              "qualification.pub"
              "-s"
              "qualification.key"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/minisign"
              "-S"
              "-s"
              "qualification.key"
              "-m"
              "answer.txt"
              "-x"
              "answer.minisig"
              "-t"
              "qualification"
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
              "@out@/bin/minisign"
              "-V"
              "-q"
              "-p"
              "qualification.pub"
              "-m"
              "changed.txt"
              "-x"
              "answer.minisig"
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
        "https://github.com/jedisct1/minisign/archive/${version}/minisign-${version}.tar.gz"
      ];
      hash = "sha256-eW3OE3b5vLGhns5ynAdcRwVDZDVf4MDB6+UQTVCMfbA=";
    };

    buildDeps = [
      gnumake
      cmake
      pkg-config
    ];
    runtimeDeps = [libsodium];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd minisign-${version}
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p build && cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_BUILD_TYPE=Release
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
      description = "minisign — simple tool to sign and verify files";
      homepage = "https://jedisct1.github.io/minisign/";
      license = "ISC";
    };
  }
