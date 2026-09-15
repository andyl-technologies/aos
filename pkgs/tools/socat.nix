##! socat — Multipurpose relay for bidirectional data transfer
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  openssl,
  buildPackages,
}: let
  version = "1.8.1.3";
in
  mkDerivation {
    pname = "socat";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Socat preserves the payload exactly.";
        "files" = {};
        "input" = "A fixed byte stream on standard input.";
        "operation" = "Relay the stream between Socat's standard-input and standard-output addresses.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/socat"
              "-u"
              "STDIN"
              "STDOUT"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "answer=42\n";
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Socat rejects the address before starting a relay.";
        "files" = {};
        "input" = "An address type that Socat does not implement.";
        "operation" = "Open the unknown address.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/socat"
              "-u"
              "QUALIFICATION-NOT-AN-ADDRESS"
              "STDOUT"
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
        "http://www.dest-unreach.org/socat/download/socat-${version}.tar.bz2"
      ];
      hash = "sha256-JbxkdikrLmFCIJicd7C2/Kh7slJdl0ezGmY5sftgJBg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of socat's
    # `-V`-baked PKG_CONFIG_PATH / CC strings.
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd socat-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./socat-openssl-4.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-openssl \
            --with-openssl=${openssl}
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

    meta = {
      description = "socat — multipurpose relay for bidirectional data transfer";
      homepage = "http://www.dest-unreach.org/socat/";
      license = "GPL-2.0-only";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      rpath = testing.mkRPATHCheck {
        pkg = self;
        bins = ["socat"];
      };

      version = testing.mkToolCheck {
        pname = "tool-socat";
        tool = self;
        command = "socat -V";
      };
    };
  }
