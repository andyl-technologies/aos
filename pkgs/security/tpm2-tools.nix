##! tpm2-tools — TPM 2.0 command-line tools.
{
  lib,
  mkDerivation,
  fetchurl,
  bash,
  gnumake,
  pkg-config,
  openssl,
  curl,
  tpm2-tss,
  stdenv,
  buildPackages,
}: let
  version = "5.8";
in
  mkDerivation {
    pname = "tpm2-tools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Tpm2-rc-decode identifies parameter one as an out-of-range value.";
        "files" = {};
        "input" = "The TPM response code 0x1c4.";
        "operation" = "Decode the numeric response without opening a TPM device.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/tpm2_rc_decode\", \"0x1c4\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"parameter(1)\" in result.stdout and \"out of range\" in result.stdout\nprint(\"tpm2-tools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tpm2-tools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Tpm2-rc-decode rejects the invalid numeric value.";
        "files" = {};
        "input" = "A response-code value wider than the supported integer representation.";
        "operation" = "Decode the out-of-range response code.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/tpm2_rc_decode\", \"0x100000000\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"invalid TSS2_RC\" in result.stderr\n\nsys.stderr.write(\"tpm2-tools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tpm2-tools rejected invalid input\n";
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
        "https://github.com/tpm2-software/tpm2-tools/releases/download/${version}/tpm2-tools-${version}.tar.gz"
      ];
      hash = "sha256-HLcxhcroFLThXHwtCyJkLWQPr0h3X0FWof2S7fhL73M=";
    };

    patches =
      if stdenv.hostPlatform.isDarwin
      then [./tpm2-tools-patches/0001-darwin-utf16-compat.patch]
      else [];

    buildDeps =
      [gnumake pkg-config]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.autoconf]
        else []
      );
    runtimeDeps = [bash openssl curl tpm2-tss];
    propagatedDeps = [openssl curl tpm2-tss];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
                          tar xf $src
                          cd tpm2-tools-${version}

                          # Upstream handles FreeBSD's endian API but not Darwin's
                          # equivalent libkern interface.
                          sed -i '
                            /#if defined __FreeBSD__ || defined __DragonFly__/c\
            #if defined __APPLE__\
            # include <libkern/OSByteOrder.h>\
            # define htole16 OSSwapHostToLittleInt16\
            # define htole32 OSSwapHostToLittleInt32\
            # define le16toh OSSwapLittleToHostInt16\
            # define le32toh OSSwapLittleToHostInt32\
            # define le64toh OSSwapLittleToHostInt64\
            # define be64toh OSSwapBigToHostInt64\
            #elif defined __FreeBSD__ || defined __DragonFly__
                          ' lib/tpm2_systemdeps.h

                          # These GNU ld hardening switches describe ELF
                          # relocation behavior and have no Mach-O equivalent.
                          # Keep every other upstream hardening check enabled.
                          sed -i '
                            /add_hardened_ld_flag(\[\[-Wl,-z,relro\]\])/d
                            /add_hardened_ld_flag(\[\[-Wl,-z,now\]\])/d
                          ' configure.ac
                          touch aclocal.m4
                          autoconf
                          touch Makefile.in lib/config.h.in
          ''
          else ''
            tar xf $src
            cd tpm2-tools-${version}
          '';
      }
      {
        # The agent-side quote path needs the ESYS/SYS/MU/TCTI layers and
        # libcurl-backed EK certificate helpers. FAPI tools remain unavailable
        # until the AOS tpm2-tss package grows the tss2-fapi stack.
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --disable-unit \
              --with-bashcompdir=$out/share/bash-completion/completions
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --disable-unit \
              --with-bashcompdir=$out/share/bash-completion/completions
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
          mv $out/bin/tpm2 $out/bin/.tpm2-unwrapped
          cat > $out/bin/tpm2 <<EOF
          #!${bash}/bin/bash
          export LD_LIBRARY_PATH="${tpm2-tss}/lib\''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
          argv0="\''${0##*/}"
          exec -a "\$argv0" "$out/bin/.tpm2-unwrapped" "\$@"
          EOF
          chmod +x $out/bin/tpm2
        '';
      }
    ];

    meta = {
      description = "TPM 2.0 command-line tools";
      homepage = "https://github.com/tpm2-software/tpm2-tools";
      license = "BSD-3-Clause";
    };
  }
