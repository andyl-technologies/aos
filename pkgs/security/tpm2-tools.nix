##! tpm2-tools — TPM 2.0 command-line tools.
{
  mkDerivation,
  fetchurl,
  bash,
  gnumake,
  pkg-config,
  openssl,
  curl,
  tpm2-tss,
}: let
  version = "5.7";
in
  mkDerivation {
    pname = "tpm2-tools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/tpm2-software/tpm2-tools/releases/download/${version}/tpm2-tools-${version}.tar.gz"
      ];
      hash = "sha256-OBDTa1B5JW9PL3zlUuIiE9Q7EDHBMVON+KLbw8VwmDo=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [bash openssl curl tpm2-tss];
    propagatedDeps = [openssl curl tpm2-tss];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tpm2-tools-${version}
        '';
      }
      {
        # The agent-side quote path needs the ESYS/SYS/MU/TCTI layers and
        # libcurl-backed EK certificate helpers. FAPI tools remain unavailable
        # until the AOS tpm2-tss package grows the tss2-fapi stack.
        name = "configure";
        script = ''
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
