{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
}: let
  version = "4.1.3";
in
  mkDerivation {
    pname = "tpm2-tss";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/tpm2-software/tpm2-tss/releases/download/${version}/tpm2-tss-${version}.tar.gz"
      ];
      hash = "sha256-N/FYAgCreDBdH8hy2JJBqu4Mk8voW8VZvzMnN6YNO+g=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [openssl];
    propagatedDeps = [openssl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tpm2-tss-${version}
        '';
      }
      {
        # systemd links the ESYS/SYS/MU/TCTI layers only — FAPI and the
        # policy engine pull in json-c/curl and a runtime keystore we do
        # not need, so disable them. localstatedir under $out keeps
        # `make install` from writing to the host /var.
        name = "configure";
        script = ''
          # tpm2-tss's configure insists on groupadd/useradd so a distro
          # build can create the `tss` service account. We never create
          # that account (no abrmd; systemd talks to /dev/tpm directly),
          # so satisfy the check with no-op shims — `make install` does not
          # invoke them.
          mkdir -p $TMPDIR/fakebin
          for t in groupadd useradd addgroup adduser; do
            printf '#!%s\nexit 0\n' "$CONFIG_SHELL" > $TMPDIR/fakebin/$t
            chmod +x $TMPDIR/fakebin/$t
          done
          export PATH=$TMPDIR/fakebin:$PATH

          ./configure \
            $configureFlags \
            --prefix=$out \
            --localstatedir=$out/var \
            --disable-static \
            --disable-fapi \
            --disable-policy \
            --disable-doc \
            --disable-integration \
            --disable-tcti-cmd \
            --with-crypto=ossl \
            --disable-defaultflags
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
      description = "TPM2 Software Stack (TSS2) — ESYS/SYS/MU/TCTI libraries";
      homepage = "https://github.com/tpm2-software/tpm2-tss";
      license = "BSD-2-Clause";
    };
  }
