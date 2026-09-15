##! python3-cryptography — Cryptographic recipes and primitives for Python
{
  mkDerivation,
  fetchurl,
  fetchCargoDeps,
  rust,
  python3,
  setuptools,
  pkg-config,
  openssl,
  libffi,
  python3-cffi,
  python3-pycparser,
}: let
  version = "50.0.1";
  sitePackages = "lib/python3.14/site-packages";
  src = fetchurl {
    urls = [
      "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-${version}.tar.gz"
    ];
    hash = "sha256-Xdm9ocErQWL2/1aO614P+VbCjRRAbodc/opjotQU/yA=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-vSilXoEH89iPH90PHSIYtkiz6D82NKx6Mw5F91SdwgM=";
  };
  pythonPath = "${setuptools}/${sitePackages}:${python3-cffi}/${sitePackages}:${python3-pycparser}/${sitePackages}";
in
  mkDerivation {
    pname = "python3-cryptography";
    inherit version src;

    buildDeps = [rust python3 setuptools pkg-config];
    runtimeDeps = [python3 openssl libffi python3-cffi python3-pycparser];
    propagatedDeps = [python3 openssl libffi python3-cffi python3-pycparser];
    disallowedReferences = [cargoDeps rust];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cryptography-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export CARGO_INCREMENTAL=0
          mkdir -p "$CARGO_HOME" .cargo
          cat > .cargo/config.toml <<EOF
          [source.crates-io]
          replace-with = "vendored-sources"

          [source.vendored-sources]
          directory = "${cargoDeps}"

          [net]
          offline = true
          EOF
        '';
      }
      {
        name = "build";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export CARGO_INCREMENTAL=0
          export OPENSSL_DIR=${openssl}
          export OPENSSL_NO_VENDOR=1
          export PYO3_PYTHON=${python3}/bin/python3
          export PYTHONPATH=${pythonPath}

          cargo build \
            --manifest-path src/rust/Cargo.toml \
            --release \
            --frozen \
            --offline \
            -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}"
          cp -R src/cryptography "$out/${sitePackages}/"
          cp target/release/libcryptography_rust.so \
            "$out/${sitePackages}/cryptography/hazmat/bindings/_rust.abi3.so"

          mkdir -p "$out/${sitePackages}/cryptography-${version}.dist-info"
          printf 'Metadata-Version: 2.4\nName: cryptography\nVersion: ${version}\n' \
            > "$out/${sitePackages}/cryptography-${version}.dist-info/METADATA"

          export PYTHONPATH="$out/${sitePackages}:${python3-cffi}/${sitePackages}:${python3-pycparser}/${sitePackages}"
          ${python3}/bin/python3 -c \
            'from cryptography.hazmat.primitives.asymmetric import rsa; rsa.generate_private_key(public_exponent=65537, key_size=2048)'
        '';
      }
    ];

    meta = {
      description = "Cryptographic recipes and primitives for Python";
      homepage = "https://cryptography.io/";
      license = "Apache-2.0 OR BSD-3-Clause";
    };
  }
