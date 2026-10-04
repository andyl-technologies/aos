##! python3-cryptography — Cryptographic recipes and primitives for Python
{
  mkDerivation,
  fetchurl,
  fetchCargoDeps,
  buildPackages,
  rust,
  python3,
  pkg-config,
  openssl,
  libffi,
  python3-cffi,
  python3-pycparser,
  stdenv,
  lib,
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
    hash = "sha256-NTTC7bI1oQCrYfcEnEzngaTFgygXBgu6A9rkaQfrRJk=";
  };
  # build_openssl.py runs on the builder and imports cffi to generate the C
  # bindings, so its modules come from the build package set.
  pythonPath = "${buildPackages.setuptools}/${sitePackages}:${buildPackages.python3-cffi}/${sitePackages}:${buildPackages.python3-pycparser}/${sitePackages}";

  # A cross build needs Cargo with the target standard library, while build
  # scripts and proc macros still link for the builder.
  cargoTool =
    if stdenv.isCross
    then rust.passthru.buildTool
    else rust;
  rustTarget = stdenv.hostPlatform.config;
  nativeCargoTarget = lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
  cargoOutputDir =
    if stdenv.isCross
    then "target/${rustTarget}/release"
    else "target/release";
  extensionLibrary =
    if stdenv.hostPlatform.isDarwin
    then "libcryptography_rust.dylib"
    else "libcryptography_rust.so";

  # PyO3 reads the target interpreter's sysconfig from PYO3_CROSS_LIB_DIR;
  # cryptography-cffi derives the target Python headers from the same path.
  # Build the cdylib as an extension module so it does not link libpython,
  # and on Darwin let the loading interpreter supply the C API symbols, as
  # the target sysconfig LDSHARED does for C extensions.
  crossBuildEnvironment = lib.optionalString stdenv.isCross ''
    export PYO3_CROSS_LIB_DIR=${python3}/lib/python3.14
    export PYO3_BUILD_EXTENSION_MODULE=1

    mkdir -p .aos-build-tools
    cat > .aos-build-tools/cc-for-build <<'CC_EOF'
    #!${buildPackages.bash}/bin/bash
    unset AOS_CROSS_COMPILING AOS_TARGET_ARCH AOS_TARGET_PLATFORM
    unset AOS_OBJECT_FORMAT AOS_RUST_TARGET AOS_GOARCH AOS_GOOS
    unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE
    unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
    unset LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET SDKROOT
    unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS
    exec ${buildPackages.cc}/bin/cc "$@"
    CC_EOF
    chmod +x .aos-build-tools/cc-for-build
    export CARGO_TARGET_${nativeCargoTarget}_LINKER="$PWD/.aos-build-tools/cc-for-build"
  '';
  cargoTargetFlags = lib.optionalString stdenv.isCross " --target ${rustTarget}";
  # Only the final cdylib takes these flags. The install name replaces the
  # default sandbox output path with the module's installed file name.
  extensionLinkArgs =
    lib.optionalString stdenv.hostPlatform.isDarwin
    " -- -C link-arg=-undefined -C link-arg=dynamic_lookup -C link-arg=-Wl,-install_name,@rpath/_rust.abi3.so";

  # A foreign extension cannot be imported on the builder.
  installCheck = lib.optionalString (!stdenv.isCross) ''

    export PYTHONPATH="$out/${sitePackages}:${python3-cffi}/${sitePackages}:${python3-pycparser}/${sitePackages}"
    ${python3}/bin/python3 -c \
      'from cryptography.hazmat.primitives.asymmetric import rsa; rsa.generate_private_key(public_exponent=65537, key_size=2048)'
  '';
in
  mkDerivation {
    pname = "python3-cryptography";
    inherit version src;

    buildDeps = [cargoTool buildPackages.python3 buildPackages.setuptools pkg-config];
    runtimeDeps = [python3 openssl libffi python3-cffi python3-pycparser];
    propagatedDeps = [python3 openssl libffi python3-cffi python3-pycparser];
    disallowedReferences = [cargoDeps cargoTool];

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
        script =
          crossBuildEnvironment
          + ''
            export CARGO_HOME="$TMPDIR/cargo"
            export CARGO_INCREMENTAL=0
            export OPENSSL_DIR=${openssl}
            export OPENSSL_NO_VENDOR=1
            export PYO3_PYTHON=${buildPackages.python3}/bin/python3
            export PYTHONPATH=${pythonPath}

            cargo ${
              if stdenv.hostPlatform.isDarwin
              then "rustc"
              else "build"
            } \
              --manifest-path src/rust/Cargo.toml \
              --release \
              --frozen \
              --offline \
              -j"$NIX_BUILD_CORES"${cargoTargetFlags}${extensionLinkArgs}
          '';
      }
      {
        name = "install";
        script =
          ''
            mkdir -p "$out/${sitePackages}"
            cp -R src/cryptography "$out/${sitePackages}/"
            cp ${cargoOutputDir}/${extensionLibrary} \
              "$out/${sitePackages}/cryptography/hazmat/bindings/_rust.abi3.so"

            mkdir -p "$out/${sitePackages}/cryptography-${version}.dist-info"
            printf 'Metadata-Version: 2.4\nName: cryptography\nVersion: ${version}\n' \
              > "$out/${sitePackages}/cryptography-${version}.dist-info/METADATA"
          ''
          + installCheck;
      }
    ];

    meta = {
      description = "Cryptographic recipes and primitives for Python";
      homepage = "https://cryptography.io/";
      license = "Apache-2.0 OR BSD-3-Clause";
    };
  }
