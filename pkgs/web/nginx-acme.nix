##! nginx-acme — ACME (Let's Encrypt) dynamic module for nginx
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  pkg-config,
  llvm,
  nginx,
  openssl,
  pcre2,
  zlib,
  libxcrypt,
  bootstrapTools,
}: let
  version = "0.3.1";
  src = fetchurl {
    urls = [
      "https://github.com/nginx/nginx-acme/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-vj09EPBCkwo780hzFpjq23AD0iSoY8U7cZzNKHIVcsM=";
  };
in
  mkCargoPackage {
    pname = "nginx-acme";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-RTo+++YM3AQkCijApZxxdErXxTecR+rV7EMLfSp74YM=";
    };

    cargoFlags = "--lib";
    installBins = false;
    installLibs = true;
    doCheck = false;

    buildDeps = [
      pkg-config
      llvm
    ];
    runtimeDeps = [
      nginx
      openssl
      pcre2
      zlib
      libxcrypt
    ];

    # bindgen needs libclang and system headers (libclang doesn't use C_INCLUDE_PATH)
    LIBCLANG_PATH = "${llvm}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${bootstrapTools}/include-glibc";
    # nginx-sys needs the source tree and build artifacts
    NGINX_SOURCE_DIR = "${nginx}/share/nginx-dev";
    NGINX_BUILD_DIR = "${nginx}/share/nginx-dev/objs";

    postInstall = ''
      mkdir -p $out/lib/nginx/modules
      mv $out/lib/libnginx_acme.so $out/lib/nginx/modules/ngx_http_acme_module.so
    '';

    meta = {
      description = "nginx-acme — ACME dynamic module for automatic TLS certificates";
      homepage = "https://github.com/nginx/nginx-acme";
      license = "BSD-2-Clause";
    };
  }
