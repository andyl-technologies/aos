##! nginx — HTTP and reverse proxy server
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  perl,
  openssl,
  pcre2,
  zlib,
  libxcrypt,
}:

let
  version = "1.27.3";
in
mkDerivation {
  pname = "nginx";
  inherit version;

  src = fetchurl {
    urls = [
      "https://nginx.org/download/nginx-${version}.tar.gz"
    ];
    hash = "sha256-uiOpVo9EIDa2HNDim9ZqR7kGNO+pHgss8tcZBXqbeQM=";
  };

  buildDeps = [
    make
    pkg-config
    perl
  ];
  runtimeDeps = [
    openssl
    pcre2
    zlib
    libxcrypt
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd nginx-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sbin-path=$out/bin/nginx \
          --modules-path=$out/lib/nginx/modules \
          --conf-path=$out/etc/nginx/nginx.conf \
          --error-log-path=$out/var/log/nginx/error.log \
          --http-log-path=$out/var/log/nginx/access.log \
          --pid-path=$out/run/nginx.pid \
          --lock-path=$out/run/nginx.lock \
          --with-http_ssl_module \
          --with-http_v2_module \
          --with-http_realip_module \
          --with-http_stub_status_module \
          --with-http_auth_request_module \
          --with-http_gzip_static_module \
          --with-http_gunzip_module \
          --with-http_sub_module \
          --with-http_addition_module \
          --with-http_secure_link_module \
          --with-threads \
          --with-stream \
          --with-stream_ssl_module \
          --with-pcre-jit \
          --with-compat \
          --with-cc=$CC \
          --with-cc-opt="$CFLAGS" \
          --with-ld-opt="$LDFLAGS -Wl,-rpath,$out/lib"
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

        # Preserve source tree and build artifacts for dynamic module
        # compilation (e.g. nginx-acme's nginx-sys build script needs
        # NGINX_SOURCE_DIR with src/core/nginx.h and NGINX_BUILD_DIR
        # with objs/ngx_auto_config.h).
        mkdir -p $out/share/nginx-dev
        cp -a src $out/share/nginx-dev/src
        cp -a objs $out/share/nginx-dev/objs
        cp -a auto $out/share/nginx-dev/auto
        cp -a conf $out/share/nginx-dev/conf
        cp configure Makefile $out/share/nginx-dev/ 2>/dev/null || true
      '';
    }
  ];

  meta = {
    description = "nginx — HTTP and reverse proxy server";
    homepage = "https://nginx.org";
    license = "BSD-2-Clause";
  };
}
