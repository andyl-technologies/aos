##! nginx — High-performance HTTP and reverse proxy server
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  pcre2,
  zlib,
}: let
  version = "1.30.4";
in
  mkDerivation {
    pname = "nginx";
    inherit version;

    src = fetchurl {
      urls = [
        "https://nginx.org/download/nginx-${version}.tar.gz"
      ];
      hash = "sha256-QmHckOnkfBxAQSdumqo9SOvi5mT3KOFPqVrmxn1XoIs=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [
      openssl
      pcre2
      zlib
    ];
    propagatedDeps = [];

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
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/var/log/nginx/error.log \
            --http-log-path=/var/log/nginx/access.log \
            --pid-path=/run/nginx/nginx.pid \
            --lock-path=/run/nginx/nginx.lock \
            --http-client-body-temp-path=/var/lib/nginx/client_body \
            --http-proxy-temp-path=/var/lib/nginx/proxy \
            --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
            --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
            --http-scgi-temp-path=/var/lib/nginx/scgi \
            --user=nginx \
            --group=nginx \
            --with-compat \
            --with-file-aio \
            --with-threads \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-http_v3_module \
            --with-http_realip_module \
            --with-http_addition_module \
            --with-http_sub_module \
            --with-http_dav_module \
            --with-http_flv_module \
            --with-http_mp4_module \
            --with-http_gunzip_module \
            --with-http_gzip_static_module \
            --with-http_auth_request_module \
            --with-http_random_index_module \
            --with-http_secure_link_module \
            --with-http_slice_module \
            --with-http_stub_status_module \
            --with-mail \
            --with-mail_ssl_module \
            --with-stream \
            --with-stream_ssl_module \
            --with-stream_ssl_preread_module \
            --with-pcre-jit \
            --with-cc-opt="-I${openssl}/include -I${pcre2}/include -I${zlib}/include" \
            --with-ld-opt="-L${openssl}/lib -L${pcre2}/lib -L${zlib}/lib -Wl,-rpath,${openssl}/lib:${pcre2}/lib:${zlib}/lib"
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
          installRoot="$TMPDIR/nginx-install"
          make install DESTDIR="$installRoot"
          mkdir -p "$out"
          cp -a "$installRoot$out/." "$out/"
          test -x $out/bin/nginx
        '';
      }
    ];

    meta = {
      description = "nginx — high-performance HTTP and reverse proxy server";
      homepage = "https://nginx.org";
      license = "BSD-2-Clause";
      mainProgram = "nginx";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      version = testing.mkToolCheck {
        pname = "tool-nginx";
        tool = self;
        command = "nginx -V 2>&1";
      };
    };
  }
