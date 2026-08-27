##! nginx — High-performance HTTP and reverse proxy server
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  pcre2,
  zlib,
  stdenv,
}: let
  version = "1.30.4";
  linkerOptions =
    if stdenv.hostPlatform.isDarwin
    then "-L${openssl}/lib -L${pcre2}/lib -L${zlib}/lib -Wl,-rpath,${openssl}/lib -Wl,-rpath,${pcre2}/lib -Wl,-rpath,${zlib}/lib"
    else "-L${openssl}/lib -L${pcre2}/lib -L${zlib}/lib -Wl,-rpath,${openssl}/lib:${pcre2}/lib:${zlib}/lib";
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
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
                            # Nginx's crossbuild option selects the target OS, but its
                            # feature harness still attempts to execute probe binaries.
                            # Darwin capabilities are compile/link probes here; the one
                            # explicit historical kqueue bug probe remains conservative.
                            sed -i '0,/ngx_feature_run=yes/s//ngx_feature_run=no/' auto/cc/name
                            sed -i 's/ngx_feature_run=yes/ngx_feature_run=no/g' auto/os/darwin auto/unix
              sed -i "s|/bin/sh|$CONFIG_SHELL|g" auto/feature
              sed -i 's/if $NGX_AUTOTEST >\/dev\/null 2>\&1; then/if true; then/' auto/endianness

                            # All supported Darwin targets use the LP64 ABI. Nginx's
                            # bespoke sizeof probe unconditionally executes its output,
                            # unlike the feature harness disabled above, so provide the
              # target ABI values while retaining the compile/link probe.
                            sed -i '
                              /^if \[ -x \$NGX_AUTOTEST \]; then$/,/^fi$/c\
              case "$ngx_type" in\
                int|sig_atomic_t) ngx_size=4 ;;\
                *) ngx_size=8 ;;\
              esac\
              echo " $ngx_size bytes"
              ' auto/types/sizeof

              # Upstream implements file AIO only for FreeBSD and Linux. Its
              # kqueue probe is too weak for Darwin's sigevent layout and
              # otherwise enables FreeBSD-only source that cannot compile.
            ''
            else ""
          }
          ./configure \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--crossbuild=Darwin:23.0:${stdenv.hostPlatform.darwinArch}"
            else ""
          } \
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
            ${
            if stdenv.hostPlatform.isDarwin
            then ""
            else "--with-file-aio"
          } \
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
            --with-cc-opt="${
            if stdenv.hostPlatform.isDarwin
            then "-Wno-deprecated-declarations "
            else ""
          }-I${openssl}/include -I${pcre2}/include -I${zlib}/include" \
            --with-ld-opt="${linkerOptions}"
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
