##! nginx — High-performance HTTP and reverse proxy server
{
  mkDerivation,
  writeShellScriptBin,
  fetchurl,
  gnumake,
  bash,
  coreutils,
  jq,
  openssl,
  pcre2,
  zlib,
}: let
  version = "1.30.4";
  control = writeShellScriptBin "nginx-control" ''
    set -euo pipefail

    runtime_config=/etc/aos/packages/nginx/runtime.json
    nginx=/bin/nginx
    nginx_config=/etc/nginx/nginx.conf

    enabled() {
      ${jq}/bin/jq -e '.enabled == true' "$runtime_config" >/dev/null
    }

    case "''${1:-}" in
      enabled)
        enabled
        ;;
      prepare)
        ${coreutils}/bin/mkdir -p \
          /var/lib/aos-pkg-nginx/client_body \
          /var/lib/aos-pkg-nginx/proxy \
          /var/lib/aos-pkg-nginx/fastcgi \
          /var/lib/aos-pkg-nginx/uwsgi \
          /var/lib/aos-pkg-nginx/scgi \
          /var/lib/aos-pkg-nginx/www
        "$nginx" -t -c "$nginx_config"
        ;;
      reload)
        if enabled; then
          "$nginx" -t -c "$nginx_config"
          "$nginx" -c "$nginx_config" -s reload
        elif [[ -s /run/nginx/nginx.pid ]]; then
          "$nginx" -c "$nginx_config" -s quit
        fi
        ;;
      quit)
        if [[ -s /run/nginx/nginx.pid ]]; then
          "$nginx" -c "$nginx_config" -s quit
        fi
        ;;
      *)
        echo "usage: nginx-control {enabled|prepare|reload|quit}" >&2
        exit 64
        ;;
    esac
  '';
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
      bash
      control
      coreutils
      jq
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
          mkdir -p "$out/share/nginx"
          cp conf/mime.types "$out/share/nginx/mime.types"
          ln -s ${control}/bin/nginx-control "$out/bin/nginx-control"
          test -x $out/bin/nginx
          test -x $out/bin/nginx-control
          test -s $out/share/nginx/mime.types
        '';
      }
    ];

    expose = {
      units."nginx.service" = {
        description = "nginx HTTP and reverse proxy server";
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "simple";
          DynamicUser = true;
          RuntimeDirectory = "nginx";
          RuntimeDirectoryMode = "0750";
          StateDirectory = "aos-pkg-nginx";
          StateDirectoryMode = "0750";
          UMask = "0027";
          ExecCondition = "/bin/nginx-control enabled";
          ExecStartPre = "/bin/nginx-control prepare";
          ExecStart = "/bin/nginx -c /etc/nginx/nginx.conf -g 'daemon off;'";
          ExecReload = "/bin/nginx-control reload";
          ExecStop = "/bin/nginx-control quit";
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/nginx/runtime.json";
            format = "json";
            required = ["enabled" "generation"];
            units = ["nginx.service"];
            reload = "reload";
          }
        ];
        credentials =
          builtins.map (name: {
            inherit name;
            source = "/run/credstore/nginx/${name}";
            units = ["nginx.service"];
            encrypted = false;
            optional = true;
          }) [
            "tls-certificate"
            "tls-private-key"
          ];
      };

      permissions = {
        network = "host";
        capabilities = ["CAP_NET_BIND_SERVICE"];
        devices = [];
        host-paths = [
          {
            path = "/etc/nginx/nginx.conf";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
      };
    };

    configModule = {
      src = ./_nginx-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "nginx.accessLog"
        "nginx.clientMaxBodySize"
        "nginx.enable"
        "nginx.extraHttpConfig"
        "nginx.gzip"
        "nginx.tlsCredentials.certificate"
        "nginx.tlsCredentials.privateKey"
        "nginx.upstreams"
        "nginx.virtualHosts"
        "nginx.workerConnections"
        "nginx.workerProcesses"
      ];
      ownsRoots = [
        {
          root = "nginx";
          interfaceAbi = 1;
          contributable = [
            "upstreams.*"
            "virtualHosts.*"
          ];
        }
      ];
      # This is the scoped-artifact contract consumed by the evaluator. It
      # grants exact names, never authority over a structural-core root.
      artifacts = {
        etc = ["nginx/nginx.conf"];
        units = [];
        users = [];
        groups = [];
      };
    };

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
