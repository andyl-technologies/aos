##! nginx — High-performance HTTP and reverse proxy server
{
  mkDerivation,
  fetchurl,
  gnumake,
  lib,
  openssl,
  pcre2,
  zlib,
  stdenv,
}: let
  version = "1.31.5";
  linkerOptions =
    if stdenv.hostPlatform.isDarwin
    then "-L${openssl}/lib -L${pcre2}/lib -L${zlib}/lib -Wl,-rpath,${openssl}/lib -Wl,-rpath,${pcre2}/lib -Wl,-rpath,${zlib}/lib"
    else "-L${openssl}/lib -L${pcre2}/lib -L${zlib}/lib -Wl,-rpath,${openssl}/lib:${pcre2}/lib:${zlib}/lib";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "nginx";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Nginx reports successful configuration validation.";
        "files" = {
          "nginx.conf" = "daemon off;\nmaster_process off;\nerror_log stderr;\npid @work@/primary/nginx.pid;\nevents {}\nhttp {}\n";
        };
        "input" = "A minimal Nginx configuration with empty events and HTTP blocks.";
        "operation" = "Parse and validate the configuration through nginx -t.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/nginx"
              "-t"
              "-p"
              "@work@/primary/"
              "-c"
              "nginx.conf"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Nginx rejects the unknown directive with status 1.";
        "files" = {
          "nginx.conf" = "qualification_directive_does_not_exist on;\n";
        };
        "input" = "An Nginx configuration containing an unknown top-level directive.";
        "operation" = "Parse and validate the malformed configuration through nginx -t.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/nginx"
              "-t"
              "-p"
              "@work@/bad-input/"
              "-c"
              "nginx.conf"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://nginx.org/download/nginx-${version}.tar.gz"
      ];
      hash = "sha256-6VFgfVNINmJL02trRacdv7BVI33q43ONprvzJw2tonk=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [openssl pcre2 zlib];
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
          mkdir -p "$out/share/nginx"
          cp conf/mime.types "$out/share/nginx/mime.types"
          test -x $out/bin/nginx
          test -s $out/share/nginx/mime.types
        '';
      }
    ];

    abilities = ./_nginx;

    meta = {
      description = "nginx — high-performance HTTP and reverse proxy server";
      homepage = "https://nginx.org";
      license = "BSD-2-Clause";
      mainProgram = "nginx";
    };

    checks = {
      testing,
      self,
      pkgs,
      mkSystem,
      ...
    }: let
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "system-image";
        key = "nginx-package-check";
        stage = "host";
      };
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      credential = name:
        lib.abilities.resourceReference {
          interface = serviceManagement.interfaces.credentialDelivery.identity;
          resource = {
            provider = credentialProvider;
            key = name;
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
      evaluate = nginxConfig:
        mkSystem {
          systemName = "nginx-package-check";
          modules = [
            {
              environment.systemPackages = [self];
              nginx = nginxConfig;
            }
          ];
        };
      disabled = evaluate {};
      cleartext = evaluate {
        enable = true;
        workerProcesses = 2;
        upstreams.application.servers = [{address = "127.0.0.1:3000";}];
        virtualHosts.default = {
          listen = [8080];
          serverNames = ["example.test"];
          locations."/".proxyPass = "http://application";
        };
      };
      tls = evaluate {
        enable = true;
        virtualHosts.default = {
          listen = [8443];
          tls.enable = true;
        };
        tlsCredentials = {
          certificate.resource = credential "tls-certificate";
          privateKey.resource = credential "tls-private-key";
        };
      };
      assertionsHold = evaluation:
        builtins.all (assertion: assertion.assertion) evaluation.config.assertions;
      ownedValues = lib.filterAttrs (_: value: value.package == self.pname);
      disabledAbilities = disabled.config.aos.abilities;
      cleartextAbilities = cleartext.config.aos.abilities;
      tlsAbilities = tls.config.aos.abilities;
      cleartextRequests = builtins.attrNames cleartextAbilities.requests;
      tlsRequests = builtins.attrNames tlsAbilities.requests;
      source = cleartextAbilities.requests."nginx:server-configuration".parameters.source;
      mainStorage = cleartextAbilities.requests."nginx:main-storage".parameters.mounts;
      publicOptionSchemas =
        builtins.map
        (option: option.type._abilitySchema)
        [
          cleartext.options.nginx.upstreams
          cleartext.options.nginx.virtualHosts
          cleartext.options.nginx.tlsCredentials.certificate
          cleartext.options.nginx.tlsCredentials.privateKey
        ];
      expectedRequestOutput = localKey: output: {
        package = self.pname;
        inherit localKey output;
      };
      contractHolds =
        builtins.deepSeq publicOptionSchemas true
        && assertionsHold cleartext
        && assertionsHold tls
        && ownedValues disabledAbilities.instances == {}
        && ownedValues disabledAbilities.requests == {}
        && builtins.elem "nginx:configuration-materialization" (builtins.attrNames disabledAbilities.requirementTemplates)
        && builtins.elem "nginx:service-lifecycle" (builtins.attrNames disabledAbilities.requirementTemplates)
        && builtins.elem "nginx:main-lifecycle" cleartextRequests
        && !(builtins.elem "nginx:main-credentials" cleartextRequests)
        && builtins.elem "nginx:main-credentials" tlsRequests
        && builtins.elem "nginx:credential-tls-certificate" tlsRequests
        && builtins.elem "nginx:credential-tls-private-key" tlsRequests
        && source.kind == "interpolated-text"
        && builtins.any (fragment: fragment.kind == "artifact-file-path") source.fragments
        && builtins.any (fragment: fragment.kind == "execution-path") source.fragments
        && builtins.map
        (mount:
          lib.abilities.requestOutputIdentity {
            requests = cleartextAbilities.requests;
            reference = mount.source;
          })
        mainStorage
        == [
          (expectedRequestOutput "runtime-storage" "planned-path")
          (expectedRequestOutput "state-storage" "planned-path")
          (expectedRequestOutput "log-storage" "planned-path")
        ]
        && !(lib.hasInfix "/etc/nginx" (builtins.toJSON cleartextAbilities.requests))
        && !(lib.hasInfix "/run/credentials" (builtins.toJSON tlsAbilities.requests));
    in
      {
        version = testing.mkToolCheck {
          pname = "tool-nginx";
          tool = self;
          command = "nginx -V 2>&1";
        };

        ability-contract =
          if contractHolds
          then
            pkgs.runCommand "nginx-production-ability-contract" {} ''
              mkdir -p "$out"
              printf '%s\n' PASS >"$out/result"
            ''
          else throw "the nginx ability module contract checks failed";
      }
      // lib.optionalAttrs (
        pkgs.stdenv.hostPlatform.isLinux
        && builtins.elem pkgs.stdenv.hostPlatform.constraints.cpu ["aarch64" "x86_64"]
      ) {
        openssl-consumption = lib.mkArtifactConsumptionAudit {
          inherit pkgs;
          name = "nginx-openssl-linkage";
          consumer = self;
          consumerPath = "/bin/nginx";
          provider = openssl;
          providerPath = "/lib/libssl.so.4";
          targetPlatform = {
            system = pkgs.stdenv.hostPlatform.constraints.os;
            architecture = pkgs.stdenv.hostPlatform.constraints.cpu;
          };
          soname = "libssl.so.4";
          needed = [
            "libc.so.6"
            "libcrypto.so.4"
            "libpcre2-8.so.0"
            "libssl.so.4"
            "libz.so.1"
          ];
          searchPath = [
            "${pkgs.stdenv.glibc}/lib"
            "${openssl}/lib"
            "${pcre2}/lib"
            "${zlib}/lib"
          ];
          searchPathKind = "runpath";
          symbols = [
            {
              name = "SSL_read";
              version = "OPENSSL_4.0.0";
            }
          ];
          loader = "${pkgs.stdenv.glibc}/lib/${pkgs.stdenv.hostPlatform.dynamicLinker}";
          inspector = pkgs.buildPackages.aos;
        };
      };
  }
