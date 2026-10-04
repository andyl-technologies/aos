{
  pkgs,
  hotForkEquivalence ? false,
  strictHttpResponse ? false,
  httpServer ? "nginx",
}: let
  envoyDirect = assert builtins.elem httpServer ["nginx" "envoy-direct"];
  assert httpServer != "envoy-direct" || (strictHttpResponse && !hotForkEquivalence);
    httpServer == "envoy-direct";
  serverName =
    if envoyDirect
    then "Envoy"
    else "nginx";
  responseBody = "Crucible reached ${serverName}\n";
  envoyConfig = builtins.toJSON {
    static_resources.listeners = [
      {
        name = "direct_response";
        address.socket_address = {
          address = "10.0.0.2";
          port_value = 8080;
        };
        filter_chains = [
          {
            filters = [
              {
                name = "envoy.filters.network.http_connection_manager";
                typed_config = {
                  "@type" = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
                  stat_prefix = "direct_response";
                  route_config = {
                    name = "direct_response";
                    virtual_hosts = [
                      {
                        name = "service";
                        domains = ["*"];
                        routes = [
                          {
                            match.prefix = "/";
                            direct_response = {
                              status = 200;
                              body.inline_string = responseBody;
                            };
                          }
                        ];
                      }
                    ];
                  };
                  http_filters = [
                    {
                      name = "envoy.filters.http.router";
                      typed_config."@type" = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";
                    }
                  ];
                };
              }
            ];
          }
        ];
      }
    ];
  };
  closureDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.crucible-guest
    pkgs.curl
    pkgs.iproute2
    (
      if envoyDirect
      then pkgs.envoy
      else pkgs.nginx
    )
    pkgs.util-linux
  ];
  closureGraph =
    pkgs.lib.concatLists
    (pkgs.lib.imap (index: dependency: [
        "guest-closure-${builtins.toString index}"
        dependency
      ])
      closureDeps);
  guestPath = pkgs.lib.concatStringsSep ":" (
    builtins.concatMap (dependency: [
      "${dependency}/bin"
      "${dependency}/sbin"
    ])
    closureDeps
  );
  hotForkEquivalenceEnabled =
    if hotForkEquivalence
    then "1"
    else "0";
in
  pkgs.mkDerivation {
    pname = "crucible-${httpServer}-curl-http-200-root-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.fakeroot
    ];
    runtimeDeps = [];
    exportReferencesGraph = closureGraph;
    dontNukeRefs = true;

    phases = [
      {
        name = "build-nginx-curl-root-image";
        script = ''
          set -eu

          copy_closure() {
            grep -h '^/nix/store/' guest-closure-* | sort -u > closure-paths
            while IFS= read -r path; do
              target="rootfs$path"
              mkdir -p "$(dirname "$target")"
              cp -a "$path" "$target"
            done < closure-paths
          }

          mkdir -p rootfs/bin rootfs/dev rootfs/etc/nginx rootfs/mnt rootfs/nix/store
          mkdir -p rootfs/proc rootfs/run/nginx rootfs/sys rootfs/tmp
          mkdir -p rootfs/usr/bin rootfs/usr/sbin rootfs/var/lib/nginx
          mkdir -p rootfs/var/log/nginx rootfs/var/tmp
          copy_closure

          ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/sh
          ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/bash

          cat > rootfs/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/sh
          nginx:x:101:101:nginx:/var/lib/nginx:/bin/sh
          PASSWD
          cat > rootfs/etc/group <<'GROUP'
          root:x:0:
          nginx:x:101:
          GROUP

          cat > rootfs/etc/nginx/nginx.conf <<'NGINX_CONFIG'
          user nginx nginx;
          worker_processes 1;
          error_log /dev/stderr notice;
          pid /run/nginx/nginx.pid;

          events {
            worker_connections 64;
          }

          http {
            access_log off;
            server {
              listen 10.0.0.2:8080;
              location / {
                default_type text/plain;
                return 200 "Crucible reached nginx\n";
              }
            }
          }
          NGINX_CONFIG

          ${pkgs.lib.optionalString envoyDirect ''
            cat > rootfs/etc/envoy-direct.json <<'ENVOY_CONFIG'
            ${envoyConfig}
            ENVOY_CONFIG
          ''}

          cat > rootfs/init <<'INIT'
          #!/bin/sh
          set -eu

          export PATH="${guestPath}"
          export HOME=/tmp

          mkdir -p /proc /sys /dev /run/nginx /tmp /var/lib/nginx /var/log/nginx
          mount -t proc proc /proc
          mount -t sysfs sysfs /sys
          mount -t devtmpfs devtmpfs /dev
          mount -t tmpfs tmpfs /run
          mkdir -p /run/nginx
          chown -R 101:101 /run/nginx /var/lib/nginx /var/log/nginx

          ${pkgs.lib.optionalString strictHttpResponse ''
            crucible-guest event boot.init-mounted
          ''}

          ip link set lo up
          ip link set eth0 up

          cmdline=" $(cat /proc/cmdline) "
          case "$cmdline" in
          *" crucible.workload=httpd "*)
              ip address add 10.0.0.2/24 dev eth0
              ${pkgs.lib.optionalString strictHttpResponse ''
            crucible-guest event boot.network-configured
            crucible-guest event boot.service-starting
            # This attests init/network setup, not HTTP service readiness.
            crucible-guest setup-complete
          ''}
              ${
            if envoyDirect
            then ''
              envoy --mode validate --config-path /etc/envoy-direct.json
              exec envoy --disable-hot-restart --concurrency 1 \
                --config-path /etc/envoy-direct.json --log-level info
            ''
            else "exec nginx -c /etc/nginx/nginx.conf -g 'daemon off; master_process off;'"
          }
              ;;
            *" crucible.workload=httpget "*)
              ip address add 10.0.0.3/24 dev eth0
              ${pkgs.lib.optionalString strictHttpResponse ''
            crucible-guest event boot.network-configured
            crucible-guest event boot.service-starting
            crucible-guest setup-complete
          ''}
              if [ "${hotForkEquivalenceEnabled}" = 1 ]; then
                crucible-guest selectable register-u64 \
                  1 hot-fork.retry-quanta 1 9 2 3 quanta
                crucible-guest setup-complete
                crucible-guest measurement-begin hot-fork-window instance-1
                crucible-guest semantic-marker hot-fork-window-begin instance-1
              fi
              case "$cmdline" in
                *" probe-block=1 "*)
                  block_prefix=$(dd if=/dev/vdb bs=18 count=1 2>/dev/null)
                  test "$block_prefix" = CRUCIBLE-BLOCK-OK
                  crucible-guest sometimes \
                    curl-block-read-complete \
                    'Curl read its block sub-node' \
                    1
                  ;;
              esac
              reported=0
              selection_complete=0
              while :; do
                status=$(curl \
                  --connect-timeout 30 \
                  --max-time 60 \
                  --output ${
            if strictHttpResponse
            then "/tmp/http-response"
            else "/dev/null"
          } \
                  --silent \
                  --write-out '%{http_code}' \
                  http://10.0.0.2:8080/ || true)
                if [ "$status" = 200 ]; then
                  if [ "$reported" = 0 ]; then
                    ${pkgs.lib.optionalString strictHttpResponse ''
            # The marker authenticates a complete application response,
            # not only a successful TCP connection or status line.
            test "$(cat /tmp/http-response)" = 'Crucible reached ${serverName}'
            test "$(wc -c < /tmp/http-response)" -eq ${toString (builtins.stringLength responseBody)}
          ''}
                    crucible-guest sometimes \
                      curl-receives-http-200 \
                      'Curl receives an HTTP 200 response from ${
            if envoyDirect
            then "Envoy"
            else "Nginx"
          }' \
                      1
                    ${pkgs.lib.optionalString strictHttpResponse ''
            crucible-guest semantic-marker http.request-response instance-1
          ''}
                    reported=1
                  fi
                  if [ "${hotForkEquivalenceEnabled}" = 1 ] \
                    && [ "$selection_complete" = 0 ]; then
                    (
                      while :; do
                        curl \
                          --connect-timeout 30 \
                          --max-time 60 \
                          --output /dev/null \
                          --silent \
                          http://10.0.0.2:8080/ || true
                        dd if=/dev/zero of=/dev/vdb \
                          bs=512 count=1 seek=8 conv=notrunc 2>/dev/null
                      done
                    ) &
                    # Leave the routed queue and volatile cache live while the
                    # guest stops at the exact pre-fault choice boundary.
                    sleep 2
                    selection=$(crucible-guest selectable choose-u64 \
                      1 hot-fork.retry-quanta continuation/one 1 9 2)
                    test "$selection" = u64=7
                    mkdir -p /known-dirty
                    mount -t tmpfs -o size=8m tmpfs /known-dirty
                    dd if=/dev/zero of=/known-dirty/pages bs=4096 count=1024 2>/dev/null
                    crucible-guest metric-sample \
                      hot-fork-window instance-1 selected-retry u64 7
                    crucible-guest measurement-end hot-fork-window instance-1
                    crucible-guest semantic-marker hot-fork-window-end instance-1
                    crucible-guest sometimes \
                      hot-fork-continuation-complete \
                      'The selected continuation completed' \
                      1
                    selection_complete=1
                  fi
                  case "$cmdline" in
                    *" continue=1 "*) ;;
                    *)
                      while :; do
                        sleep 3600
                      done
                      ;;
                  esac
                fi
              done
              ;;
            *" crucible.workload=bench "*)
              mount -t 9p \
                -o trans=virtio,version=9p2000.L,msize=8192,cache=none \
                crucible /mnt
              ninep_content=$(cat /mnt/probe.txt)
              test "$ninep_content" = CRUCIBLE-9P-OK

              crucible-guest sometimes \
                io-probe-complete \
                'The I/O probe read its 9p sub-node' \
                1
              while :; do
                if ! cat /mnt/probe.txt > /dev/null 2>&1; then
                  crucible-guest sometimes \
                    io-probe-fault-observed \
                    'The I/O probe observed its injected 9p read error' \
                    1
                  break
                fi
                sleep 1
              done
              while :; do
                sleep 3600
              done
              ;;
            *" crucible.workload=hot-fork-single "*)
              block_prefix=$(dd if=/dev/vdb bs=18 count=1 2>/dev/null)
              test "$block_prefix" = CRUCIBLE-BLOCK-OK
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=8192 crucible /mnt
              ninep_content=$(cat /mnt/probe.txt)
              test "$ninep_content" = CRUCIBLE-9P-OK

              crucible-guest selectable register-u64 \
                1 hot-fork.retry-quanta 1 9 2 3 quanta
              crucible-guest setup-complete
              crucible-guest measurement-begin hot-fork-window instance-1
              crucible-guest semantic-marker hot-fork-window-begin instance-1
              selection=$(crucible-guest selectable choose-u64 \
                1 hot-fork.retry-quanta continuation/one 1 9 2)
              test "$selection" = u64=7
              mkdir -p /known-dirty
              mount -t tmpfs -o size=8m tmpfs /known-dirty
              dd if=/dev/zero of=/known-dirty/pages bs=4096 count=1024 2>/dev/null
              crucible-guest metric-sample \
                hot-fork-window instance-1 selected-retry u64 7
              crucible-guest measurement-end hot-fork-window instance-1
              crucible-guest semantic-marker hot-fork-window-end instance-1
              crucible-guest sometimes \
                hot-fork-continuation-complete \
                'The selected continuation completed' \
                1
              while :; do
                sleep 3600
              done
              ;;
            *" crucible.workload=hot-fork-scaling "*)
              crucible-guest selectable register-u64 \
                1 hot-fork.retry-quanta 1 9 2 3 quanta
              crucible-guest setup-complete
              crucible-guest measurement-begin hot-fork-window instance-1
              crucible-guest semantic-marker hot-fork-window-begin instance-1
              for sequence in 1 2 3 4; do
                selection=$(crucible-guest selectable choose-u64 \
                  "$sequence" hot-fork.retry-quanta \
                  "scaling/$sequence" 1 9 2)
                test "$selection" = u64=7
              done
              while :; do
                sleep 3600
              done
              ;;
            *)
              echo CRUCIBLE_WORKLOAD_UNKNOWN
              exit 1
              ;;
          esac
          INIT
          chmod 0755 rootfs/init

          apparent_kb=$(du -sk --apparent-size rootfs | cut -f1)
          apparent_mib=$(( (apparent_kb + 1023) / 1024 ))
          image_mib=$(( apparent_mib * 3 / 2 + 64 ))
          if [ "$image_mib" -lt 256 ]; then
            image_mib=256
          fi

          mkdir -p $out
          fakeroot -- mkfs.ext4 \
            -d rootfs \
            -L crucible-http \
            -m 0 \
            -q \
            -O '^has_journal,^metadata_csum,^64bit' \
            $out/root.ext4 \
            "''${image_mib}M"
          chmod 0444 $out/root.ext4
          sha256sum $out/root.ext4 > $out/root.ext4.sha256
        '';
      }
    ];
  }
