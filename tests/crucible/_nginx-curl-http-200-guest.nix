{
  pkgs,
  hotForkEquivalence ? false,
}: let
  closureDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.crucible-guest
    pkgs.curl
    pkgs.iproute2
    pkgs.nginx
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
    pname = "crucible-nginx-curl-http-200-root-image";
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

          ip link set lo up
          ip link set eth0 up

          cmdline=" $(cat /proc/cmdline) "
          case "$cmdline" in
            *" crucible.workload=httpd "*)
              ip address add 10.0.0.2/24 dev eth0
              exec nginx -c /etc/nginx/nginx.conf -g 'daemon off; master_process off;'
              ;;
            *" crucible.workload=httpget "*)
              ip address add 10.0.0.3/24 dev eth0
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
                  --output /dev/null \
                  --silent \
                  --write-out '%{http_code}' \
                  http://10.0.0.2:8080/ || true)
                if [ "$status" = 200 ]; then
                  if [ "$reported" = 0 ]; then
                    crucible-guest sometimes \
                      curl-receives-http-200 \
                      'Curl receives an HTTP 200 response from Nginx' \
                      1
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
                    # Let the modeled permanent-failure signal settle before
                    # the guest blocks at the retained choice boundary. Under
                    # deterministic icount this is guest virtual time, not a
                    # host-side readiness delay.
                    sleep 35
                    selection=$(crucible-guest selectable choose-u64 \
                      1 hot-fork.retry-quanta continuation/one 1 9 2)
                    test "$selection" = u64=7
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
              mount -t 9p -o trans=virtio,version=9p2000.L,msize=8192 crucible /mnt
              ninep_content=$(cat /mnt/probe.txt)
              test "$ninep_content" = CRUCIBLE-9P-OK

              crucible-guest sometimes \
                io-probe-complete \
                'The I/O probe read its 9p sub-node' \
                1
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
