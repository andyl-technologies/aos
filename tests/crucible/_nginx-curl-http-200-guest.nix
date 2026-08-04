{pkgs}: let
  closureDeps = [
    pkgs.bash
    pkgs.coreutils
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

          mkdir -p rootfs/bin rootfs/dev rootfs/etc/nginx rootfs/nix/store
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
              while :; do
                status=$(curl \
                  --connect-timeout 30 \
                  --max-time 60 \
                  --output /dev/null \
                  --silent \
                  --write-out '%{http_code}' \
                  http://10.0.0.2:8080/ || true)
                if [ "$status" = 200 ]; then
                  echo CURL_STATUS=200
                  while :; do
                    sleep 3600
                  done
                fi
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
