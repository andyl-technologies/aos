{pkgs}: let
  closureDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.crucible-guest
    pkgs.curl
    pkgs.envoy
    pkgs.iproute2
    pkgs.nginx
    pkgs.python3
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
    pname = "crucible-envoy-network-root-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.fakeroot
      pkgs.grep
      pkgs.sed
    ];
    runtimeDeps = [];
    exportReferencesGraph = closureGraph;
    dontNukeRefs = true;

    phases = [
      {
        name = "build-envoy-network-root-image";
        script = ''
          set -eu

          mkdir -p rootfs/bin rootfs/dev rootfs/etc/crucible rootfs/etc/nginx rootfs/mnt
          mkdir -p rootfs/nix/store rootfs/proc rootfs/run rootfs/sys rootfs/tmp
          mkdir -p rootfs/var/lib/nginx rootfs/var/log/nginx

          grep -h '^/nix/store/' guest-closure-* | sort -u > closure-paths
          while IFS= read -r path; do
            target="rootfs$path"
            mkdir -p "$(dirname "$target")"
            cp -a "$path" "$target"
          done < closure-paths

          ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/sh
          ln -sfn ${pkgs.bash}/bin/bash rootfs/bin/bash

          sed 's|@GUEST_PATH@|${guestPath}|g' \
            ${./fixtures/envoy-network/init.sh} > rootfs/init
          cp ${./fixtures/envoy-network/render-envoy.sh} \
            rootfs/etc/crucible/render-envoy.sh
          cp ${./fixtures/envoy-network/traffic.py} \
            rootfs/etc/crucible/traffic.py
          chmod 0755 rootfs/init rootfs/etc/crucible/render-envoy.sh

          cat > rootfs/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/sh
          PASSWD
          cat > rootfs/etc/group <<'GROUP'
          root:x:0:
          GROUP

          cat > rootfs/etc/nginx/nginx.conf <<'NGINX_CONFIG'
          user root;
          worker_processes 1;
          error_log /proc/self/fd/2 notice;
          pid /run/nginx.pid;

          events {
            worker_connections 128;
          }

          http {
            access_log off;
            server {
              listen 10.77.0.5:8080;

              location /healthz {
                return 200 "healthy";
              }

              location /probe {
                default_type text/plain;
                return 200 "east:$arg_seq:$http_x_crucible_a:$http_x_crucible_b:$http_x_crucible_c";
              }
            }
          }
          NGINX_CONFIG

          apparent_kb=$(du -sk --apparent-size rootfs | cut -f1)
          apparent_mib=$(( (apparent_kb + 1023) / 1024 ))
          image_mib=$(( apparent_mib * 5 / 4 + 128 ))
          if [ "$image_mib" -lt 512 ]; then
            image_mib=512
          fi

          mkdir -p "$out"
          fakeroot -- mkfs.ext4 \
            -d rootfs \
            -L crucible-envoy-network \
            -m 0 \
            -q \
            -O '^has_journal,^metadata_csum,^64bit' \
            "$out/root.ext4" \
            "''${image_mib}M"
          chmod 0444 "$out/root.ext4"
          sha256sum "$out/root.ext4" > "$out/root.ext4.sha256"
        '';
      }
    ];
  }
