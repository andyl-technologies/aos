##! modules/services/seed.nix — Seed server orchestration module
##!
##! Configures a zone-level infrastructure server that builds AOS images from
##! source and serves them over HTTPS for iPXE network boot. Each zone has one
##! seed server. Built images are stored at runtime on ZFS datasets, not baked
##! into the image.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.seed;

  # Build script for image building service.
  buildScript = ''
    #!/bin/sh
    set -e
    SRCDIR=/var/lib/aos/src
    IMGDIR=/var/lib/aos/images
    STAGING=/var/lib/aos/staging

    # Ensure staging directory exists
    mkdir -p "$STAGING"

    for variant in ${builtins.concatStringsSep " " cfg.variants}; do
      echo "Building variant: $variant"
      mkdir -p "$STAGING/$variant"

      # Build the image using Nix
      result=$(nix-build "$SRCDIR" -A "images.$variant" --no-out-link)

      # Extract artifacts
      cp "$result/kernel" "$STAGING/$variant/kernel" 2>/dev/null || true
      cp "$result/initrd" "$STAGING/$variant/initrd" 2>/dev/null || true

      if [ -f "$result/image.raw" ]; then
        zstd -f -T0 "$result/image.raw" -o "$STAGING/$variant/image.raw.zst"
      fi

      # Write metadata
      printf '{"variant":"%s","timestamp":"%s","store_path":"%s"}\n' \
        "$variant" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" \
        > "$STAGING/$variant/metadata.json"

      echo "Finished building: $variant"
    done
  '';

  # Publish script — atomically move built artifacts to serving directory.
  publishScript = ''
    #!/bin/sh
    set -e
    IMGDIR=/var/lib/aos/images
    STAGING=/var/lib/aos/staging

    for variant in ${builtins.concatStringsSep " " cfg.variants}; do
      if [ -d "$STAGING/$variant" ]; then
        mkdir -p "$IMGDIR/$variant"
        # Atomic move of each file
        for f in "$STAGING/$variant"/*; do
          if [ -f "$f" ]; then
            mv -f "$f" "$IMGDIR/$variant/"
          fi
        done
      fi
    done

    # Create iPXE boot script placeholder
    mkdir -p "$IMGDIR/ipxe"
    cat > "$IMGDIR/ipxe/boot.ipxe" << 'IPXE'
    #!ipxe
    # AOS iPXE boot script — placeholder
    # Configure variant selection logic here.
    echo AOS network boot
    shell
    IPXE
  '';
in {
  options.aos.services.seed = {
    ## Enable the AOS seed server for building and serving OS images.
    ##
    ## # See Also
    ## - `aos.services.seed.domain`, `aos.services.seed.variants`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the AOS seed server for building and serving OS images.";
    };

    ## Public FQDN for the seed server (used for ACME cert and nginx vhost).
    domain = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Public FQDN for the seed server (used for ACME cert and nginx vhost).";
    };

    ## Path to htpasswd file for image download authentication.
    basicAuthFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/seed-htpasswd";
      description = "Path to htpasswd file for image download authentication.";
    };

    ## System variants to build and serve.
    variants = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "server"
        "k8s-worker"
        "k8s-control-plane"
      ];
      description = "System variants to build and serve.";
    };

    ## Systemd calendar expression for build timer.
    buildInterval = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "Systemd calendar expression for build timer (e.g. 'daily', 'hourly', 'weekly').";
    };
  };

  config = lib.mkIf cfg.enable {
    # ZFS datasets for image storage and source checkout.
    aos.filesystems.zfs.datasets."var/lib/aos" = {
      mountpoint = "/var/lib/aos";
      compression = "zstd-3";
      atime = "off";
    };
    aos.filesystems.zfs.datasets."var/lib/aos/images" = {
      mountpoint = "/var/lib/aos/images";
      compression = "zstd-3";
      atime = "off";
    };
    aos.filesystems.zfs.datasets."var/lib/aos/src" = {
      mountpoint = "/var/lib/aos/src";
      compression = "zstd-3";
      atime = "off";
    };

    # Configure nginx virtual host for serving images.
    aos.services.nginx.virtualHosts."seed" = {
      serverName = cfg.domain;
      acme = true;
      basicAuth = true;
      basicAuthFile = cfg.basicAuthFile;
      root = "/var/lib/aos/images";
      autoindex = true;
      extraConfig = ''
        # Optimize for large file downloads.
        sendfile on;
        tcp_nopush on;
        directio 4m;
      '';
    };

    # Ensure seed directories exist.
    environment.etc."tmpfiles.d/aos-seed.conf" = {
      text = ''
        # Seed server state directories.
        d /var/lib/aos 0755 root root -
        d /var/lib/aos/images 0755 root root -
        d /var/lib/aos/images/ipxe 0755 root root -
        d /var/lib/aos/src 0755 root root -
        d /var/lib/aos/staging 0755 root root -
        d /etc/aos 0750 root root -
      '';
    };

    # aos-build-images.service — builds system images from source.
    systemd.services."aos-build-images" = {
      description = "AOS Image Builder";
      after = [
        "network-online.target"
        "nix-daemon.service"
        "local-fs.target"
      ];
      wants = ["network-online.target"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.bash}/bin/sh -c '${buildScript}'";
        TimeoutStartSec = "7200";
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };

    # aos-build-images.timer — periodic build trigger.
    systemd.services."aos-build-images-timer" = {
      description = "AOS Image Build Timer";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.buildInterval;
        Persistent = true;
        RandomizedDelaySec = "1800";
      };
    };

    # aos-publish-images.service — atomically publishes built images.
    systemd.services."aos-publish-images" = {
      description = "AOS Image Publisher";
      after = ["aos-build-images.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.bash}/bin/sh -c '${publishScript}'";
      };
    };
  };
}
