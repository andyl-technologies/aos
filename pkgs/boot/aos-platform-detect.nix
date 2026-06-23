##! aos-platform-detect — initrd-time ignition platform auto-detect
##!
##! Runs in stage-1 before `ignition-fetch.service` and writes
##! `/run/ignition/platform.env` containing `PLATFORM_ID=<name>` (and,
##! when the operator-placed ISO9660 metadata channel fires,
##! `IGNITION_CONFIG_FILE=<path>` as well). The ignition stage units
##! inherit the env-file so `ignition --platform=${PLATFORM_ID}` picks
##! up the right platform at each stage.
##!
##! Detection order:
##!   1. filesystem label `aos-metadata` — operator override (ISO9660
##!      mounted at /run/aos-metadata, `file` platform + config path)
##!   2. DMI vendor/product/asset-tag → platform enum
##!   3. Fallback: "metal"
##!
##! See the plan's §7 for the asset-tag ordering rationale (Azure and
##! Oracle Cloud both use chassis-asset-tag, not vendor strings) and
##! the platform enum comes from the upstream ignition binary.
{
  mkDerivation,
  bash,
  coreutils,
  util-linux,
}:
mkDerivation {
  pname = "aos-platform-detect";
  version = "0";
  src = null;

  runtimeDeps = [
    bash
    coreutils
    util-linux
  ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin

        cat > $out/bin/aos-platform-detect << 'SCRIPT'
        #!${bash}/bin/bash
        set -eu

        ${coreutils}/bin/mkdir -p /run/ignition

        # 1. Operator-placed ISO9660 override. Mount the filesystem at
        #    /run/aos-metadata so ignition's `file` platform reader can
        #    slurp config.json via IGNITION_CONFIG_FILE.
        metadata_dev=$(${util-linux}/sbin/blkid -L aos-metadata 2>/dev/null || true)
        if [ -n "$metadata_dev" ]; then
            ${coreutils}/bin/mkdir -p /run/aos-metadata
            ${util-linux}/bin/mount -o ro "$metadata_dev" /run/aos-metadata
            ${coreutils}/bin/cat >/run/ignition/platform.env <<EOF
        PLATFORM_ID=file
        IGNITION_CONFIG_FILE=/run/aos-metadata/config.json
        EOF
            exit 0
        fi

        # 2. DMI identification — first hit wins. Read helpers guarded
        #    so missing sysfs entries don't break the script.
        read_dmi() {
            ${coreutils}/bin/cat "/sys/class/dmi/id/$1" 2>/dev/null | ${coreutils}/bin/tr -d '\n' || ${coreutils}/bin/printf ""
        }
        sys_vendor=$(read_dmi sys_vendor)
        bios_vendor=$(read_dmi bios_vendor)
        product=$(read_dmi product_name)
        asset_tag=$(read_dmi chassis_asset_tag)

        platform=""

        # 2a. Asset-tag: Azure and Oracle Cloud write a fixed string here
        #     rather than putting their name in sys_vendor.
        case "$asset_tag" in
            "7783-7084-3265-9085-8269-3286-77")  platform=azure ;;
            "OracleCloud.com")                   platform=oraclecloud ;;
        esac

        # 2b. sys_vendor — covers the bulk of cloud platforms.
        if [ -z "$platform" ]; then
            case "$sys_vendor" in
                "Amazon EC2")             platform=aws ;;
                "Google")                 platform=gcp ;;
                "Microsoft Corporation")
                    [ "$product" = "Virtual Machine" ] && platform=hyperv ;;
                "DigitalOcean")           platform=digitalocean ;;
                "Hetzner")                platform=hetzner ;;
                "Vultr")                  platform=vultr ;;
                "Scaleway")               platform=scaleway ;;
                "OpenStack Foundation")   platform=openstack ;;
                "VMware, Inc.")           platform=vmware ;;
                "innotek GmbH")           platform=virtualbox ;;
                "QEMU")                   platform=qemu ;;
            esac
        fi

        # 2c. bios_vendor — AWS Nitro bare-metal puts OEM in sys_vendor
        #     but "Amazon EC2" in bios_vendor.
        if [ -z "$platform" ]; then
            case "$bios_vendor" in
                "Amazon EC2")             platform=aws ;;
            esac
        fi

        # 2d. product_name — catches GCP (sys_vendor = "Google") and
        #     generic QEMU (product "Standard PC (…)"; sys_vendor often
        #     empty or matches a non-cloud builder).
        if [ -z "$platform" ]; then
            case "$product" in
                "Google Compute Engine")  platform=gcp ;;
                "Standard PC"*)           platform=qemu ;;
            esac
        fi

        # 3. Fallback — bare metal. Ignition's `metal` provider returns
        #    an empty config on its own, but still honours
        #    `ignition.config.url=` on /proc/cmdline as an escape hatch
        #    for operators who want to supply a URL via firmware kargs.
        if [ -z "$platform" ]; then
            platform=metal
        fi

        # 4. Network-dependent platforms fetch their config over IP from an
        #    instance metadata server, so stage-1 must bring up DHCP first.
        #    Drop a flag file the aos-ignition-network gate keys off
        #    (ConditionPathExists); the local-ISO `file` path above never
        #    reaches here and so never networks.
        needs_network=
        case "$platform" in
            aws|gcp|azure|digitalocean|hetzner|vultr|scaleway|openstack|oraclecloud)
                needs_network=1
                ${coreutils}/bin/touch /run/ignition/need-network
                ;;
        esac

        ${coreutils}/bin/cat >/run/ignition/platform.env <<EOF
        PLATFORM_ID=$platform
        ''${needs_network:+IGNITION_NEEDS_NETWORK=$needs_network}
        EOF
        SCRIPT
        chmod +x $out/bin/aos-platform-detect
      '';
    }
  ];

  meta = {
    description = "AOS initrd platform auto-detector for ignition";
  };
}
