##! Test-only package that prepares the blank ZFS pool device used by VM checks.
{
  coreutils,
  lib,
  mkDerivation,
  writeShellScriptBin,
  zfs,
}: let
  preparePool = writeShellScriptBin "aos-zfs-test-pool" ''
    set -eu

    pool_name=$1
    pool_device=$2
    export PATH="${lib.makeBinPath [coreutils]}:${lib.makeSearchPath "sbin" [zfs]}"

    if zpool list -H "$pool_name" >/dev/null 2>&1; then
      exit 0
    fi
    if zpool import -N -f "$pool_name" >/dev/null 2>&1; then
      exit 0
    fi

    zpool create -f -o ashift=12 -o autotrim=on -o compatibility=openzfs-2.3 \
      -O compression=zstd-3 -O atime=off -O mountpoint=none \
      -O recordsize=128K -O dedup=off -O xattr=sa -O acltype=posixacl \
      "$pool_name" "$pool_device"
  '';
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
    pname = "aos-zfs-test-pool";
    version = "1.0.0";
    src = null;

    runtimeDeps = [preparePool coreutils zfs];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${preparePool}/bin/aos-zfs-test-pool "$out/bin/aos-zfs-test-pool"
        '';
      }
    ];

    abilities = ./_aos-zfs-test-pool;

    meta = {
      description = "Prepare the blank ZFS pool used by AOS VM checks";
      license = "Apache-2.0";
    };
  }
