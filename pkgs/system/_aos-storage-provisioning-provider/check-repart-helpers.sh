# Formats disposable regular-file images with the exact installed launcher.
# Validation metadata is separate from formatter discovery; sandbox backing
# filesystems need not support its extended attributes. No block device is used.
set -euo pipefail

launcher=$1
scratch=$2
environment=$3

mkdir -p "$scratch"

for filesystem in swap ext4 xfs vfat; do
    definitions="$scratch/$filesystem.d"
    mkdir -p "$definitions"

    partition_type=linux-generic
    if [ "$filesystem" = swap ]; then
        partition_type=swap
    fi

    cat > "$definitions/partition.conf" <<EOF
[Partition]
Type=$partition_type
Format=$filesystem
AddValidateFS=no
SizeMinBytes=384M
SizeMaxBytes=384M
EOF

    "$environment" -i TMPDIR="$scratch" "$launcher" \
        --definitions="$definitions" --empty=create --size=512M \
        --dry-run=no --offline=yes "$scratch/$filesystem.img"
done
