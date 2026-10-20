# Formats disposable regular-file images with the exact installed launcher.
# Validation metadata is separate from formatter discovery; sandbox backing
# filesystems need not support its extended attributes. No block device is used.
set -euo pipefail

launcher=$1
scratch=$2
environment=$3
sfdisk=$4
jq=$5

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

# A metadata-only marker update must preserve every other GPT field. The real
# sfdisk path avoids a kernel rescan; only udev observation is refreshed at boot.
definitions="$scratch/marker.d"
mkdir -p "$definitions"
cat > "$definitions/marker.conf" <<EOF
[Partition]
Type=163bea60-58c7-46e7-b69a-6846a5a688af
Label=aos-provisioning-pending-v1
UUID=01234567-89ab-cdef-8123-456789abcdef
SizeMinBytes=4M
SizeMaxBytes=4M
EOF

"$environment" -i TMPDIR="$scratch" "$launcher" \
    --definitions="$definitions" --empty=create --size=16M \
    --dry-run=no --offline=yes "$scratch/marker.img"
"$sfdisk" --json "$scratch/marker.img" > "$scratch/marker-before.json"
"$sfdisk" --no-reread --no-tell-kernel --part-label \
    "$scratch/marker.img" 1 aos-provenance-operator-v1
"$sfdisk" --json "$scratch/marker.img" > "$scratch/marker-after.json"
"$jq" -e --slurpfile before "$scratch/marker-before.json" \
    '. == ($before[0] | .partitiontable.partitions[0].name = "aos-provenance-operator-v1")' \
    "$scratch/marker-after.json"
