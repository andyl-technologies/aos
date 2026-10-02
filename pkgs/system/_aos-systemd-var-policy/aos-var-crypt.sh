#!@bash@/bin/bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: aos-var-crypt PCR_PUBLIC_KEY SIGNED_PCRS PINNED_PCRS RECOVERY_KEY_PATH" >&2
  exit 2
fi

export PATH=@coreutils@/bin:@util-linux@/bin:@util-linux@/sbin:@cryptsetup@/bin:@cryptsetup@/sbin

pub=$1
signed_pcrs=$2
pinned_pcrs=$3
var_recovery_key=$4
enroll=@systemd@/bin/systemd-cryptenroll
csetup=@systemd@/lib/systemd/systemd-cryptsetup
cs=@cryptsetup@/sbin/cryptsetup
mkfs=@e2fsprogs@/sbin/mkfs.ext4
mkfs_xfs=@xfsprogs@/sbin/mkfs.xfs
blkid=@util-linux@/sbin/blkid
sbvar=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
volumes=/run/aos-metadata/storage-volumes
volume_recovery_dir=/run/aos-volume-recovery
# Log to /dev/kmsg — the console (ttyS0) is contended by the
# initrd debug shell whose escape sequences corrupt the serial.
klog() { echo "aos-var-crypt: $*" > /dev/kmsg 2>/dev/null || echo "aos-var-crypt: $*" >&2; }

# Make the systemd-tpm2 LUKS2 token plugin findable. cryptsetup
# dlopens external token plugins by absolute path from its
# configured tokens dir (/run/cryptsetup/tokens — see
# cryptsetup.nix), but the systemd-tpm2 plugin ships in systemd's
# store path. Symlink systemd's plugin dir into that search path
# so systemd-cryptsetup can use the TPM2 token to unlock volumes.
mkdir -p /run/cryptsetup
ln -sfn @systemd@/lib/cryptsetup /run/cryptsetup/tokens

# Sealing binds PCR 7 (Secure Boot state) and PCR 12 (boot inputs)
# by value, so it must happen during a clean boot with SB
# *enforcing* — otherwise the seal captures an unusable state.
# Read SecureBoot from efivarfs (mount it if the initrd has not yet).
mount -t efivarfs none /sys/firmware/efi/efivars 2>/dev/null || true
sb=0
if [ -r "$sbvar" ]; then
  sb=$(od -An -tu1 -j4 -N1 "$sbvar" | tr -d ' ' || echo 0)
fi

# udev is slow to process a crypto_LUKS device on the unlock boot,
# and there is no ConditionPathExists guarding this unit, so poll
# (up to ~30s) before deciding a device is absent.
wait_for() {
  i=0
  while [ ! -e "$1" ] && [ "$i" -lt 60 ]; do i=$((i + 1)); sleep 0.5; done
  [ -e "$1" ]
}

# The inner filesystem of a sealed volume. Tool defaults are the
# intended defaults; both detect md stripe geometry on an array.
make_filesystem() {
  case "$1" in
    ext4) "$mkfs" -q -L "$2" "$3" ;;
    xfs) "$mkfs_xfs" -q -L "$2" "$3" ;;
    *) klog "unsupported filesystem $1 for $3"; return 1 ;;
  esac
}

# A signed (public-key) policy needs the PCR *signature* at unlock
# time; sd-stub materializes the UKI's .pcrsig at
# /run/systemd/tpm2-pcr-signature.json.
pcr_signature() {
  for p in /run/systemd/tpm2-pcr-signature.json \
           /.extra/tpm2-pcr-signature.json \
           /run/credentials/@system/tpm2-pcr-signature.json; do
    if [ -r "$p" ]; then echo "$p"; return 0; fi
  done
  return 0
}

# Already sealed: unlock via the signed TPM2 policy. If the unseal
# fails (SB-state or appended-input PCR mismatch, or an unsigned
# UKI), the volume stays locked and recovery is required — the
# intended security property. `headless` makes systemd-cryptsetup
# FAIL rather than fall back to an interactive passphrase prompt
# (which would wedge the boot); `timeout` bounds it either way.
unlock_volume() {
  name=$1
  dev=$2
  [ -e "/dev/mapper/$name" ] && return 0
  sig=$(pcr_signature)
  klog "unlocking $name from $dev via TPM2 (signature=${sig:-<none>})"
  opts="tpm2-device=auto,headless"
  [ -n "$sig" ] && opts="tpm2-device=auto,tpm2-signature=$sig,headless"
  rc=0
  timeout 60 "$csetup" attach "$name" "$dev" - "$opts" || rc=$?
  if [ "$rc" -ne 0 ]; then
    klog "TPM2 unlock of $name failed (rc=$rc) — it stays sealed, recovery key required"
  fi
  return 0
}

# First enforcing boot: format with a throwaway key, seal to the
# signed PCR policy (PCR 11) + pinned PCRs 7 and 12, add a recovery
# key, then drop the bootstrap keyslot so only the TPM/recovery paths
# remain. The LUKS2 label and subsystem identify the volume on a
# later boot that has no plan to consult.
seal_volume() {
  name=$1
  dev=$2
  label=$3
  filesystem=$4
  recovery_path=$5
  klog "sealing $name on $dev ($filesystem)"
  keyf=$(mktemp)
  dd if=/dev/urandom of="$keyf" bs=512 count=1 status=none
  "$cs" luksFormat --type luks2 --batch-mode \
    --label "$label" --subsystem aos-volume "$dev" "$keyf"
  "$cs" open "$dev" "$name" --key-file "$keyf"
  make_filesystem "$filesystem" "$label" "/dev/mapper/$name"
  "$enroll" --unlock-key-file="$keyf" \
    --tpm2-device=auto \
    --tpm2-public-key="$pub" \
    --tpm2-public-key-pcrs="$signed_pcrs" \
    --tpm2-pcrs="$pinned_pcrs" \
    "$dev"
  # Recovery key — MUST be escrowed off-machine (deployment
  # decision); written to the /run tmpfs, never to the volume. This
  # is NOT masked: if recovery enrollment fails we must abort BEFORE
  # wiping the bootstrap slot, otherwise a later TPM unseal failure
  # (legit firmware/SB or boot-input change → pinned PCR mismatch)
  # would brick the volume with no way in. `set -e` propagates a
  # failure here.
  # Command substitution removes systemd-cryptenroll's presentation
  # newline. cryptsetup treats every byte in a key file as key
  # material, so retaining that newline would make direct exact-slot
  # recovery verification disagree with systemd's password reader.
  recovery_key=$("$enroll" --unlock-key-file="$keyf" --recovery-key "$dev")
  mkdir -p "$(dirname "$recovery_path")"
  printf '%s' "$recovery_key" > "$recovery_path"
  unset recovery_key
  chmod 600 "$recovery_path"
  # Drop the throwaway bootstrap keyslot by TYPE (a plain
  # passphrase/keyfile slot), not by a guessed slot number — the
  # TPM2 and recovery slots carry their own systemd token types and
  # are left intact.
  "$enroll" --unlock-key-file="$keyf" --wipe-slot=password "$dev"
  shred -u "$keyf" 2>/dev/null || rm -f "$keyf"
}

# Bring one TPM-sealed volume to its state for this boot: unlock a
# sealed one, seal a raw one once Secure Boot is enforcing, and keep
# the system-state volume usable in plaintext before then.
handle_volume() {
  name=$1
  dev=$2
  label=$3
  filesystem=$4
  if ! wait_for "$dev"; then
    klog "$dev for $name absent after wait; skipping"
    return 0
  fi
  klog "$name device ready: $dev isLuks=$("$cs" isLuks "$dev" && echo Y || echo N)"
  if "$cs" isLuks "$dev"; then
    unlock_volume "$name" "$dev"
    return 0
  fi

  fs_type=$("$blkid" -p -s TYPE -o value "$dev" 2>/dev/null || true)
  if [ "$sb" != "1" ]; then
    if [ "$name" != var ]; then
      klog "SB not enforcing yet — $name stays raw until the first enforcing boot"
      return 0
    fi
    # Pre-enrollment boot (Setup Mode): SB not enforcing yet. Bring
    # up a temporary PLAIN ext4 /var so the system reaches
    # multi-user and an operator/test can enroll PK/KEK/db; the
    # first enforcing boot below replaces it with the sealed
    # volume. Format it once and preserve it across further Setup
    # Mode boots so key enrollment can complete without repeated
    # formatting.
    case "$fs_type" in
      "")
        klog "SB not enforcing yet — formatting plain ext4 /var (sealed once enforcing)"
        "$mkfs" -q -L "$label" "$dev"
        ;;
      ext4)
        klog "SB not enforcing yet — preserving existing plain ext4 /var"
        ;;
      *)
        klog "SB not enforcing yet — refusing unexpected /var filesystem type: $fs_type"
        exit 1
        ;;
    esac
    return 0
  fi

  # The system-state volume's plaintext Setup Mode filesystem is
  # disposable by contract; any other volume must still be blank,
  # since sealing over a foreign signature would destroy data the
  # plan never promised to own.
  if [ "$name" != var ] && [ -n "$fs_type" ]; then
    klog "refusing to seal $name: $dev already carries $fs_type"
    exit 1
  fi
  if [ "$name" = var ]; then
    seal_volume "$name" "$dev" "$label" "$filesystem" "$var_recovery_key"
  else
    seal_volume "$name" "$dev" "$label" "$filesystem" "$volume_recovery_dir/$name.key"
  fi
}

if [ -s "$volumes" ]; then
  # The validated plan names every sealed volume and the device
  # that carries it (a partition, or an array aos-storage-topology
  # has assembled).
  while IFS="$(printf '\t')" read -r name kind device label encryption filesystem; do
    [ "$encryption" = tpm2 ] || continue
    handle_volume "$name" "$device" "$label" "$filesystem"
  done < "$volumes"
else
  # No plan this boot (metadata unavailable after commit). The
  # system-state volume is found by its fixed identities; every
  # other sealed volume announces itself through the aos-volume
  # LUKS2 subsystem tag written when it was sealed. Nothing is
  # created on this path.
  var_dev=""
  for candidate in /dev/md/var /dev/disk/by-partlabel/var; do
    if [ -e "$candidate" ]; then var_dev="$candidate"; break; fi
  done
  if [ -n "$var_dev" ]; then
    handle_volume var "$var_dev" var ext4
  fi
  for dev in $("$blkid" -t TYPE=crypto_LUKS -o device 2>/dev/null || true); do
    subsystem=$("$blkid" -p -s SUBSYSTEM -o value "$dev" 2>/dev/null || true)
    label=$("$blkid" -p -s LABEL -o value "$dev" 2>/dev/null || true)
    [ "$subsystem" = aos-volume ] || continue
    [ -n "$label" ] || continue
    [ "$label" = var ] && continue
    # Discovery only unlocks; the filesystem already exists, so the
    # type passed here is never used to format.
    handle_volume "$label" "$dev" "$label" ext4
  done
fi
