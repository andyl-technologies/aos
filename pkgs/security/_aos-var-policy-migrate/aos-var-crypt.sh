#!@bash@/bin/bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: aos-var-crypt PCR_PUBLIC_KEY SIGNED_PCRS PINNED_PCRS RECOVERY_KEY_PATH" >&2
  exit 2
fi

dev=/dev/disk/by-partlabel/var
pub=$1
signed_pcrs=$2
pinned_pcrs=$3
recovery_key_path=$4
enroll=@systemd@/bin/systemd-cryptenroll
csetup=@systemd@/lib/systemd/systemd-cryptsetup
cs=@cryptsetup@/sbin/cryptsetup
mkfs=@e2fsprogs@/sbin/mkfs.ext4
sbvar=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c

export PATH=@coreutils@/bin:@util-linux@/bin:@util-linux@/sbin:@cryptsetup@/bin:@cryptsetup@/sbin

# The serial console may be owned by an initrd debug shell, so keep security
# diagnostics on the kernel log and fall back to standard error.
klog() {
  echo "aos-var-crypt: $*" > /dev/kmsg 2>/dev/null \
    || echo "aos-var-crypt: $*" >&2
}

# cryptsetup loads the systemd TPM2 token plugin from its configured runtime
# directory. Publish the package-owned plugin directory before any unlock.
mkdir -p /run/cryptsetup
ln -sfn @systemd@/lib/cryptsetup /run/cryptsetup/tokens

# A crypto_LUKS partition may acquire its stable partlabel link after the udev
# settlement service exits. Retain the bounded wait used by the original unit.
i=0
while [ ! -e "$dev" ] && [ "$i" -lt 60 ]; do
  i=$((i + 1))
  sleep 0.5
done
if [ ! -e "$dev" ]; then
  klog "$dev absent after wait; skipping"
  exit 0
fi
klog "device ready: isLuks=$("$cs" isLuks "$dev" && echo Y || echo N)"

if "$cs" isLuks "$dev"; then
  # A signed PCR policy needs the signature at unlock time. Prefer systemd's
  # canonical runtime path while preserving both initrd fallback locations.
  if [ ! -e /dev/mapper/var ]; then
    sig=""
    for candidate in \
      /run/systemd/tpm2-pcr-signature.json \
      /.extra/tpm2-pcr-signature.json \
      /run/credentials/@system/tpm2-pcr-signature.json; do
      if [ -r "$candidate" ]; then
        sig=$candidate
        break
      fi
    done

    klog "unlocking /var via TPM2 (signature=${sig:-<none>})"
    opts="tpm2-device=auto,headless"
    if [ -n "$sig" ]; then
      opts="tpm2-device=auto,tpm2-signature=$sig,headless"
    fi

    rc=0
    timeout 60 "$csetup" attach var "$dev" - "$opts" || rc=$?
    if [ "$rc" -ne 0 ]; then
      klog "TPM2 unlock failed (rc=$rc) — /var stays sealed, recovery key required"
    fi
  fi
  exit 0
fi

# Initial sealing is valid only once firmware enforces Secure Boot. Read the
# authenticated variable directly, mounting efivarfs if needed.
mount -t efivarfs none /sys/firmware/efi/efivars 2>/dev/null || true
sb=0
if [ -r "$sbvar" ]; then
  sb=$(od -An -tu1 -j4 -N1 "$sbvar" | tr -d ' ' || echo 0)
fi

if [ "$sb" != "1" ]; then
  # Setup Mode receives a disposable plain ext4 filesystem so enrollment can
  # finish. Preserve it across further Setup Mode boots.
  fs_type=$(@util-linux@/sbin/blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)
  case "$fs_type" in
    "")
      klog "SB not enforcing yet — formatting plain ext4 /var (sealed once enforcing)"
      "$mkfs" -q -L var "$dev"
      ;;
    ext4)
      klog "SB not enforcing yet — preserving existing plain ext4 /var"
      ;;
    *)
      klog "SB not enforcing yet — refusing unexpected /var filesystem type: $fs_type"
      exit 1
      ;;
  esac
  exit 0
fi

# The first enforcing boot creates LUKS2, enrolls the signed and pinned PCR
# policy, adds recovery, and only then removes the bootstrap keyslot.
keyf=$(mktemp)
dd if=/dev/urandom of="$keyf" bs=512 count=1 status=none
"$cs" luksFormat --type luks2 --batch-mode "$dev" "$keyf"
"$cs" open "$dev" var --key-file "$keyf"
"$mkfs" -q -L var /dev/mapper/var
"$enroll" --unlock-key-file="$keyf" \
  --tpm2-device=auto \
  --tpm2-public-key="$pub" \
  --tpm2-public-key-pcrs="$signed_pcrs" \
  --tpm2-pcrs="$pinned_pcrs" \
  "$dev"

# Recovery must succeed before the bootstrap slot is wiped. Command
# substitution removes the presentation newline so direct key-file recovery
# uses the same bytes as systemd's password reader.
recovery_key=$("$enroll" --unlock-key-file="$keyf" --recovery-key "$dev")
printf '%s' "$recovery_key" > "$recovery_key_path"
unset recovery_key
chmod 600 "$recovery_key_path"

"$enroll" --unlock-key-file="$keyf" --wipe-slot=password "$dev"
shred -u "$keyf" 2>/dev/null || rm -f "$keyf"
