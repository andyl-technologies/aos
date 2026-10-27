set -euo pipefail
unset LD_LIBRARY_PATH
umask 077

test "$(id -u)" = 0
mount -o remount,rw /
mkdir -p /dev/pts
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts
ln -sfn pts/ptmx /dev/ptmx
test -c /dev/pts/ptmx
mkdir -p /builder
mkfs.ext4 -F -q -m 0 -L native-builder /dev/vdc
mount -t ext4 /dev/vdc /builder

# Keep the daemon database, builds and temporary files on the private disk.
cp -a /nix /builder/nix
mkdir -p /build /builder/build /builder/tmp
chmod 1777 /builder/tmp
mount --bind /builder/nix /nix
mount --bind /builder/build /build
umount /tmp
mount --bind /builder/tmp /tmp
for path in /nix /build /tmp; do
  test "$(findmnt --noheadings --output FSTYPE --target "$path")" = ext4
done

mkdir -p /root /etc/nix /var/empty
chmod 0700 /root
export HOME=/root
printf 'root:x:0:0:root:/root:/bin/sh\n' > /etc/passwd
printf 'root:x:0:\nnixbld:x:30000:' > /etc/group
for number in $(seq 1 16); do
  printf 'nixbld%s:x:%s:30000:Nix build user:/var/empty:/bin/sh\n' \
    "$number" "$((30000 + number))" >> /etc/passwd
  if test "$number" -gt 1; then printf ',' >> /etc/group; fi
  printf 'nixbld%s' "$number" >> /etc/group
done
printf '\n' >> /etc/group
printf 'passwd: files\ngroup: files\nhosts: files\n' > /etc/nsswitch.conf
cat > /etc/nix/nix.conf <<'NIX_CONFIG'
experimental-features = nix-command flakes
build-users-group = nixbld
build-dir = /build
sandbox = true
sandbox-fallback = false
sandbox-paths =
extra-sandbox-paths =
builders =
substituters =
max-jobs = 1
cores = 8
system-features = terrane-native-builder
trusted-users = root
allowed-users = root
keep-failed = true
NIX_CONFIG

NIX_REMOTE=local nix-store --load-db < /run/aos-test-input/registration
NIX_REMOTE=local nix-daemon --daemon > /builder/daemon.log 2>&1 &
daemon_pid=$!
relay_pid=
cleanup() {
  if test -n "$relay_pid"; then kill "$relay_pid" 2>/dev/null || true; fi
  kill "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
  printf 'NATIVE_BUILDER_DAEMON_LOG\n'
  tail -100 /builder/daemon.log
  printf 'NATIVE_BUILDER_RELAY_LOG\n'
  tail -100 /builder/relay.log 2>/dev/null || true
  sync
}
trap cleanup EXIT

ready=0
for attempt in $(seq 1 100); do
  kill -0 "$daemon_pid"
  if test -S /nix/var/nix/daemon-socket/socket; then ready=1; break; fi
  sleep 0.1
done
test "$ready" = 1
socat VSOCK-LISTEN:64,reuseaddr,fork \
  UNIX-CONNECT:/nix/var/nix/daemon-socket/socket > /builder/relay.log 2>&1 &
relay_pid=$!
printf 'NATIVE_BUILDER_READY kernel=%s boot_id=%s nix=%s\n' \
  "$(uname -r)" "$(cat /proc/sys/kernel/random/boot_id)" "$(nix --version)"

# The host requests teardown after its remote build command settles.
control=$(socat -u VSOCK-LISTEN:65,reuseaddr STDOUT)
test "$control" = stop
kill -0 "$daemon_pid"
printf 'NATIVE_BUILDER_STOPPED\n'
