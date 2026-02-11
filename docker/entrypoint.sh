#!/bin/bash
# docker/entrypoint.sh
#
# Start guix-daemon in the background, then exec the requested command.

set -euo pipefail

# --- OverlayFS setup for /gnu/store ---
# If GUIX_STORE_OVERLAY=1, mount an overlay on /gnu/store so that:
#   - The image's /gnu/store is the read-only lower layer
#   - A Docker volume provides the read-write upper layer
#   - New builds are written to the upper layer (persisted via volume)
#   - The merged view at /gnu/store shows both layers
if [ "${GUIX_STORE_OVERLAY:-0}" = "1" ]; then
    echo "Setting up OverlayFS overlay on /gnu/store..."

    OVERLAY_UPPER="/gnu/store-upper/upper"
    OVERLAY_WORK="/gnu/store-upper/work"

    # The upper and work directories live on the Docker volume
    # mounted at /gnu/store-upper
    mkdir -p "${OVERLAY_UPPER}" "${OVERLAY_WORK}"

    # Copy the original /gnu/store to a temporary lower dir
    # (overlay cannot use the same path as both lower and merged)
    cp -a /gnu/store /gnu/store-lower

    mount -t overlay overlay \
        -o "lowerdir=/gnu/store-lower,upperdir=${OVERLAY_UPPER},workdir=${OVERLAY_WORK}" \
        /gnu/store

    echo "OverlayFS mounted on /gnu/store (lower=image, upper=volume)"
fi

# --- Start guix-daemon ---
echo "Starting guix-daemon..."
# --no-substitutes: refuse all upstream binary caches
# --max-jobs: number of parallel build jobs
# --cores: cores per build (0 = use all available)
guix-daemon --build-users-group=guixbuild \
            --no-substitutes \
            --max-jobs="${GUIX_MAX_JOBS:-4}" \
            --cores="${GUIX_CORES:-0}" &

DAEMON_PID=$!

# Wait for daemon to become ready
for i in $(seq 1 30); do
    if guix describe >/dev/null 2>&1; then
        echo "guix-daemon is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: guix-daemon did not become ready within 30 seconds."
    fi
    sleep 1
done

# --- Channel configuration ---
# If the channel repo is mounted, add it
if [ -d /andyl-channel ]; then
    echo "Configuring ANDYL channel..."
    mkdir -p ~/.config/guix
    cat > ~/.config/guix/channels.scm << 'CHANNELS'
(list
  (channel
    (name 'andyl)
    (url "file:///andyl-channel")
    (branch "main")))
CHANNELS
    guix pull --channels=/root/.config/guix/channels.scm
fi

# Execute the provided command
exec "$@"
