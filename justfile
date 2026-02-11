# justfile
#
# ANDYL OS build orchestration
# All builds happen inside Docker containers.

# Default recipe: show help
default:
    @just --list

# ===========================================================================
# Docker Environment
# ===========================================================================

# Build the Guix build container image
docker-build:
    docker compose -f docker/docker-compose.yml build

# Interactive bash shell in the builder container
docker-shell:
    docker compose -f docker/docker-compose.yml run --rm guix-builder bash

# Interactive shell with overlay-backed /gnu/store
docker-shell-overlay:
    docker compose -f docker/docker-compose.overlay.yml run --rm guix-builder bash

# Start builder detached
docker-up:
    docker compose -f docker/docker-compose.yml up -d guix-builder

# Stop builder
docker-down:
    docker compose -f docker/docker-compose.yml down

# Show Docker volume sizes
docker-volumes:
    docker system df -v | grep -E 'gnu-store|guix-var|store-upper'

# ===========================================================================
# Store Overlay Management
# ===========================================================================

# Show newly built packages in overlay upper layer
store-overlay-diff:
    docker run --rm -v store-upper:/mnt busybox \
        sh -c 'echo "Upper layer contents:" && ls /mnt/upper/ 2>/dev/null | head -20'

# Discard all cached builds from overlay (reset upper layer)
store-overlay-reset:
    docker volume rm store-upper

# ===========================================================================
# Development
# ===========================================================================

# Open a Guix REPL for interactive development
repl:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix repl

# Update the channel (pull latest definitions)
channel-pull:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix pull --channels=/root/.config/guix/channels.scm

# Show store size
store-size:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        du -sh /gnu/store/

# ===========================================================================
# Bootstrap (Phase 2 targets)
# ===========================================================================

# Run the full bootstrap (Stage 0 through Stage 6)
# WARNING: This takes many hours on first run. Subsequent runs use the store.
bootstrap: docker-build
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes \
            andyl-bootstrap-seeds \
            andyl-mescc-tools \
            andyl-mes \
            andyl-tinycc-mescc \
            andyl-gcc-core-mesboot \
            andyl-gcc \
            andyl-glibc \
            andyl-binutils \
            andyl-make \
            andyl-coreutils

# Bootstrap just the toolchain (assumes seeds + mescc-tools are cached)
bootstrap-toolchain:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes andyl-gcc andyl-glibc andyl-binutils

# ===========================================================================
# Package Building
# ===========================================================================

# Build a specific package
build PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes "{{PACKAGE}}"

# Build all server packages
build-all:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix build --no-substitutes \
            andyl-linux \
            andyl-nginx \
            andyl-openssl \
            andyl-postgresql \
            andyl-python

# Show the dependency graph for a package
graph PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix graph "{{PACKAGE}}"

# Lint a package definition
lint PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix lint "{{PACKAGE}}"

# Show package details
show PACKAGE:
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix show "{{PACKAGE}}"

# ===========================================================================
# Image Building & Deployment (Phase 5 targets)
# ===========================================================================

# Build the ext4 golden image inside Docker
image-build SYSTEM_CONFIG="channel/andyl/system/server.scm":
    docker compose -f docker/docker-compose.yml run --rm guix-builder \
        guix system build "{{SYSTEM_CONFIG}}"
    @echo ""
    @echo "Image built successfully."
    @echo "To create an update bundle, run: just image-bundle"

# Build an image for a specific role
build-image image="base":
    ANDYL_IMAGE={{image}} guix system image --image-type=disk-image channel/andyl/images/base.scm

# Build a delta update bundle from the system definition
# Usage: just image-bundle [previous-generation]
image-bundle PREV_GEN="":
    docker compose -f docker/docker-compose.yml run --rm \
        -v andyl-bundles:/var/lib/andyl-os/bundles \
        guix-builder \
        /bin/bash -c '\
            export ANDYL_BUNDLE_DIR=/var/lib/andyl-os/bundles && \
            bash channel/andyl/services/deployment.scm-build-bundle \
                channel/andyl/system/server.scm {{PREV_GEN}} \
            || guix system build channel/andyl/system/server.scm'
    @echo ""
    @echo "Bundle staged in Docker volume: andyl-bundles"

# GPG-sign the golden image / update bundle
# Usage: just image-sign <generation-number>
image-sign GEN:
    @echo "=== Signing Generation {{GEN}} ==="
    @echo ""
    @echo "Signing with minisign..."
    docker compose -f docker/docker-compose.yml run --rm \
        -v andyl-bundles:/var/lib/andyl-os/bundles \
        -v andyl-signing-keys:/etc/andyl-os/deploy \
        guix-builder \
        minisign -Sm /var/lib/andyl-os/bundles/gen-{{GEN}}/bundle.tar \
            -s /etc/andyl-os/deploy/signing-key.sec \
            -t "ANDYL OS generation {{GEN}} $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    @echo ""
    @echo "Signature: /var/lib/andyl-os/bundles/gen-{{GEN}}/bundle.tar.sig"

# Upload signed bundle to the distribution server
# Usage: just image-upload <generation-number>
image-upload GEN:
    @echo "=== Uploading Generation {{GEN}} ==="
    docker compose -f docker/docker-compose.yml run --rm \
        -v andyl-bundles:/var/lib/andyl-os/bundles \
        -v ~/.ssh:/root/.ssh:ro \
        guix-builder \
        /bin/bash -c '\
            BUNDLE_DIR=/var/lib/andyl-os/bundles && \
            GEN_DIR=$BUNDLE_DIR/gen-{{GEN}} && \
            SERVER=${ANDYL_UPDATE_SERVER:-update.andyl-os.internal} && \
            USER=${ANDYL_SSH_USER:-deploy} && \
            REMOTE=/var/www/updates && \
            for f in manifest.json bundle.tar bundle.tar.sig; do \
                [ -f "$GEN_DIR/$f" ] || { echo "ERROR: Missing $f"; exit 1; }; \
            done && \
            ssh "$USER@$SERVER" "mkdir -p $REMOTE/gen-{{GEN}}" && \
            scp -p "$GEN_DIR/manifest.json" "$GEN_DIR/bundle.tar" \
                "$GEN_DIR/bundle.tar.sig" "$USER@$SERVER:$REMOTE/gen-{{GEN}}/" && \
            echo "{\"generation\": {{GEN}}, \"channel\": \"stable\"}" | \
                ssh "$USER@$SERVER" "cat > $REMOTE/latest.json" && \
            echo "Upload complete: https://$SERVER/updates/gen-{{GEN}}/"'

# Deploy an update to a target machine via SSH
# Usage: just deploy <target-hostname> [--no-reboot]
deploy TARGET *OPTS:
    @echo "=== Deploying to {{TARGET}} ==="
    ssh -o ConnectTimeout=10 root@{{TARGET}} true || \
        { echo "ERROR: Cannot connect to {{TARGET}}"; exit 1; }
    @echo "Current generation:"
    @ssh root@{{TARGET}} 'cat /var/lib/andyl-os/current-generation 2>/dev/null || echo "unknown"'
    @echo ""
    @echo "Triggering update..."
    ssh root@{{TARGET}} '/usr/bin/andyl-os-agent now'
    @echo ""
    @echo "Update triggered on {{TARGET}}."

# Generate a minisign key pair for bundle signing
image-keygen:
    @echo "=== Generating Signing Key Pair ==="
    docker compose -f docker/docker-compose.yml run --rm \
        -v andyl-signing-keys:/etc/andyl-os/deploy \
        guix-builder \
        minisign -G \
            -p /etc/andyl-os/deploy/signing-key.pub \
            -s /etc/andyl-os/deploy/signing-key.sec
    @echo ""
    @echo "Keys stored in Docker volume: andyl-signing-keys"
    @echo "Copy the public key to target machines:"
    @echo "  /etc/andyl-os/update-signing-key.pub"

# List generations on a target machine
generations TARGET:
    ssh root@{{TARGET}} '/usr/bin/andyl-os-agent generations'

# Trigger garbage collection on a target machine
gc TARGET:
    ssh root@{{TARGET}} '/usr/bin/andyl-os-gc'

# ===========================================================================
# Testing (Native Guile SRFI-64)
# ===========================================================================

# Run all native Guile tests
# Each test module runs under the image that provides its config imports.
test:
    @echo "=== Running ANDYL OS Native Tests ==="
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests config)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests packages)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    ANDYL_IMAGE=server guile -L channel/ -c '(use-modules (andyl tests system)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    ANDYL_IMAGE=server guile -L channel/ -c '(use-modules (andyl tests security)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests boot)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    ANDYL_IMAGE=k8s-worker guile -L channel/ -c '(use-modules (andyl tests kubernetes)) (exit (if (zero? (test-runner-fail-count (test-runner-current))) 0 1))'
    @echo "=== All Tests Passed ==="

# Individual test targets
test-config:
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests config))'

test-packages:
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests packages))'

test-system:
    ANDYL_IMAGE=server guile -L channel/ -c '(use-modules (andyl tests system))'

test-security:
    ANDYL_IMAGE=server guile -L channel/ -c '(use-modules (andyl tests security))'

test-boot:
    ANDYL_IMAGE=base guile -L channel/ -c '(use-modules (andyl tests boot))'

test-kubernetes:
    ANDYL_IMAGE=k8s-worker guile -L channel/ -c '(use-modules (andyl tests kubernetes))'

# ===========================================================================
# Local Update Server
# ===========================================================================

# Start a local update server for testing (serves bundles over HTTP)
update-serve PORT="8080":
    @echo "=== Starting Local Update Server ==="
    @echo "Serving bundles on http://localhost:{{PORT}}/updates/"
    docker compose -f docker/docker-compose.yml run --rm \
        -v andyl-bundles:/var/lib/andyl-os/bundles \
        -p {{PORT}}:{{PORT}} \
        guix-builder \
        python3 -m http.server {{PORT}} \
            --directory /var/lib/andyl-os/bundles
