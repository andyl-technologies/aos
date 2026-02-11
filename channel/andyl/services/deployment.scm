;;; ANDYL OS -- Deployment Orchestration Service Definitions
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the build-server-side tooling for the ANDYL OS
;;; deployment pipeline.  These scripts and services run on the build
;;; server (not on target machines) and handle:
;;;
;;;   1. Golden image building
;;;      Build a new system generation from the operating-system definition
;;;      using `guix system build`.  Compute the store closure and generate
;;;      the generation manifest.
;;;
;;;   2. NAR archive generation (delta bundles)
;;;      Compare the new generation's store closure against the previous
;;;      generation, export only the new store paths as NAR archives,
;;;      compress with zstd, and bundle into a tar archive.
;;;
;;;   3. Bundle signing
;;;      Sign the update bundle with minisign for integrity verification
;;;      on target machines.
;;;
;;;   4. Distribution
;;;      Upload signed bundles to the update server (static HTTPS file
;;;      server) for consumption by the andyl-os-agent on target machines.
;;;
;;;   5. Version management
;;;      Track generation history, retain N previous versions, and provide
;;;      garbage collection of old bundles on the distribution server.
;;;
;;; See:
;;;   Phase 5 sections 5.2, 5.11 (NAR Generation, Push-Based Updates)
;;;   RFC-0001 section 9 (Update Strategy)

(define-module (andyl services deployment)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl config)
  #:export (andyl-deployment-configuration
            andyl-deployment-configuration?
            andyl-deployment-configuration-update-server
            andyl-deployment-configuration-signing-key
            andyl-deployment-configuration-keep-generations
            andyl-deployment-configuration-channel
            andyl-deployment-configuration-bundle-dir
            andyl-deployment-configuration-ssh-user

            %andyl-default-deployment-config
            %andyl-build-bundle-script
            %andyl-sign-bundle-script
            %andyl-upload-bundle-script
            %andyl-deploy-script
            %andyl-fleet-update-script
            andyl-deployment-scripts))


;;;
;;; Deployment Configuration Record
;;;
;;; Defines the parameters for the deployment pipeline.  These are
;;; used by the build server scripts to generate, sign, and distribute
;;; update bundles.
;;;

(define-record-type* <andyl-deployment-configuration>
  andyl-deployment-configuration make-andyl-deployment-configuration
  andyl-deployment-configuration?
  ;; URL of the update distribution server.
  (update-server    andyl-deployment-configuration-update-server
                    (default (config-ref "deployment.update.server"
                                         "https://update.andyl-os.internal")))
  ;; Path to the minisign secret key for signing bundles.
  (signing-key      andyl-deployment-configuration-signing-key
                    (default (config-ref "deployment.signing.key-path"
                                         "/etc/andyl-os/deploy/signing-key.sec")))
  ;; Number of previous generations to retain on the distribution server.
  (keep-generations andyl-deployment-configuration-keep-generations
                    (default (config-ref "deployment.gc.keep-generations" 5)))
  ;; Default channel for releases.
  (channel          andyl-deployment-configuration-channel
                    (default (config-ref "deployment.update.channel" "stable")))
  ;; Local directory for staging bundles before upload.
  (bundle-dir       andyl-deployment-configuration-bundle-dir
                    (default (config-ref "deployment.bundle.dir"
                                         "/var/lib/andyl-os/bundles")))
  ;; SSH user for uploading to the distribution server.
  (ssh-user         andyl-deployment-configuration-ssh-user
                    (default (config-ref "deployment.bundle.ssh-user" "deploy"))))


(define %andyl-default-deployment-config
  (andyl-deployment-configuration))


;;;
;;; Build Bundle Script
;;;
;;; Builds a new generation bundle from the system definition.
;;; This script runs on the build server and produces:
;;;   - manifest.json: generation metadata and store path hashes
;;;   - bundle.tar: compressed NAR archives of new store paths
;;;
;;; The bundle contains only the delta between the new generation
;;; and the previous one, minimizing download size.
;;;
;;; Installed at /usr/bin/andyl-os-build-bundle on the build server.
;;;

(define %andyl-build-bundle-script
  "\
#!/bin/bash
# ANDYL OS Build Bundle
# Generates a delta update bundle from two generations.
# See: Phase 5 section 5.2
set -euo pipefail

readonly BUNDLE_DIR=${ANDYL_BUNDLE_DIR:-/var/lib/andyl-os/bundles}
readonly SYSTEM_CONFIG=${1:-channel/andyl/system/server.scm}
readonly PREV_GEN=${2:-}

usage() {
    echo \"Usage: andyl-os-build-bundle <system-config.scm> [previous-generation-number]\"
    echo \"\"
    echo \"Builds a new generation update bundle.\"
    echo \"\"
    echo \"Arguments:\"
    echo \"  system-config.scm    Path to the Guix system configuration\"
    echo \"  previous-gen         Previous generation number (for delta computation)\"
    echo \"\"
    echo \"Environment:\"
    echo \"  ANDYL_BUNDLE_DIR     Output directory (default: /var/lib/andyl-os/bundles)\"
    exit 1
}

[ \"$#\" -ge 1 ] || usage

echo \"=== ANDYL OS Bundle Builder ===\"
echo \"System config: $SYSTEM_CONFIG\"

# Step 1: Build the new system profile.
echo \"\"
echo \"[1/6] Building system profile...\"
NEW_PROFILE=$(guix system build \"$SYSTEM_CONFIG\" 2>&1 | tail -1)
echo \"  Profile: $NEW_PROFILE\"

# Step 2: Compute the store closure of the new profile.
echo \"\"
echo \"[2/6] Computing store closure...\"
NEW_CLOSURE=$(mktemp)
guix gc --references --recursive \"$NEW_PROFILE\" | sort > \"$NEW_CLOSURE\"
NEW_COUNT=$(wc -l < \"$NEW_CLOSURE\")
echo \"  New closure: $NEW_COUNT store paths\"

# Step 3: Compute the delta (new paths only).
echo \"\"
echo \"[3/6] Computing delta...\"
DELTA_PATHS=$(mktemp)

if [ -n \"$PREV_GEN\" ] && [ -f \"${BUNDLE_DIR}/gen-${PREV_GEN}/manifest.json\" ]; then
    # Extract previous generation's closure from its manifest.
    PREV_CLOSURE=$(mktemp)
    sed -n 's/.*\"path\":\\s*\"\\([^\"]*\\)\".*/\\1/p' \
        \"${BUNDLE_DIR}/gen-${PREV_GEN}/manifest.json\" | sort > \"$PREV_CLOSURE\"

    # Delta = new - previous.
    comm -23 \"$NEW_CLOSURE\" \"$PREV_CLOSURE\" > \"$DELTA_PATHS\"
    rm -f \"$PREV_CLOSURE\"
    echo \"  Previous generation: $PREV_GEN\"
else
    # No previous generation; bundle the full closure.
    cp \"$NEW_CLOSURE\" \"$DELTA_PATHS\"
    echo \"  No previous generation; full closure bundle.\"
fi

DELTA_COUNT=$(wc -l < \"$DELTA_PATHS\")
echo \"  Delta: $DELTA_COUNT new store paths\"

# Step 4: Determine the new generation number.
NEXT_GEN=1
if [ -n \"$PREV_GEN\" ]; then
    NEXT_GEN=$((PREV_GEN + 1))
else
    # Find the highest existing generation.
    for d in \"${BUNDLE_DIR}\"/gen-*; do
        [ -d \"$d\" ] || continue
        num=${d##*gen-}
        [ \"$num\" -ge \"$NEXT_GEN\" ] && NEXT_GEN=$((num + 1))
    done
fi

GEN_DIR=\"${BUNDLE_DIR}/gen-${NEXT_GEN}\"
mkdir -p \"$GEN_DIR\"
echo \"\"
echo \"[4/6] Exporting NAR archives (generation $NEXT_GEN)...\"

# Step 5: Export each new store path as a compressed NAR.
NAR_DIR=$(mktemp -d)
MANIFEST_ENTRIES=\"\"

while IFS= read -r store_path; do
    [ -n \"$store_path\" ] || continue
    basename=$(basename \"$store_path\")
    nar_file=\"${NAR_DIR}/${basename}.nar.zst\"

    echo \"  Exporting: $basename\"
    guix archive --export \"$store_path\" | zstd --ultra -19 -o \"$nar_file\"

    # Compute SHA-256 hash of the compressed NAR.
    hash=$(sha256sum \"$nar_file\" | cut -d' ' -f1)
    size=$(stat -c%s \"$nar_file\" 2>/dev/null || stat -f%z \"$nar_file\")

    MANIFEST_ENTRIES=\"${MANIFEST_ENTRIES}
    {\\\"path\\\": \\\"${store_path}\\\", \\\"hash\\\": \\\"${hash}\\\", \\\"size\\\": ${size}}\"
done < \"$DELTA_PATHS\"

# Include kernel and initrd if they exist in the profile.
KERNEL_HASH=\"\"
INITRD_HASH=\"\"
if [ -f \"${NEW_PROFILE}/bzImage\" ] || [ -f \"${NEW_PROFILE}/vmlinuz\" ]; then
    KERNEL_SRC=$(ls \"${NEW_PROFILE}/bzImage\" \"${NEW_PROFILE}/vmlinuz\" 2>/dev/null | head -1)
    cp \"$KERNEL_SRC\" \"${NAR_DIR}/vmlinuz\"
    KERNEL_HASH=$(sha256sum \"${NAR_DIR}/vmlinuz\" | cut -c1-12)
fi
if [ -f \"${NEW_PROFILE}/initrd\" ] || [ -f \"${NEW_PROFILE}/initrd.img\" ]; then
    INITRD_SRC=$(ls \"${NEW_PROFILE}/initrd\" \"${NEW_PROFILE}/initrd.img\" 2>/dev/null | head -1)
    cp \"$INITRD_SRC\" \"${NAR_DIR}/initrd.img\"
    INITRD_HASH=$(sha256sum \"${NAR_DIR}/initrd.img\" | cut -c1-12)
fi

# Step 6: Generate manifest and create the bundle tarball.
echo \"\"
echo \"[5/6] Generating manifest...\"

# Clean up manifest entries (remove leading newline, add commas).
MANIFEST_ENTRIES=$(echo \"$MANIFEST_ENTRIES\" | sed '/^$/d' | paste -sd',' -)

cat > \"${NAR_DIR}/manifest.json\" <<MANIFESTEOF
{
  \"generation\": ${NEXT_GEN},
  \"channel\": \"${ANDYL_CHANNEL:-stable}\",
  \"profile\": \"${NEW_PROFILE}\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"previous_generation\": ${PREV_GEN:-null},
  \"kernel_hash\": \"${KERNEL_HASH}\",
  \"initrd_hash\": \"${INITRD_HASH}\",
  \"store_paths\": [
    ${MANIFEST_ENTRIES}
  ]
}
MANIFESTEOF

echo \"\"
echo \"[6/6] Creating bundle tarball...\"
tar -cf \"${GEN_DIR}/bundle.tar\" -C \"$NAR_DIR\" .
cp \"${NAR_DIR}/manifest.json\" \"${GEN_DIR}/manifest.json\"

# Clean up.
rm -rf \"$NAR_DIR\" \"$NEW_CLOSURE\" \"$DELTA_PATHS\"

# Summary.
BUNDLE_SIZE=$(du -sh \"${GEN_DIR}/bundle.tar\" | cut -f1)
echo \"\"
echo \"=== Bundle Complete ===\"
echo \"  Generation:  $NEXT_GEN\"
echo \"  Bundle:      ${GEN_DIR}/bundle.tar ($BUNDLE_SIZE)\"
echo \"  Manifest:    ${GEN_DIR}/manifest.json\"
echo \"  Store paths: $DELTA_COUNT (delta)\"
echo \"\"
echo \"Next steps:\"
echo \"  1. Sign:   andyl-os-sign-bundle $NEXT_GEN\"
echo \"  2. Upload: andyl-os-upload-bundle $NEXT_GEN\"
")


;;;
;;; Sign Bundle Script
;;;
;;; Signs a generated bundle with minisign for integrity verification.
;;; Installed at /usr/bin/andyl-os-sign-bundle on the build server.
;;;

(define %andyl-sign-bundle-script
  "\
#!/bin/bash
# ANDYL OS Sign Bundle
# Signs an update bundle with minisign.
# See: Phase 5 section 5.2
set -euo pipefail

readonly BUNDLE_DIR=${ANDYL_BUNDLE_DIR:-/var/lib/andyl-os/bundles}
readonly SIGNING_KEY=${ANDYL_SIGNING_KEY:-/etc/andyl-os/deploy/signing-key.sec}

GEN=\"${1:-}\"

if [ -z \"$GEN\" ]; then
    echo \"Usage: andyl-os-sign-bundle <generation-number>\"
    echo \"\"
    echo \"Environment:\"
    echo \"  ANDYL_BUNDLE_DIR   Bundle directory (default: /var/lib/andyl-os/bundles)\"
    echo \"  ANDYL_SIGNING_KEY  Minisign secret key (default: /etc/andyl-os/deploy/signing-key.sec)\"
    exit 1
fi

GEN_DIR=\"${BUNDLE_DIR}/gen-${GEN}\"
BUNDLE=\"${GEN_DIR}/bundle.tar\"

if [ ! -f \"$BUNDLE\" ]; then
    echo \"ERROR: Bundle not found: $BUNDLE\" >&2
    exit 1
fi

if [ ! -f \"$SIGNING_KEY\" ]; then
    echo \"ERROR: Signing key not found: $SIGNING_KEY\" >&2
    echo \"\"
    echo \"Generate a key pair with:\"
    echo \"  minisign -G -p /etc/andyl-os/deploy/signing-key.pub \\\\\"
    echo \"           -s /etc/andyl-os/deploy/signing-key.sec\"
    exit 1
fi

echo \"Signing generation $GEN bundle...\"
echo \"  Bundle: $BUNDLE\"
echo \"  Key:    $SIGNING_KEY\"

minisign -Sm \"$BUNDLE\" -s \"$SIGNING_KEY\" \
    -t \"ANDYL OS generation ${GEN} $(date -u +%Y-%m-%dT%H:%M:%SZ)\"

echo \"\"
echo \"Signature created: ${BUNDLE}.sig\"
echo \"\"
echo \"Verify with:\"
echo \"  minisign -Vm ${BUNDLE} -p /etc/andyl-os/deploy/signing-key.pub\"
")


;;;
;;; Upload Bundle Script
;;;
;;; Uploads a signed bundle to the update distribution server.
;;; The distribution server is a static HTTPS file server (nginx)
;;; that serves bundles to target machines via the andyl-os-agent.
;;;
;;; Installed at /usr/bin/andyl-os-upload-bundle on the build server.
;;;

(define %andyl-upload-bundle-script
  "\
#!/bin/bash
# ANDYL OS Upload Bundle
# Uploads a signed update bundle to the distribution server.
# See: Phase 5 section 5.1
set -euo pipefail

readonly BUNDLE_DIR=${ANDYL_BUNDLE_DIR:-/var/lib/andyl-os/bundles}
readonly UPDATE_SERVER=${ANDYL_UPDATE_SERVER:-update.andyl-os.internal}
readonly SSH_USER=${ANDYL_SSH_USER:-deploy}
readonly REMOTE_DIR=${ANDYL_REMOTE_DIR:-/var/www/updates}
readonly KEEP_GENERATIONS=${ANDYL_KEEP_GENERATIONS:-5}

GEN=\"${1:-}\"

if [ -z \"$GEN\" ]; then
    echo \"Usage: andyl-os-upload-bundle <generation-number>\"
    echo \"\"
    echo \"Environment:\"
    echo \"  ANDYL_BUNDLE_DIR       Local bundle directory\"
    echo \"  ANDYL_UPDATE_SERVER    Distribution server hostname\"
    echo \"  ANDYL_SSH_USER         SSH user for upload\"
    echo \"  ANDYL_REMOTE_DIR       Remote directory for bundles\"
    echo \"  ANDYL_KEEP_GENERATIONS Generations to retain (default: 5)\"
    exit 1
fi

GEN_DIR=\"${BUNDLE_DIR}/gen-${GEN}\"

# Verify all required files exist.
for file in manifest.json bundle.tar bundle.tar.sig; do
    if [ ! -f \"${GEN_DIR}/${file}\" ]; then
        echo \"ERROR: Missing file: ${GEN_DIR}/${file}\" >&2
        echo \"Have you built and signed the bundle?\" >&2
        exit 1
    fi
done

echo \"=== Uploading Generation $GEN ===\"
echo \"  Server: ${SSH_USER}@${UPDATE_SERVER}\"
echo \"  Remote: ${REMOTE_DIR}/gen-${GEN}/\"

# Create remote directory.
ssh \"${SSH_USER}@${UPDATE_SERVER}\" \"mkdir -p ${REMOTE_DIR}/gen-${GEN}\"

# Upload bundle files.
echo \"\"
echo \"Uploading files...\"
scp -p \
    \"${GEN_DIR}/manifest.json\" \
    \"${GEN_DIR}/bundle.tar\" \
    \"${GEN_DIR}/bundle.tar.sig\" \
    \"${SSH_USER}@${UPDATE_SERVER}:${REMOTE_DIR}/gen-${GEN}/\"

# Update the 'latest' endpoint.
echo \"\"
echo \"Updating latest pointer...\"
ssh \"${SSH_USER}@${UPDATE_SERVER}\" \"cat > ${REMOTE_DIR}/latest.json\" <<LATESTEOF
{
  \"generation\": ${GEN},
  \"channel\": \"${ANDYL_CHANNEL:-stable}\",
  \"manifest_url\": \"/updates/gen-${GEN}/manifest.json\",
  \"bundle_url\": \"/updates/gen-${GEN}/bundle.tar\",
  \"signature_url\": \"/updates/gen-${GEN}/bundle.tar.sig\",
  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
}
LATESTEOF

# Garbage collect old generations on the server.
echo \"\"
echo \"Cleaning old generations (keeping ${KEEP_GENERATIONS})...\"
ssh \"${SSH_USER}@${UPDATE_SERVER}\" bash <<GCEOF
    cd \"${REMOTE_DIR}\"
    # List generation directories sorted by number, remove oldest beyond retention.
    ls -d gen-* 2>/dev/null | sort -t- -k2 -n | head -n -${KEEP_GENERATIONS} | while read old; do
        echo \"  Removing: \$old\"
        rm -rf \"\$old\"
    done
GCEOF

echo \"\"
echo \"=== Upload Complete ===\"
echo \"  URL: https://${UPDATE_SERVER}/updates/gen-${GEN}/\"
")


;;;
;;; Deploy Script
;;;
;;; Push-based deployment to a specific target machine.
;;; Triggers the update agent on the target via SSH.
;;;
;;; Installed at /usr/bin/andyl-os-deploy on the build server.
;;;

(define %andyl-deploy-script
  "\
#!/bin/bash
# ANDYL OS Deploy
# Pushes an update to a specific target machine via SSH.
# See: Phase 5 section 5.11
set -euo pipefail

TARGET=\"${1:-}\"
OPTS=\"${2:-}\"

if [ -z \"$TARGET\" ]; then
    echo \"Usage: andyl-os-deploy <target-host> [--no-reboot]\"
    echo \"\"
    echo \"Triggers the update agent on the target machine.\"
    echo \"The target must have the andyl-os-agent installed.\"
    exit 1
fi

echo \"=== Deploying to $TARGET ===\"

# Check connectivity.
if ! ssh -o ConnectTimeout=10 \"root@${TARGET}\" true 2>/dev/null; then
    echo \"ERROR: Cannot connect to $TARGET\" >&2
    exit 1
fi

# Check current generation on target.
echo \"\"
echo \"Checking current state...\"
CURRENT=$(ssh \"root@${TARGET}\" 'cat /var/lib/andyl-os/current-generation 2>/dev/null || echo unknown')
echo \"  Current generation: $CURRENT\"

# Trigger update.
echo \"\"
echo \"Triggering update...\"
if [ \"$OPTS\" = \"--no-reboot\" ]; then
    ssh \"root@${TARGET}\" '/usr/bin/andyl-os-agent check && /usr/bin/andyl-os-agent download && /usr/bin/andyl-os-agent verify && /usr/bin/andyl-os-agent apply'
    echo \"\"
    echo \"Update applied.  Reboot manually to activate.\"
else
    ssh \"root@${TARGET}\" '/usr/bin/andyl-os-agent now'
    echo \"\"
    echo \"Update triggered.  Target will reboot shortly.\"
fi

# Wait for the target to come back (if rebooting).
if [ \"$OPTS\" != \"--no-reboot\" ]; then
    echo \"\"
    echo \"Waiting for $TARGET to come back online...\"
    sleep 10
    for i in $(seq 1 30); do
        if ssh -o ConnectTimeout=5 \"root@${TARGET}\" true 2>/dev/null; then
            NEW_GEN=$(ssh \"root@${TARGET}\" 'cat /var/lib/andyl-os/current-generation 2>/dev/null || echo unknown')
            echo \"  $TARGET is back online (generation $NEW_GEN)\"

            # Check health.
            echo \"\"
            echo \"Verifying health...\"
            if ssh \"root@${TARGET}\" '/usr/bin/andyl-os-health-check'; then
                echo \"\"
                echo \"=== Deployment Successful ===\"
            else
                echo \"\"
                echo \"WARNING: Health check failed on $TARGET\"
                echo \"Boot counting will handle automatic rollback.\"
            fi
            exit 0
        fi
        sleep 10
    done

    echo \"WARNING: $TARGET did not come back within 5 minutes.\"
    echo \"Check the machine manually.\"
    exit 1
fi
")


;;;
;;; Fleet Update Script
;;;
;;; Rolling update across a fleet of machines.
;;; Updates machines in batches, waiting for health checks between batches.
;;;
;;; Installed at /usr/bin/andyl-os-fleet-update on the build server.
;;;

(define %andyl-fleet-update-script
  "\
#!/bin/bash
# ANDYL OS Fleet Update
# Rolling update across a fleet of target machines.
# See: Phase 5 section 5.11
set -euo pipefail

readonly INVENTORY=${1:-/etc/andyl-os/deploy/inventory}
readonly BATCH_SIZE=${ANDYL_BATCH_SIZE:-2}
readonly BATCH_DELAY=${ANDYL_BATCH_DELAY:-60}

if [ ! -f \"$INVENTORY\" ]; then
    echo \"Usage: andyl-os-fleet-update <inventory-file>\"
    echo \"\"
    echo \"Inventory file format (one host per line):\"
    echo \"  server-01.example.com\"
    echo \"  server-02.example.com\"
    echo \"\"
    echo \"Environment:\"
    echo \"  ANDYL_BATCH_SIZE   Machines per batch (default: 2)\"
    echo \"  ANDYL_BATCH_DELAY  Seconds between batches (default: 60)\"
    exit 1
fi

# Read inventory, skip comments and blank lines.
mapfile -t HOSTS < <(grep -v '^#' \"$INVENTORY\" | grep -v '^$')
TOTAL=${#HOSTS[@]}

echo \"=== ANDYL OS Fleet Update ===\"
echo \"  Hosts: $TOTAL\"
echo \"  Batch size: $BATCH_SIZE\"
echo \"  Batch delay: ${BATCH_DELAY}s\"
echo \"\"

BATCH=1
UPDATED=0
FAILED=0

for ((i=0; i<TOTAL; i+=BATCH_SIZE)); do
    BATCH_HOSTS=(\"${HOSTS[@]:$i:$BATCH_SIZE}\")
    BATCH_COUNT=${#BATCH_HOSTS[@]}

    echo \"--- Batch $BATCH ($BATCH_COUNT hosts) ---\"

    # Update each host in the batch (in parallel).
    PIDS=()
    for host in \"${BATCH_HOSTS[@]}\"; do
        echo \"  Starting: $host\"
        (
            if andyl-os-deploy \"$host\" 2>&1 | sed \"s/^/  [$host] /\"; then
                exit 0
            else
                exit 1
            fi
        ) &
        PIDS+=($!)
    done

    # Wait for all hosts in the batch.
    BATCH_FAILED=0
    for pid in \"${PIDS[@]}\"; do
        if ! wait \"$pid\"; then
            BATCH_FAILED=$((BATCH_FAILED + 1))
        fi
    done

    UPDATED=$((UPDATED + BATCH_COUNT - BATCH_FAILED))
    FAILED=$((FAILED + BATCH_FAILED))

    if [ \"$BATCH_FAILED\" -gt 0 ]; then
        echo \"\"
        echo \"WARNING: $BATCH_FAILED hosts failed in batch $BATCH.\"
        echo \"Continuing with next batch (failed hosts will roll back automatically).\"
    fi

    # Delay between batches (unless this is the last batch).
    if [ $((i + BATCH_SIZE)) -lt \"$TOTAL\" ]; then
        echo \"\"
        echo \"Waiting ${BATCH_DELAY}s before next batch...\"
        sleep \"$BATCH_DELAY\"
    fi

    BATCH=$((BATCH + 1))
done

echo \"\"
echo \"=== Fleet Update Complete ===\"
echo \"  Updated: $UPDATED / $TOTAL\"
echo \"  Failed:  $FAILED / $TOTAL\"
[ \"$FAILED\" -eq 0 ] || exit 1
")


;;;
;;; Collected Deployment Scripts
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; deployment scripts.  These are installed on the build server, not
;;; on target machines.
;;;

(define (andyl-deployment-scripts)
  "Return an alist of (filename . content) pairs for all deployment
scripts and configuration.  These are installed on the build server."
  (list
   ;; Build bundle script
   (cons "usr/bin/andyl-os-build-bundle"
         %andyl-build-bundle-script)

   ;; Sign bundle script
   (cons "usr/bin/andyl-os-sign-bundle"
         %andyl-sign-bundle-script)

   ;; Upload bundle script
   (cons "usr/bin/andyl-os-upload-bundle"
         %andyl-upload-bundle-script)

   ;; Deploy to single target
   (cons "usr/bin/andyl-os-deploy"
         %andyl-deploy-script)

   ;; Fleet rolling update
   (cons "usr/bin/andyl-os-fleet-update"
         %andyl-fleet-update-script)))
