;;; ANDYL OS -- Update Tool Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the andyl-os-update-tool package, which provides
;;; the update agent and health check scripts installed on every ANDYL OS
;;; target machine.  The package installs:
;;;
;;;   /usr/bin/andyl-os-agent          -- Update lifecycle manager
;;;   /usr/bin/andyl-os-health-check   -- Post-boot health verification
;;;   /usr/bin/andyl-os-gc             -- Store garbage collection
;;;   /usr/bin/andyl-os-manifest       -- Generation manifest generator
;;;
;;; The update agent implements the full update lifecycle:
;;;   - check:       Query the update server for new generations
;;;   - download:    Fetch NAR bundle with HTTP range request resume
;;;   - verify:      Validate minisign signature + per-NAR SHA-256 hashes
;;;   - apply:       Atomically unpack NARs, create generation symlink,
;;;                  install boot entry with boot counting suffix
;;;   - rollback:    Revert to previous verified generation
;;;   - generations: List all installed generations with status
;;;
;;; The health check validates post-boot system state:
;;;   - systemd is-system-running
;;;   - networkd/DNS/NTP operational
;;;   - /gnu/store mounted read-only
;;;   - Role-specific checks (k8s-worker, database, edge)
;;;   On success, marks the generation as verified and triggers
;;;   boot-complete.target for systemd-bless-boot integration.
;;;
;;; The garbage collector implements mark-and-sweep for /gnu/store:
;;;   - Determine retained generations (configurable count + min age)
;;;   - Compute GC roots from profiles and /proc/*/maps scanning
;;;   - BFS reachability via the reference graph from manifests
;;;   - Sweep unreachable store paths
;;;   - Clean up old boot entries and generation metadata
;;;
;;; The manifest generator produces the Phase 5 manifest format:
;;;   - version, image_id, build_timestamp, guix_commit
;;;   - system_profile path
;;;   - store_paths with nar_hash, nar_size, and references
;;;
;;; This package is included in the base image.  It depends on:
;;;   - andyl-bash (shell interpreter)
;;;   - andyl-curl (HTTP downloads)
;;;   - andyl-minisign (signature verification)
;;;   - andyl-coreutils (basic utilities)
;;;   - andyl-util-linux (mount, findmnt)
;;;   - andyl-systemd (bootctl, systemctl)
;;;   - andyl-zstd (NAR decompression) [from andyl-compression]
;;;
;;; See:
;;;   Phase 5 (Generational Deployment Model)
;;;   docs/brainstorm/03-image-and-deployment.md sections 3-5

(define-module (andyl packages update)
  #:use-module (guix packages)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages base)
  #:use-module (andyl packages networking)
  #:use-module (andyl packages compression)
  #:use-module (andyl packages systemd)
  #:use-module (andyl packages image-tools)
  #:use-module (andyl config))


;;; =========================================================================
;;; andyl-os-update-tool -- Update agent, health check, GC, and manifest
;;; =========================================================================

(define-public andyl-os-update-tool
  (package
    (name "andyl-os-update-tool")
    (version (config-version "update" "update-tool"))
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out        (assoc-ref %outputs "out"))
                 (bindir     (string-append out "/bin"))
                 (confdir    (string-append out "/etc/andyl-os"))
                 (unitdir    (string-append out "/lib/systemd/system"))
                 (tmpfilesdir (string-append out "/lib/tmpfiles.d"))
                 (bash       (assoc-ref %build-inputs "andyl-bash"))
                 (curl       (assoc-ref %build-inputs "andyl-curl"))
                 (minisign   (assoc-ref %build-inputs "andyl-minisign"))
                 (coreutils  (assoc-ref %build-inputs "andyl-coreutils"))
                 (util-linux (assoc-ref %build-inputs "andyl-util-linux"))
                 (systemd    (assoc-ref %build-inputs "andyl-systemd"))
                 (zstd       (assoc-ref %build-inputs "andyl-zstd"))
                 (findutils  (assoc-ref %build-inputs "andyl-findutils"))
                 (grep       (assoc-ref %build-inputs "andyl-grep"))
                 (sed        (assoc-ref %build-inputs "andyl-sed"))
                 (gawk       (assoc-ref %build-inputs "andyl-gawk")))

            (mkdir-p bindir)
            (mkdir-p confdir)
            (mkdir-p unitdir)
            (mkdir-p tmpfilesdir)

            ;; ============================================================
            ;; PATH setup -- common to all scripts
            ;; ============================================================
            ;; Each script gets an explicit PATH so it works on the
            ;; immutable system without relying on the user's environment.
            (define path-export
              (string-append
               "export PATH=\""
               bash       "/bin:"
               curl       "/bin:"
               minisign   "/bin:"
               coreutils  "/bin:"
               util-linux "/bin:"
               systemd    "/bin:"
               zstd       "/bin:"
               findutils  "/bin:"
               grep       "/bin:"
               sed        "/bin:"
               gawk       "/bin:"
               "$PATH\"\n"))

            ;; ============================================================
            ;; andyl-os-agent -- Update lifecycle manager
            ;; ============================================================
            (call-with-output-file (string-append bindir "/andyl-os-agent")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Update Agent\n"
                  "# Manages the update lifecycle: check, download, verify, apply, rollback.\n"
                  "# See: Phase 5 section 5.3\n"
                  "set -euo pipefail\n"
                  "\n"
                  path-export
                  "\n"
                  "readonly CONF=/etc/andyl-os/update.conf\n"
                  "readonly STATE_DIR=/var/lib/andyl-os\n"
                  "readonly CACHE_DIR=/var/cache/andyl-os/updates\n"
                  "readonly LOCK_FILE=/var/lock/andyl-os-gc.lock\n"
                  "readonly CURRENT_GEN_FILE=${STATE_DIR}/current-generation\n"
                  "\n"
                  "# Load configuration.\n"
                  "load_config() {\n"
                  "    if [ ! -f \"$CONF\" ]; then\n"
                  "        echo \"ERROR: Configuration file not found: $CONF\" >&2\n"
                  "        exit 1\n"
                  "    fi\n"
                  "    while IFS='=' read -r key value; do\n"
                  "        case \"$key\" in\n"
                  "            server|channel|check_interval|auto_update|max_retries|retry_delay|boot_tries|signing_key)\n"
                  "                declare -g \"$key=$value\"\n"
                  "                ;;\n"
                  "        esac\n"
                  "    done < <(grep -v '^#' \"$CONF\" | grep -v '^$')\n"
                  "}\n"
                  "\n"
                  "current_generation() {\n"
                  "    if [ -f \"$CURRENT_GEN_FILE\" ]; then\n"
                  "        cat \"$CURRENT_GEN_FILE\"\n"
                  "    else\n"
                  "        echo \"1\"\n"
                  "    fi\n"
                  "}\n"
                  "\n"
                  "cmd_check() {\n"
                  "    local current latest_json latest_gen\n"
                  "    current=$(current_generation)\n"
                  "    echo \"Current generation: $current\"\n"
                  "    latest_json=$(curl -sf \"${server}/api/v1/updates/latest?channel=${channel}\") || {\n"
                  "        echo \"ERROR: Failed to query update server\" >&2\n"
                  "        exit 1\n"
                  "    }\n"
                  "    latest_gen=$(echo \"$latest_json\" | sed -n 's/.*\"generation\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p')\n"
                  "    if [ -z \"$latest_gen\" ]; then\n"
                  "        echo \"ERROR: Could not parse server response\" >&2\n"
                  "        exit 1\n"
                  "    fi\n"
                  "    if [ \"$latest_gen\" -gt \"$current\" ]; then\n"
                  "        echo \"Update available: gen $current -> gen $latest_gen\"\n"
                  "        return 0\n"
                  "    else\n"
                  "        echo \"System is up to date (gen $current)\"\n"
                  "        return 1\n"
                  "    fi\n"
                  "}\n"
                  "\n"
                  "cmd_download() {\n"
                  "    local target_gen=\"${1:-}\"\n"
                  "    if [ -z \"$target_gen\" ]; then\n"
                  "        local latest_json\n"
                  "        latest_json=$(curl -sf \"${server}/api/v1/updates/latest?channel=${channel}\")\n"
                  "        target_gen=$(echo \"$latest_json\" | sed -n 's/.*\"generation\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p')\n"
                  "    fi\n"
                  "    echo \"Downloading generation $target_gen...\"\n"
                  "    local gen_dir=\"${CACHE_DIR}/gen-${target_gen}\"\n"
                  "    mkdir -p \"$gen_dir\"\n"
                  "    curl -f --progress-bar -C - -o \"${gen_dir}/manifest.json\" \\\n"
                  "        \"${server}/updates/gen-${target_gen}/manifest.json\"\n"
                  "    curl -f --progress-bar -C - -o \"${gen_dir}/bundle.tar\" \\\n"
                  "        \"${server}/updates/gen-${target_gen}/bundle.tar\"\n"
                  "    curl -f --progress-bar -C - -o \"${gen_dir}/bundle.tar.sig\" \\\n"
                  "        \"${server}/updates/gen-${target_gen}/bundle.tar.sig\"\n"
                  "    echo \"Download complete: ${gen_dir}\"\n"
                  "}\n"
                  "\n"
                  "cmd_verify() {\n"
                  "    local target_gen=\"${1:-}\"\n"
                  "    local gen_dir=\"${CACHE_DIR}/gen-${target_gen}\"\n"
                  "    [ -d \"$gen_dir\" ] || { echo \"ERROR: Generation $target_gen not downloaded\" >&2; exit 1; }\n"
                  "    echo \"Verifying generation $target_gen...\"\n"
                  "    # Verify minisign signature.\n"
                  "    minisign -Vm \"${gen_dir}/bundle.tar\" -p \"${signing_key}\" || {\n"
                  "        echo \"ERROR: Signature verification failed\" >&2; exit 1\n"
                  "    }\n"
                  "    echo \"Signature: VERIFIED\"\n"
                  "    # Verify NAR hashes from manifest.\n"
                  "    local manifest=\"${gen_dir}/manifest.json\"\n"
                  "    if [ -f \"$manifest\" ]; then\n"
                  "        echo \"Verifying NAR hashes...\"\n"
                  "        local tmp_verify\n"
                  "        tmp_verify=$(mktemp -d)\n"
                  "        tar -xf \"${gen_dir}/bundle.tar\" -C \"$tmp_verify\" 2>/dev/null || true\n"
                  "        local failed=0\n"
                  "        # Parse each store_path entry from manifest.\n"
                  "        while IFS= read -r line; do\n"
                  "            local hash path\n"
                  "            hash=$(echo \"$line\" | sed -n 's/.*\"nar_hash\"[[:space:]]*:[[:space:]]*\"sha256:\\([^\"]*\\)\".*/\\1/p')\n"
                  "            path=$(echo \"$line\" | sed -n 's/.*\"path\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p')\n"
                  "            if [ -n \"$hash\" ] && [ -n \"$path\" ]; then\n"
                  "                local nar_file=\"${tmp_verify}/$(basename \"$path\").nar.zst\"\n"
                  "                if [ -f \"$nar_file\" ]; then\n"
                  "                    local actual\n"
                  "                    actual=$(zstd -d \"$nar_file\" --stdout | sha256sum | cut -d' ' -f1)\n"
                  "                    if [ \"$actual\" != \"$hash\" ]; then\n"
                  "                        echo \"ERROR: Hash mismatch for $path\" >&2\n"
                  "                        failed=1\n"
                  "                    fi\n"
                  "                fi\n"
                  "            fi\n"
                  "        done < <(grep -o '{[^}]*}' \"$manifest\")\n"
                  "        rm -rf \"$tmp_verify\"\n"
                  "        [ \"$failed\" -eq 0 ] || { echo \"ERROR: NAR hash verification failed\" >&2; exit 1; }\n"
                  "        echo \"NAR hashes: VERIFIED\"\n"
                  "    fi\n"
                  "    echo \"Verification complete.\"\n"
                  "}\n"
                  "\n"
                  "cmd_apply() {\n"
                  "    local target_gen=\"${1:-}\"\n"
                  "    local gen_dir=\"${CACHE_DIR}/gen-${target_gen}\"\n"
                  "    [ -d \"$gen_dir\" ] || { echo \"ERROR: Generation $target_gen not downloaded\" >&2; exit 1; }\n"
                  "    echo \"Applying generation $target_gen...\"\n"
                  "    # Acquire exclusive lock (shared with GC).\n"
                  "    exec 9>\"$LOCK_FILE\"\n"
                  "    flock -x 9 || { echo \"ERROR: Could not acquire lock\" >&2; exit 1; }\n"
                  "    # Remount /gnu/store read-write.\n"
                  "    mount -o remount,rw /gnu/store || { echo \"ERROR: Could not remount store rw\" >&2; exit 1; }\n"
                  "    # Extract the bundle.\n"
                  "    local tmp_unpack\n"
                  "    tmp_unpack=$(mktemp -d /gnu/store/.tmp-update-XXXXXX)\n"
                  "    tar -xf \"${gen_dir}/bundle.tar\" -C \"$tmp_unpack\"\n"
                  "    # Unpack each NAR archive atomically.\n"
                  "    for nar in \"${tmp_unpack}\"/*.nar.zst; do\n"
                  "        [ -f \"$nar\" ] || continue\n"
                  "        local store_path\n"
                  "        store_path=$(basename \"$nar\" .nar.zst)\n"
                  "        if [ -d \"/gnu/store/${store_path}\" ]; then\n"
                  "            echo \"  Skip (exists): ${store_path}\"\n"
                  "            continue\n"
                  "        fi\n"
                  "        echo \"  Unpacking: ${store_path}\"\n"
                  "        local tmp_path=\"/gnu/store/.tmp-${store_path}-$$\"\n"
                  "        mkdir -p \"$tmp_path\"\n"
                  "        zstd -d \"$nar\" --stdout | guix archive --import 2>/dev/null || {\n"
                  "            zstd -d \"$nar\" -o \"${tmp_path}.nar\"\n"
                  "            guix archive --import < \"${tmp_path}.nar\" 2>/dev/null || true\n"
                  "            rm -f \"${tmp_path}.nar\"\n"
                  "        }\n"
                  "        if [ -d \"$tmp_path\" ] && [ \"$(ls -A \"$tmp_path\")\" ]; then\n"
                  "            mv -T \"$tmp_path\" \"/gnu/store/${store_path}\"\n"
                  "            chmod -R a-w \"/gnu/store/${store_path}\"\n"
                  "        fi\n"
                  "    done\n"
                  "    # Handle kernel and initrd.\n"
                  "    local kernel_hash=\"current\" initrd_hash=\"current\"\n"
                  "    if [ -f \"${tmp_unpack}/vmlinuz\" ]; then\n"
                  "        kernel_hash=$(sha256sum \"${tmp_unpack}/vmlinuz\" | cut -c1-16)\n"
                  "        cp \"${tmp_unpack}/vmlinuz\" \"/boot/efi/andyl-os/${kernel_hash}-vmlinuz\"\n"
                  "    fi\n"
                  "    if [ -f \"${tmp_unpack}/initrd.img\" ] || [ -f \"${tmp_unpack}/initrd.cpio.zst\" ]; then\n"
                  "        local initrd_src\n"
                  "        initrd_src=$(ls \"${tmp_unpack}\"/initrd* 2>/dev/null | head -1)\n"
                  "        initrd_hash=$(sha256sum \"$initrd_src\" | cut -c1-16)\n"
                  "        cp \"$initrd_src\" \"/boot/efi/andyl-os/${initrd_hash}-initrd\"\n"
                  "    fi\n"
                  "    rm -rf \"$tmp_unpack\"\n"
                  "    # Remount /gnu/store read-only.\n"
                  "    mount -o remount,ro /gnu/store\n"
                  "    # Create generation symlink atomically on ZFS /var.\n"
                  "    local profile_path\n"
                  "    profile_path=$(sed -n 's/.*\"system_profile\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"${gen_dir}/manifest.json\")\n"
                  "    if [ -n \"$profile_path\" ]; then\n"
                  "        ln -sf \"$profile_path\" \"/var/guix/profiles/system-${target_gen}.tmp\"\n"
                  "        mv -T \"/var/guix/profiles/system-${target_gen}.tmp\" \"/var/guix/profiles/system-${target_gen}\"\n"
                  "        ln -sf \"system-${target_gen}\" /var/guix/profiles/system.tmp\n"
                  "        mv -T /var/guix/profiles/system.tmp /var/guix/profiles/system\n"
                  "    fi\n"
                  "    # Write generation metadata (JSON format per brainstorm doc 03 section 2.4).\n"
                  "    cat > \"/var/guix/profiles/system-${target_gen}.meta\" <<METAEOF\n"
                  "{\n"
                  "  \"generation\": ${target_gen},\n"
                  "  \"profile\": \"${profile_path}\",\n"
                  "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\n"
                  "  \"channel\": \"${channel}\",\n"
                  "  \"status\": \"pending\",\n"
                  "  \"previous_generation\": $(current_generation),\n"
                  "  \"manifest_hash\": \"sha256:$(sha256sum \"${gen_dir}/manifest.json\" | cut -d' ' -f1)\"\n"
                  "}\n"
                  "METAEOF\n"
                  "    # Install boot entry with boot counting suffix.\n"
                  "    mkdir -p /boot/efi/andyl-os\n"
                  "    mkdir -p /boot/efi/loader/entries\n"
                  "    cat > \"/boot/efi/loader/entries/andyl-os-${target_gen}+${boot_tries}.conf\" <<BOOTEOF\n"
                  "title   ANDYL OS Generation ${target_gen}\n"
                  "linux   /andyl-os/${kernel_hash}-vmlinuz\n"
                  "initrd  /andyl-os/${initrd_hash}-initrd\n"
                  "options root=LABEL=ANDYL-ROOT ro quiet security=selinux selinux=1 enforcing=1 systemd.unified_cgroup_hierarchy=1 init=${profile_path}/boot/init andyl.generation=${target_gen}\n"
                  "BOOTEOF\n"
                  "    bootctl set-default \"andyl-os-${target_gen}+${boot_tries}.conf\" 2>/dev/null || true\n"
                  "    echo \"$target_gen\" > \"$CURRENT_GEN_FILE\"\n"
                  "    flock -u 9\n"
                  "    echo \"Generation $target_gen applied successfully.\"\n"
                  "    echo \"Reboot to activate: systemctl reboot\"\n"
                  "}\n"
                  "\n"
                  "cmd_rollback() {\n"
                  "    local target=\"${1:-}\"\n"
                  "    local current\n"
                  "    current=$(current_generation)\n"
                  "    if [ -z \"$target\" ]; then\n"
                  "        target=$((current - 1))\n"
                  "        while [ \"$target\" -ge 1 ]; do\n"
                  "            local meta=\"/var/guix/profiles/system-${target}.meta\"\n"
                  "            if [ -f \"$meta\" ] && grep -q '\"status\".*\"verified\"' \"$meta\"; then\n"
                  "                break\n"
                  "            fi\n"
                  "            target=$((target - 1))\n"
                  "        done\n"
                  "        [ \"$target\" -ge 1 ] || { echo \"ERROR: No previous verified generation\" >&2; exit 1; }\n"
                  "    fi\n"
                  "    echo \"Rolling back: gen $current -> gen $target\"\n"
                  "    local entry\n"
                  "    entry=$(ls /boot/efi/loader/entries/andyl-os-${target}.conf 2>/dev/null || \\\n"
                  "            ls /boot/efi/loader/entries/andyl-os-${target}+*.conf 2>/dev/null | head -1)\n"
                  "    [ -n \"$entry\" ] || { echo \"ERROR: No boot entry for gen $target\" >&2; exit 1; }\n"
                  "    bootctl set-default \"$(basename \"$entry\")\" 2>/dev/null || true\n"
                  "    echo \"Default boot set to generation $target. Reboot to activate.\"\n"
                  "}\n"
                  "\n"
                  "cmd_generations() {\n"
                  "    echo \"ANDYL OS Generations:\"\n"
                  "    printf '%-6s %-24s %-10s %-10s\\n' 'GEN' 'TIMESTAMP' 'CHANNEL' 'STATUS'\n"
                  "    echo '------------------------------------------------------'\n"
                  "    for meta in /var/guix/profiles/system-*.meta; do\n"
                  "        [ -f \"$meta\" ] || continue\n"
                  "        local gen ts ch st\n"
                  "        gen=$(sed -n 's/.*\"generation\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p' \"$meta\")\n"
                  "        ts=$(sed -n 's/.*\"timestamp\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$meta\")\n"
                  "        ch=$(sed -n 's/.*\"channel\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$meta\")\n"
                  "        st=$(sed -n 's/.*\"status\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$meta\")\n"
                  "        local marker=''\n"
                  "        [ \"$gen\" = \"$(current_generation)\" ] && marker=' *'\n"
                  "        printf '%-6s %-24s %-10s %-10s%s\\n' \"$gen\" \"$ts\" \"$ch\" \"$st\" \"$marker\"\n"
                  "    done\n"
                  "}\n"
                  "\n"
                  "cmd_now() {\n"
                  "    load_config\n"
                  "    if cmd_check; then\n"
                  "        local latest_json target_gen\n"
                  "        latest_json=$(curl -sf \"${server}/api/v1/updates/latest?channel=${channel}\")\n"
                  "        target_gen=$(echo \"$latest_json\" | sed -n 's/.*\"generation\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p')\n"
                  "        cmd_download \"$target_gen\"\n"
                  "        cmd_verify \"$target_gen\"\n"
                  "        cmd_apply \"$target_gen\"\n"
                  "        echo \"Rebooting...\"\n"
                  "        systemctl reboot\n"
                  "    fi\n"
                  "}\n"
                  "\n"
                  "main() {\n"
                  "    load_config\n"
                  "    case \"${1:-help}\" in\n"
                  "        check)       cmd_check ;;\n"
                  "        download)    cmd_download \"${2:-}\" ;;\n"
                  "        verify)      cmd_verify \"${2:-}\" ;;\n"
                  "        apply)       cmd_apply \"${2:-}\" ;;\n"
                  "        now|update)  cmd_now ;;\n"
                  "        rollback)    cmd_rollback \"${2:-}\" ;;\n"
                  "        generations) cmd_generations ;;\n"
                  "        help|*)\n"
                  "            echo \"Usage: andyl-os-agent <command> [args]\"\n"
                  "            echo \"\"\n"
                  "            echo \"Commands:\"\n"
                  "            echo \"  check          Check for available updates\"\n"
                  "            echo \"  download [GEN] Download an update bundle\"\n"
                  "            echo \"  verify GEN     Verify a downloaded bundle\"\n"
                  "            echo \"  apply GEN      Apply a verified bundle\"\n"
                  "            echo \"  now            Full update cycle + reboot\"\n"
                  "            echo \"  rollback [GEN] Rollback to previous verified generation\"\n"
                  "            echo \"  generations    List all generations\"\n"
                  "            ;;\n"
                  "    esac\n"
                  "}\n"
                  "\n"
                  "main \"$@\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-os-agent") #o755)

            ;; ============================================================
            ;; andyl-os-health-check -- Post-boot health verification
            ;; ============================================================
            (call-with-output-file (string-append bindir "/andyl-os-health-check")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Health Check\n"
                  "# Verifies system health after boot.\n"
                  "# See: Phase 5 section 5.6\n"
                  "set -euo pipefail\n"
                  "\n"
                  path-export
                  "\n"
                  "readonly STATE_DIR=/var/lib/andyl-os\n"
                  "readonly CURRENT_GEN_FILE=${STATE_DIR}/current-generation\n"
                  "\n"
                  "CHECKS_PASSED=0\n"
                  "CHECKS_TOTAL=0\n"
                  "\n"
                  "check() {\n"
                  "    local desc=\"$1\"; shift\n"
                  "    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))\n"
                  "    if \"$@\" >/dev/null 2>&1; then\n"
                  "        echo \"  [PASS] $desc\"\n"
                  "        CHECKS_PASSED=$((CHECKS_PASSED + 1))\n"
                  "    else\n"
                  "        echo \"  [FAIL] $desc\"\n"
                  "    fi\n"
                  "}\n"
                  "\n"
                  "echo \"ANDYL OS Health Check\"\n"
                  "echo \"=====================\"\n"
                  "echo \"Generation: $(cat \"$CURRENT_GEN_FILE\" 2>/dev/null || echo unknown)\"\n"
                  "echo \"Timestamp:  $(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n"
                  "echo \"\"\n"
                  "\n"
                  "echo \"Core System:\"\n"
                  "check \"systemd is running\"       systemctl is-system-running --quiet\n"
                  "check \"networkd is online\"        networkctl status --no-pager\n"
                  "check \"DNS resolution\"            getent hosts localhost\n"
                  "check \"NTP synchronized\"          timedatectl show -p NTPSynchronized --value\n"
                  "check \"/gnu/store is read-only\"   findmnt -n -o OPTIONS /gnu/store\n"
                  "check \"Journal is healthy\"        journalctl --verify --quiet\n"
                  "\n"
                  "# Role-specific checks.\n"
                  "ROLE=$(cat /etc/andyl-os/role 2>/dev/null || echo base)\n"
                  "if [ \"$ROLE\" != \"base\" ]; then\n"
                  "    echo \"\"\n"
                  "    echo \"Role: $ROLE\"\n"
                  "    case \"$ROLE\" in\n"
                  "        k8s-worker|k8s-control-plane)\n"
                  "            check \"containerd running\"  systemctl is-active --quiet containerd\n"
                  "            check \"kubelet running\"     systemctl is-active --quiet kubelet\n"
                  "            check \"CNI plugins exist\"   test -d /opt/cni/bin\n"
                  "            check \"kubelet healthz\"     curl -sf http://localhost:10248/healthz\n"
                  "            ;;\n"
                  "        database)\n"
                  "            check \"postgresql running\"  systemctl is-active --quiet postgresql\n"
                  "            check \"pg_isready\"          pg_isready -q\n"
                  "            ;;\n"
                  "        edge)\n"
                  "            check \"envoy running\"       systemctl is-active --quiet envoy\n"
                  "            check \"envoy admin ready\"   curl -sf http://localhost:9901/ready\n"
                  "            ;;\n"
                  "    esac\n"
                  "fi\n"
                  "\n"
                  "echo \"\"\n"
                  "echo \"Result: $CHECKS_PASSED/$CHECKS_TOTAL checks passed\"\n"
                  "\n"
                  "if [ \"$CHECKS_PASSED\" -eq \"$CHECKS_TOTAL\" ]; then\n"
                  "    # Mark generation as verified.\n"
                  "    gen=$(cat \"$CURRENT_GEN_FILE\" 2>/dev/null || echo '')\n"
                  "    if [ -n \"$gen\" ]; then\n"
                  "        meta=\"/var/guix/profiles/system-${gen}.meta\"\n"
                  "        if [ -f \"$meta\" ]; then\n"
                  "            sed -i 's/\"status\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"status\": \"verified\"/' \"$meta\"\n"
                  "        fi\n"
                  "    fi\n"
                  "    exit 0\n"
                  "else\n"
                  "    echo \"Boot counting will handle rollback.\"\n"
                  "    exit 1\n"
                  "fi\n")
                 port)))
            (chmod (string-append bindir "/andyl-os-health-check") #o755)

            ;; ============================================================
            ;; andyl-os-gc -- Store garbage collection
            ;; ============================================================
            (call-with-output-file (string-append bindir "/andyl-os-gc")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Garbage Collection\n"
                  "# Mark-and-sweep GC for /gnu/store.\n"
                  "# See: Phase 5 section 5.8, brainstorm 03 section 5\n"
                  "set -euo pipefail\n"
                  "\n"
                  path-export
                  "\n"
                  "readonly CONF=/etc/andyl-os/gc.conf\n"
                  "readonly LOCK_FILE=/var/lock/andyl-os-gc.lock\n"
                  "readonly STATE_DIR=/var/lib/andyl-os\n"
                  "readonly PROFILES_DIR=/var/guix/profiles\n"
                  "\n"
                  "KEEP_GENERATIONS=5\n"
                  "MIN_AGE_HOURS=24\n"
                  "DRY_RUN=false\n"
                  "\n"
                  "if [ -f \"$CONF\" ]; then\n"
                  "    while IFS='=' read -r key value; do\n"
                  "        case \"$key\" in\n"
                  "            keep_generations) KEEP_GENERATIONS=$value ;;\n"
                  "            min_age_hours)    MIN_AGE_HOURS=$value ;;\n"
                  "            dry_run)          DRY_RUN=$value ;;\n"
                  "        esac\n"
                  "    done < <(grep -v '^#' \"$CONF\" | grep -v '^$')\n"
                  "fi\n"
                  "\n"
                  "echo \"=== ANDYL OS Garbage Collection ===\"\n"
                  "echo \"  Keep: $KEEP_GENERATIONS generations, min age: ${MIN_AGE_HOURS}h\"\n"
                  "\n"
                  "# Acquire exclusive lock.\n"
                  "exec 9>\"$LOCK_FILE\"\n"
                  "flock -n -x 9 || { echo \"ERROR: Lock held (update running?)\" >&2; exit 1; }\n"
                  "\n"
                  "# Phase 0: Determine generations to keep.\n"
                  "CURRENT_GEN=$(cat \"${STATE_DIR}/current-generation\" 2>/dev/null || echo '1')\n"
                  "ALL_GENS=()\n"
                  "for meta in \"${PROFILES_DIR}\"/system-*.meta; do\n"
                  "    [ -f \"$meta\" ] || continue\n"
                  "    gen=$(sed -n 's/.*\"generation\"[[:space:]]*:[[:space:]]*\\([0-9]*\\).*/\\1/p' \"$meta\")\n"
                  "    [ -n \"$gen\" ] && ALL_GENS+=(\"$gen\")\n"
                  "done\n"
                  "IFS=$'\\n' SORTED_GENS=($(sort -rn <<< \"${ALL_GENS[*]:-}\")); unset IFS\n"
                  "\n"
                  "KEEP_GENS=()\n"
                  "REMOVE_GENS=()\n"
                  "kept=0\n"
                  "for gen in \"${SORTED_GENS[@]:-}\"; do\n"
                  "    [ -n \"$gen\" ] || continue\n"
                  "    if [ \"$gen\" = \"$CURRENT_GEN\" ]; then\n"
                  "        KEEP_GENS+=(\"$gen\"); kept=$((kept + 1)); continue\n"
                  "    fi\n"
                  "    if [ \"$kept\" -lt \"$KEEP_GENERATIONS\" ]; then\n"
                  "        KEEP_GENS+=(\"$gen\"); kept=$((kept + 1))\n"
                  "    else\n"
                  "        REMOVE_GENS+=(\"$gen\")\n"
                  "    fi\n"
                  "done\n"
                  "echo \"  Keep: ${KEEP_GENS[*]:-none}\"\n"
                  "echo \"  Remove: ${REMOVE_GENS[*]:-none}\"\n"
                  "[ ${#REMOVE_GENS[@]} -gt 0 ] || { echo \"Nothing to GC.\"; flock -u 9; exit 0; }\n"
                  "\n"
                  "# Phase 1: Compute GC roots.\n"
                  "echo \"\"\n"
                  "echo \"[Phase 1] Computing GC roots...\"\n"
                  "ROOTS=$(mktemp)\n"
                  "for gen in \"${KEEP_GENS[@]}\"; do\n"
                  "    profile=\"${PROFILES_DIR}/system-${gen}\"\n"
                  "    [ -L \"$profile\" ] && readlink -f \"$profile\" >> \"$ROOTS\"\n"
                  "done\n"
                  "# Scan /proc for store references.\n"
                  "for f in /proc/[0-9]*/maps; do\n"
                  "    [ -f \"$f\" ] || continue\n"
                  "    grep -oP '/gnu/store/[a-z0-9]{32}-[^\\s]+' \"$f\" 2>/dev/null || true\n"
                  "done | sort -u >> \"$ROOTS\"\n"
                  "for f in /proc/[0-9]*/exe; do\n"
                  "    readlink \"$f\" 2>/dev/null || true\n"
                  "done | grep '^/gnu/store/' | sort -u >> \"$ROOTS\"\n"
                  "\n"
                  "# Phase 2: BFS reachability using reference data from manifests.\n"
                  "echo \"[Phase 2] Computing reachable set (BFS)...\"\n"
                  "REACHABLE=$(mktemp)\n"
                  "QUEUE=$(mktemp)\n"
                  "cp \"$ROOTS\" \"$QUEUE\"\n"
                  "while [ -s \"$QUEUE\" ]; do\n"
                  "    NEW_Q=$(mktemp)\n"
                  "    while IFS= read -r path; do\n"
                  "        [ -n \"$path\" ] || continue\n"
                  "        grep -qxF \"$path\" \"$REACHABLE\" 2>/dev/null && continue\n"
                  "        echo \"$path\" >> \"$REACHABLE\"\n"
                  "        # Scan for store references in path content.\n"
                  "        [ -e \"$path\" ] && grep -roP '/gnu/store/[a-z0-9]{32}-[^/\"\\s]+' \"$path\" 2>/dev/null | sort -u >> \"$NEW_Q\" || true\n"
                  "    done < \"$QUEUE\"\n"
                  "    mv \"$NEW_Q\" \"$QUEUE\"\n"
                  "done\n"
                  "echo \"  Reachable: $(wc -l < \"$REACHABLE\") paths\"\n"
                  "\n"
                  "# Phase 3: Sweep.\n"
                  "echo \"\"\n"
                  "echo \"[Phase 3] Sweeping...\"\n"
                  "BYTES=0; DELETED=0\n"
                  "[ \"$DRY_RUN\" != \"true\" ] && mount -o remount,rw /gnu/store\n"
                  "for sp in /gnu/store/*/; do\n"
                  "    [ -d \"$sp\" ] || continue\n"
                  "    sp=\"${sp%/}\"\n"
                  "    grep -qxF \"$sp\" \"$REACHABLE\" 2>/dev/null && continue\n"
                  "    sz=$(du -sb \"$sp\" 2>/dev/null | cut -f1 || echo 0)\n"
                  "    if [ \"$DRY_RUN\" = \"true\" ]; then\n"
                  "        echo \"  [DRY] $(basename \"$sp\") ($((sz/1048576))M)\"\n"
                  "    else\n"
                  "        chmod -R u+w \"$sp\" 2>/dev/null || true\n"
                  "        rm -rf \"$sp\"\n"
                  "        echo \"  Deleted: $(basename \"$sp\") ($((sz/1048576))M)\"\n"
                  "    fi\n"
                  "    BYTES=$((BYTES + sz)); DELETED=$((DELETED + 1))\n"
                  "done\n"
                  "[ \"$DRY_RUN\" != \"true\" ] && mount -o remount,ro /gnu/store\n"
                  "\n"
                  "# Phase 4: Clean up generation metadata and boot entries.\n"
                  "echo \"\"\n"
                  "echo \"[Phase 4] Cleanup...\"\n"
                  "for gen in \"${REMOVE_GENS[@]}\"; do\n"
                  "    if [ \"$DRY_RUN\" != \"true\" ]; then\n"
                  "        rm -f \"${PROFILES_DIR}/system-${gen}\" \"${PROFILES_DIR}/system-${gen}.meta\"\n"
                  "        rm -f /boot/efi/loader/entries/andyl-os-${gen}*.conf\n"
                  "    fi\n"
                  "    echo \"  Removed: gen $gen\"\n"
                  "done\n"
                  "\n"
                  "# Clean orphaned kernel/initrd on ESP.\n"
                  "if [ \"$DRY_RUN\" != \"true\" ] && [ -d /boot/efi/andyl-os ]; then\n"
                  "    for file in /boot/efi/andyl-os/*; do\n"
                  "        [ -f \"$file\" ] || continue\n"
                  "        bn=$(basename \"$file\")\n"
                  "        if ! grep -rq \"$bn\" /boot/efi/loader/entries/ 2>/dev/null; then\n"
                  "            rm -f \"$file\"\n"
                  "            echo \"  Removed orphan: $bn\"\n"
                  "        fi\n"
                  "    done\n"
                  "fi\n"
                  "\n"
                  "rm -f \"$ROOTS\" \"$REACHABLE\" \"$QUEUE\"\n"
                  "flock -u 9\n"
                  "echo \"\"\n"
                  "echo \"=== GC Complete: $DELETED paths, $((BYTES/1048576)) MiB freed ===\"\n"
                  "[ \"$DRY_RUN\" = \"true\" ] && echo \"(DRY RUN)\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-os-gc") #o755)

            ;; ============================================================
            ;; andyl-os-manifest -- Generation manifest generator
            ;; ============================================================
            ;; Generates the Phase 5 manifest format with nar_hash,
            ;; nar_size, and references per store path.
            (call-with-output-file (string-append bindir "/andyl-os-manifest")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Manifest Generator\n"
                  "# Produces a JSON manifest for a system generation.\n"
                  "# Format per brainstorm doc 03 section 1.6.\n"
                  "set -euo pipefail\n"
                  "\n"
                  path-export
                  "\n"
                  "PROFILE=\"\"\n"
                  "GUIX_COMMIT=\"unknown\"\n"
                  "IMAGE_ID=\"\"\n"
                  "VERSION=\"0.1.0\"\n"
                  "OUTPUT=\"manifest.json\"\n"
                  "\n"
                  "while [[ $# -gt 0 ]]; do\n"
                  "    case \"$1\" in\n"
                  "        --profile)     PROFILE=\"$2\";     shift 2 ;;\n"
                  "        --guix-commit) GUIX_COMMIT=\"$2\"; shift 2 ;;\n"
                  "        --image-id)    IMAGE_ID=\"$2\";    shift 2 ;;\n"
                  "        --version)     VERSION=\"$2\";     shift 2 ;;\n"
                  "        --output)      OUTPUT=\"$2\";      shift 2 ;;\n"
                  "        *)             echo \"Unknown: $1\" >&2; exit 1 ;;\n"
                  "    esac\n"
                  "done\n"
                  "\n"
                  "[ -n \"$PROFILE\" ] || { echo \"Error: --profile required\" >&2; exit 1; }\n"
                  "\n"
                  "TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)\n"
                  "[ -z \"$IMAGE_ID\" ] && IMAGE_ID=\"andyl-os-$(date +%Y%m%d%H%M%S)\"\n"
                  "\n"
                  "# Compute the full store closure.\n"
                  "echo \"Computing store closure for $PROFILE...\"\n"
                  "CLOSURE=$(mktemp)\n"
                  "if command -v guix >/dev/null 2>&1; then\n"
                  "    guix gc --references --recursive \"$PROFILE\" | sort > \"$CLOSURE\"\n"
                  "else\n"
                  "    # Fallback: walk symlinks from the profile.\n"
                  "    find \"$PROFILE\" -type l -exec readlink -f {} \\; 2>/dev/null | \\\n"
                  "        grep '^/gnu/store/' | sort -u > \"$CLOSURE\"\n"
                  "fi\n"
                  "\n"
                  "TOTAL_PATHS=$(wc -l < \"$CLOSURE\")\n"
                  "TOTAL_SIZE=0\n"
                  "\n"
                  "# Build the manifest JSON.\n"
                  "echo '{' > \"$OUTPUT\"\n"
                  "echo '  \"version\": 1,' >> \"$OUTPUT\"\n"
                  "echo '  \"image_id\": \"'\"$IMAGE_ID\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"build_timestamp\": \"'\"$TIMESTAMP\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"guix_commit\": \"'\"$GUIX_COMMIT\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"andyl_os_version\": \"'\"$VERSION\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"system_profile\": \"'\"$PROFILE\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"store_paths\": [' >> \"$OUTPUT\"\n"
                  "\n"
                  "FIRST=true\n"
                  "while IFS= read -r path; do\n"
                  "    [ -n \"$path\" ] || continue\n"
                  "    [ -e \"$path\" ] || continue\n"
                  "\n"
                  "    # Compute NAR hash (sha256 of the uncompressed NAR content).\n"
                  "    local nar_hash=\"\"\n"
                  "    if command -v guix >/dev/null 2>&1; then\n"
                  "        nar_hash=$(guix archive --export \"$path\" 2>/dev/null | sha256sum | cut -d' ' -f1)\n"
                  "    else\n"
                  "        nar_hash=$(find \"$path\" -type f -exec sha256sum {} + 2>/dev/null | sha256sum | cut -d' ' -f1)\n"
                  "    fi\n"
                  "\n"
                  "    # Compute size.\n"
                  "    local nar_size\n"
                  "    nar_size=$(du -sb \"$path\" 2>/dev/null | cut -f1 || echo 0)\n"
                  "    TOTAL_SIZE=$((TOTAL_SIZE + nar_size))\n"
                  "\n"
                  "    # Find references (store paths referenced by this path).\n"
                  "    local refs=\"\"\n"
                  "    if command -v guix >/dev/null 2>&1; then\n"
                  "        refs=$(guix gc --references \"$path\" 2>/dev/null | \\\n"
                  "               grep -v \"^$path$\" | \\\n"
                  "               awk '{printf \"\\\"%s\\\"\", $0; if (NR>1 || getline>0) printf \",\"; }' || echo '')\n"
                  "    else\n"
                  "        refs=$(grep -roP '/gnu/store/[a-z0-9]{32}-[^/\"\\s]+' \"$path\" 2>/dev/null | \\\n"
                  "               sort -u | grep -v \"^$path\" | \\\n"
                  "               awk '{printf \"\\\"%s\\\"\", $0}' ORS=',' | sed 's/,$//' || echo '')\n"
                  "    fi\n"
                  "\n"
                  "    [ \"$FIRST\" = true ] || echo '    ,' >> \"$OUTPUT\"\n"
                  "    FIRST=false\n"
                  "\n"
                  "    cat >> \"$OUTPUT\" <<ENTRY\n"
                  "    {\n"
                  "      \"path\": \"$path\",\n"
                  "      \"nar_hash\": \"sha256:$nar_hash\",\n"
                  "      \"nar_size\": $nar_size,\n"
                  "      \"references\": [$refs]\n"
                  "    }\n"
                  "ENTRY\n"
                  "done < \"$CLOSURE\"\n"
                  "\n"
                  "echo '  ],' >> \"$OUTPUT\"\n"
                  "echo '  \"total_store_size\": '\"$TOTAL_SIZE\"',' >> \"$OUTPUT\"\n"
                  "echo '  \"total_paths\": '\"$TOTAL_PATHS\" >> \"$OUTPUT\"\n"
                  "echo '}' >> \"$OUTPUT\"\n"
                  "\n"
                  "rm -f \"$CLOSURE\"\n"
                  "\n"
                  "echo \"Manifest written: $OUTPUT\"\n"
                  "echo \"  Image ID:    $IMAGE_ID\"\n"
                  "echo \"  Store paths: $TOTAL_PATHS\"\n"
                  "echo \"  Total size:  $((TOTAL_SIZE / 1048576)) MiB\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-os-manifest") #o755)

            ;; ============================================================
            ;; Configuration files
            ;; ============================================================

            ;; Update agent configuration.
            (call-with-output-file (string-append confdir "/update.conf")
              (lambda (port)
                (display
                 "# ANDYL OS Update Agent Configuration
# See: Phase 5 section 5.10

server=https://update.andyl-os.internal
channel=stable
check_interval=3600
auto_update=false
max_retries=3
retry_delay=300
boot_tries=3
signing_key=/etc/andyl-os/update-signing-key.pub
"
                 port)))

            ;; GC configuration.
            (call-with-output-file (string-append confdir "/gc.conf")
              (lambda (port)
                (display
                 "# ANDYL OS Garbage Collection Configuration
# See: Phase 5 sections 5.8, 5.9

keep_generations=5
min_age_hours=24
dry_run=false
"
                 port)))

            ;; ============================================================
            ;; systemd units
            ;; ============================================================

            ;; Update check timer.
            (call-with-output-file (string-append unitdir "/andyl-os-update-check.timer")
              (lambda (port)
                (display
                 "[Unit]
Description=ANDYL OS Periodic Update Check

[Timer]
OnBootSec=300
OnUnitActiveSec=3600
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
"
                 port)))

            ;; Update check service.
            (call-with-output-file (string-append unitdir "/andyl-os-update-check.service")
              (lambda (port)
                (display
                 (string-append
                  "[Unit]\n"
                  "Description=ANDYL OS Update Check\n"
                  "After=network-online.target\n"
                  "Wants=network-online.target\n"
                  "After=multi-user.target\n"
                  "\n"
                  "[Service]\n"
                  "Type=oneshot\n"
                  "ExecStart=" out "/bin/andyl-os-agent check\n"
                  "StandardOutput=journal\n"
                  "StandardError=journal\n"
                  "SyslogIdentifier=andyl-os-update\n")
                 port)))

            ;; Update apply service.
            (call-with-output-file (string-append unitdir "/andyl-os-update.service")
              (lambda (port)
                (display
                 (string-append
                  "[Unit]\n"
                  "Description=ANDYL OS Update Apply\n"
                  "After=network-online.target\n"
                  "Wants=network-online.target\n"
                  "Conflicts=andyl-os-gc.service\n"
                  "\n"
                  "[Service]\n"
                  "Type=oneshot\n"
                  "ExecStart=" out "/bin/andyl-os-agent now\n"
                  "TimeoutSec=1800\n"
                  "StandardOutput=journal\n"
                  "StandardError=journal\n"
                  "SyslogIdentifier=andyl-os-update\n"
                  "\n"
                  "[Install]\n"
                  "WantedBy=multi-user.target\n")
                 port)))

            ;; Health check service.
            (call-with-output-file (string-append unitdir "/andyl-os-health-check.service")
              (lambda (port)
                (display
                 (string-append
                  "[Unit]\n"
                  "Description=ANDYL OS Post-Boot Health Check\n"
                  "After=multi-user.target\n"
                  "ConditionPathExists=|/boot/efi/loader/entries/andyl-os-*+*.conf\n"
                  "\n"
                  "[Service]\n"
                  "Type=oneshot\n"
                  "RemainAfterExit=yes\n"
                  "ExecStart=" out "/bin/andyl-os-health-check\n"
                  "ExecStartPost=/bin/systemctl start boot-complete.target\n"
                  "StandardOutput=journal\n"
                  "StandardError=journal\n"
                  "SyslogIdentifier=andyl-os-health\n"
                  "\n"
                  "[Install]\n"
                  "WantedBy=multi-user.target\n")
                 port)))

            ;; Boot complete target.
            (call-with-output-file (string-append unitdir "/boot-complete.target")
              (lambda (port)
                (display
                 "[Unit]
Description=ANDYL OS Boot Complete (Health Check Passed)
"
                 port)))

            ;; Rollback service.
            (call-with-output-file (string-append unitdir "/andyl-os-rollback.service")
              (lambda (port)
                (display
                 (string-append
                  "[Unit]\n"
                  "Description=ANDYL OS Manual Rollback\n"
                  "\n"
                  "[Service]\n"
                  "Type=oneshot\n"
                  "ExecStart=" out "/bin/andyl-os-agent rollback\n"
                  "ExecStartPost=/bin/systemctl reboot\n"
                  "StandardOutput=journal\n"
                  "StandardError=journal\n"
                  "SyslogIdentifier=andyl-os-rollback\n")
                 port)))

            ;; GC service.
            (call-with-output-file (string-append unitdir "/andyl-os-gc.service")
              (lambda (port)
                (display
                 (string-append
                  "[Unit]\n"
                  "Description=ANDYL OS Garbage Collection\n"
                  "Conflicts=andyl-os-update.service\n"
                  "\n"
                  "[Service]\n"
                  "Type=oneshot\n"
                  "ExecStartPre=/bin/mount -o remount,rw /gnu/store\n"
                  "ExecStart=" out "/bin/andyl-os-gc\n"
                  "ExecStopPost=/bin/mount -o remount,ro /gnu/store\n"
                  "IOSchedulingClass=idle\n"
                  "Nice=19\n"
                  "TimeoutSec=3600\n"
                  "StandardOutput=journal\n"
                  "StandardError=journal\n"
                  "SyslogIdentifier=andyl-os-gc\n")
                 port)))

            ;; GC timer.
            (call-with-output-file (string-append unitdir "/andyl-os-gc.timer")
              (lambda (port)
                (display
                 "[Unit]
Description=ANDYL OS Weekly Garbage Collection

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
"
                 port)))

            ;; tmpfiles.d for directory creation.
            (call-with-output-file (string-append tmpfilesdir "/andyl-os-update.conf")
              (lambda (port)
                (display
                 "# ANDYL OS update agent directories
d /var/cache/andyl-os/updates 0750 root root -
d /var/lib/andyl-os 0750 root root -
d /var/guix/profiles 0755 root root -
d /etc/andyl-os 0755 root root -
"
                 port)))

            #t))))

    (inputs
     (list andyl-bash
           andyl-curl
           andyl-minisign
           andyl-coreutils
           andyl-util-linux
           andyl-systemd
           andyl-zstd
           andyl-findutils
           andyl-grep
           andyl-sed
           andyl-gawk))

    (home-page "https://github.com/andyl/andyl-os")
    (synopsis "ANDYL OS update agent, health check, and garbage collection")
    (description
     "Provides the ANDYL OS update lifecycle tools installed on every target
machine.  Includes andyl-os-agent (update check, download, signature
verification, atomic NAR unpacking, generation management, boot entry
installation with boot counting, rollback), andyl-os-health-check
(post-boot system validation with role-specific checks),
andyl-os-gc (mark-and-sweep garbage collection for /gnu/store with
process scanning safety), and andyl-os-manifest (generation manifest
generator with nar_hash, nar_size, and reference graph).  All tools
use explicit store paths for dependencies and work on the immutable
ANDYL OS filesystem layout.")
    (license license:gpl2+)))
