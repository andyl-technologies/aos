##! lib/containers/init-script.nix -- daemonless container initialization.
##!
##! Returns the exact script bytes used as the `aos` container entrypoint.  A
##! compile-time root prefix exists only so the focused derivation test can run
##! the same transaction against a Nix `local?root=` store without chroot or
##! mount privileges.  Production callers leave `rootPrefix` empty.
{
  lib,
  pkgs,
  rootPrefix ? "",
  registrationPath ? "${rootPrefix}/aos-registration",
  storePathsPath ? "${rootPrefix}/usr/lib/aos-container/store-paths",
  bakedRootsPath ? "${rootPrefix}/usr/lib/aos-container/baked-roots",
  defaultCommand ? ["/usr/bin/aos" "--help"],
}: let
  rootPath = path: "${rootPrefix}${path}";
  initPath = lib.makeBinPath [pkgs.nix pkgs.coreutils pkgs.findutils pkgs.grep pkgs.util-linux];
  defaultCommandScript = lib.concatMapStringsSep " " lib.escapeShellArg defaultCommand;
in ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  fail() {
    printf 'aos-container-init: %s\n' "$1" >&2
    exit 1
  }

  root_prefix=${lib.escapeShellArg rootPrefix}
  registration=${lib.escapeShellArg registrationPath}
  store_paths=${lib.escapeShellArg storePathsPath}
  baked_roots=${lib.escapeShellArg bakedRootsPath}
  store_dir=${lib.escapeShellArg (rootPath "/nix/store")}
  state_dir=${lib.escapeShellArg (rootPath "/nix/var/nix")}
  gcroots_dir=${lib.escapeShellArg (rootPath "/nix/var/nix/gcroots")}
  profile_gcroots=${lib.escapeShellArg (rootPath "/nix/var/nix/gcroots/aos-profiles")}
  init_lock="$state_dir/.aos-container-init.lock"
  ready_marker="$state_dir/.aos-container-ready"
  read_only_marker="$state_dir/.aos-container-read-only"

  runtime_path="''${PATH-}"
  PATH=${lib.escapeShellArg initPath}
  export PATH

  # Select the in-process local store explicitly so even an injected daemon
  # socket cannot change the initialization boundary.
  if [ -n "$root_prefix" ]; then
    NIX_REMOTE="local?root=$root_prefix"
  else
    NIX_REMOTE="local"
  fi
  export NIX_REMOTE
  unset AOS_CONTAINER_READ_ONLY

  nix_store() {
    nix-store "$@"
  }

  validate_embedded_inventory() {
    [ -r "$registration" ] \
      || fail "embedded closure registration is missing: $registration"
    [ -r "$store_paths" ] \
      || fail "embedded closure inventory is missing: $store_paths"
    [ -r "$baked_roots" ] \
      || fail "embedded baked-root inventory is missing: $baked_roots"

    duplicate=$(sort "$baked_roots" | uniq -d)
    [ -z "$duplicate" ] \
      || fail "embedded baked-root inventory contains a duplicate: $duplicate"

    root_count=0
    while IFS= read -r baked_root || [ -n "$baked_root" ]; do
      [ -n "$baked_root" ] \
        || fail "embedded baked-root inventory contains an empty line"
      if [[ ! "$baked_root" =~ ^/nix/store/[0-9a-z]{32}-[^/]+$ ]]; then
        fail "embedded baked root is not a canonical store path: $baked_root"
      fi
      grep -Fx "$baked_root" "$store_paths" >/dev/null \
        || fail "baked root is absent from the embedded closure: $baked_root"
      [ -e "$root_prefix$baked_root" ] \
        || fail "baked root bytes are absent from the image: $baked_root"
      root_count=$((root_count + 1))
    done < "$baked_roots"
    [ "$root_count" -gt 0 ] \
      || fail "embedded baked-root inventory is empty"
  }

  probe_directory() {
    probe="$1/.aos-container-write-probe.$$"
    if mkdir "$probe" 2>/dev/null; then
      rmdir "$probe" \
        || fail "could not remove writability probe: $probe"
      return 0
    fi
    return 1
  }

  reconcile_baked_roots() {
    live="$gcroots_dir/aos-container-baked"
    # A killed initializer can leave a partially populated temporary set. The
    # held init lock proves none is live, and removing it avoids accidental
    # permanent roots during later garbage collections.
    find "$gcroots_dir" -mindepth 1 -maxdepth 1 -type d \
      -name '.aos-container-baked.fresh.*' -exec rm -rf -- {} +
    fresh=$(mktemp -d "$gcroots_dir/.aos-container-baked.fresh.XXXXXXXXXX") \
      || fail "could not allocate a fresh baked GC-root set"

    while IFS= read -r baked_root || [ -n "$baked_root" ]; do
      root_name="''${baked_root##*/}"
      ln -s "$baked_root" "$fresh/$root_name"
    done < "$baked_roots"

    if [ -e "$live" ] || [ -L "$live" ]; then
      mv --exchange --no-copy -T "$fresh" "$live" \
        || fail "could not atomically exchange baked GC roots"
      # After the exchange this path names the old complete root set. Both the
      # old and fresh sets stayed below gcroots throughout the transaction.
      rm -rf -- "$fresh"
    else
      mv --no-copy -T "$fresh" "$live" \
        || fail "could not atomically publish baked GC roots"
    fi
  }

  validate_embedded_inventory

  # Probe actual mutations rather than mode bits: root can pass `test -w` on an
  # EROFS mount. A writable state mount can rebuild the local database even when
  # immutable store bytes remain read-only.
  state_writable=0
  store_writable=0
  if probe_directory "$state_dir"; then
    state_writable=1
  fi
  if probe_directory "$store_dir"; then
    store_writable=1
  fi
  if [ "$store_writable" -ne 1 ] || [ "$state_writable" -ne 1 ]; then
    AOS_CONTAINER_READ_ONLY=1
    export AOS_CONTAINER_READ_ONLY
  fi

  # A read-only state directory cannot be initialized or reconciled. Baked
  # commands still run directly from the embedded store and receive the marker
  # used by APM to reject mutation actionably.
  if [ "$state_writable" -ne 1 ]; then
    PATH="$runtime_path"
    export PATH
    if [ "$#" -eq 0 ]; then
      set -- ${defaultCommandScript}
    fi
    exec "$@"
  fi

  exec 9<> "$init_lock" \
    || fail "could not open the container initialization lock"
  chmod 0600 "$init_lock" \
    || fail "could not protect the container initialization lock"
  flock -x 9 \
    || fail "could not acquire the container initialization lock"

  # The marker from an earlier PID-1 lifecycle must never admit a concurrent
  # runtime exec. Removing it while holding the exclusive lock makes the
  # marker and lock one readiness transaction.
  rm -f -- "$ready_marker" "$read_only_marker"

  # Publish roots before the database can expose any baked path as valid.
  # Container runtimes report a task as running while its entrypoint is still
  # initializing, so a concurrent `exec nix-store --gc` can otherwise observe
  # the interval after `--load-db` but before root publication and collect the
  # newly registered closure. An empty replacement state directory also needs
  # its gcroots parent created before the transaction.
  mkdir -p "$gcroots_dir"
  reconcile_baked_roots

  nix_store --init \
    || fail "could not initialize the local Nix database; /nix must be writable"
  nix_store --load-db < "$registration" \
    || fail "could not load the embedded Nix registration into the local database"

  while IFS= read -r baked_root || [ -n "$baked_root" ]; do
    nix_store --check-validity "$baked_root" \
      || fail "registered baked root is invalid: $baked_root"
  done < "$baked_roots"

  # APM generations live below a directory Nix already scans as GC roots.
  # `/var/lib/profiles` is an image-authored symlink to this real directory.
  mkdir -p \
    "$profile_gcroots/per-user/root" \
    ${lib.escapeShellArg (rootPath "/root/.cache/apm")} \
    ${lib.escapeShellArg (rootPath "/root/.config/apm")} \
    ${lib.escapeShellArg (rootPath "/root/.local/share/apm")} \
    ${lib.escapeShellArg (rootPath "/root/.local/share/apm/registries")} \
    ${lib.escapeShellArg (rootPath "/root/.local/share/apm/remote")} \
    ${lib.escapeShellArg (rootPath "/root/.local/state/apm")} \
    ${lib.escapeShellArg (rootPath "/var/cache/apm")} \
    ${lib.escapeShellArg (rootPath "/var/lib/apm")}

  if [ "$store_writable" -ne 1 ]; then
    read_only_fresh=$(mktemp "$state_dir/.aos-container-read-only.fresh.XXXXXXXXXX") \
      || fail "could not allocate the container read-only marker"
    printf 'schema=aos.container.read-only/v1\n' > "$read_only_fresh"
    chmod 0444 "$read_only_fresh"
    mv --no-copy -T "$read_only_fresh" "$read_only_marker" \
      || fail "could not publish the container read-only marker"
  fi

  pid1_stat=$(< /proc/1/stat) \
    || fail "could not read PID-1 identity"
  pid1_fields_text="''${pid1_stat##*) }"
  read -r -a pid1_fields <<< "$pid1_fields_text"
  [ "''${#pid1_fields[@]}" -gt 19 ] \
    || fail "PID-1 stat omits its start time"
  pid1_start_time="''${pid1_fields[19]}"
  if [[ ! "$pid1_start_time" =~ ^[0-9]+$ ]]; then
    fail "PID-1 stat contains an invalid start time"
  fi

  ready_fresh=$(mktemp "$state_dir/.aos-container-ready.fresh.XXXXXXXXXX") \
    || fail "could not allocate the container readiness marker"
  printf 'schema=aos.container.ready/v1\npid1_start_time=%s\n' \
    "$pid1_start_time" > "$ready_fresh"
  chmod 0444 "$ready_fresh"
  mv --no-copy -T "$ready_fresh" "$ready_marker" \
    || fail "could not publish the container readiness marker"

  flock -u 9 \
    || fail "could not release the container initialization lock"
  exec 9>&-

  PATH="$runtime_path"
  export PATH
  if [ "$#" -eq 0 ]; then
    set -- ${defaultCommandScript}
  fi
  exec "$@"
''
