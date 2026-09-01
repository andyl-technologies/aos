##! lib/build/oci/common.nix -- shared OCI builder invariants.
##!
##! This file owns the byte-level archive ABI and pure validation used by every
##! OCI builder.  Keeping the tar command in one place is intentional: a flag,
##! tool-version, or member-list change changes layer DiffIDs and therefore is a
##! reviewed artifact ABI change.
{lib}: let
  fail = message: throw "AOS OCI builder: ${message}";

  hasNewline = value: lib.hasInfix "\n" value || lib.hasInfix "\r" value;
  safeComponent = component:
    component
    != ""
    && component != "."
    && component != ".."
    && builtins.match "^[A-Za-z0-9_+@%.,:=?-]+$" component != null;
  components = path: lib.filter (component: component != "") (lib.splitString "/" path);

  validAbsolutePath = path:
    builtins.isString path
    && lib.hasPrefix "/" path
    && path != "/"
    && !lib.hasSuffix "/" path
    && !lib.hasInfix "//" path
    && !hasNewline path
    && lib.all safeComponent (components path);

  validRelativeTarget = target:
    builtins.isString target
    && target != ""
    && !lib.hasPrefix "/" target
    && !lib.hasSuffix "/" target
    && !lib.hasInfix "//" target
    && !hasNewline target
    && lib.all safeComponent (lib.splitString "/" target);

  validatePath = context: path:
    if validAbsolutePath path
    then path
    else fail "${context} must be a canonical absolute path with safe components, got ${builtins.toJSON path}";

  validateTarget = context: target:
    if validAbsolutePath target || validRelativeTarget target
    then target
    else fail "${context} must be a canonical absolute or non-traversing relative symlink target";

  validateMode = context: mode:
    if builtins.isString mode && builtins.match "^[0-7][0-7][0-7][0-7]$" mode != null
    then mode
    else fail "${context} must be a four-digit octal mode";

  validateText = context: value:
  # Nix strings cannot contain NUL, so a string type check is also the NUL
  # boundary for authored argv, environment, labels, and file contents.
    if builtins.isString value
    then value
    else fail "${context} must be a NUL-free string";

  validateStringList = context: values:
    if builtins.isList values
    then lib.imap (index: value: validateText "${context}[${toString index}]" value) values
    else fail "${context} must be a list";

  validateStringAttrs = context: values:
    if builtins.isAttrs values
    then
      lib.mapAttrs (
        name: value:
          if safeComponent name
          then validateText "${context}.${name}" value
          else fail "${context} contains an unsafe key ${builtins.toJSON name}"
      )
      values
    else fail "${context} must be an attribute set";

  validRepositoryComponent = component:
    builtins.match "[a-z0-9]+(([.]|[_][_]?|[-]+)[a-z0-9]+)*" component != null;
  validRepository = value:
    builtins.isString value
    && value != ""
    && builtins.stringLength value <= 255
    && lib.all validRepositoryComponent (lib.splitString "/" value);
  validTag = value:
    builtins.isString value
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}" value != null;

  validateRepository = context: value:
    if validRepository value
    then value
    else fail "${context} is not a canonical registry-local OCI repository";

  validateTag = context: value:
    if validTag value
    then value
    else fail "${context} is not a canonical OCI tag";

  validateTaggedReference = context: value: let
    match =
      if builtins.isString value
      then builtins.match "(.+):([^:]+)" value
      else null;
    repository =
      if match == null
      then null
      else builtins.elemAt match 0;
    tag =
      if match == null
      then null
      else builtins.elemAt match 1;
  in
    if match != null && validRepository repository && validTag tag
    then value
    else fail "${context} must be a canonical repository:tag reference";

  validateStorePath = context: value: let
    path = builtins.toString value;
  in
    if builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" path != null
    then path
    else fail "${context} is not a canonical /nix/store path: ${path}";

  validateStoreFile = context: value: let
    path = builtins.toString value;
  in
    if
      builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+(/[A-Za-z0-9_+@%.,:=?-]+)*$" path
      != null
      && !hasNewline path
    then path
    else fail "${context} is not a canonical store-backed file path: ${path}";

  # A non-directory entry may not be the parent of another authored entry.
  # Rejecting this at evaluation prevents a symlink parent from redirecting a
  # later mkdir/copy outside the staging root.
  validateMetadataEntries = entries: let
    paths = map (entry: validatePath "metadata ${entry.kind} path" entry.path) entries;
    uniquePaths = lib.unique paths;
    validateOne = entry:
      if entry.kind == "directory"
      then true
      else
        lib.all (
          other:
            other == entry.path || !lib.hasPrefix "${entry.path}/" other
        )
        paths;
  in
    if builtins.length paths != builtins.length uniquePaths
    then fail "metadata entries contain duplicate paths"
    else if !lib.all validateOne entries
    then fail "a metadata file or symlink is the parent of another entry"
    else entries;

  validatePlatform = platform: let
    os = platform.os or "linux";
    architecture = platform.architecture or (fail "platform.architecture is required");
    variant = platform.variant or null;
  in
    if os != "linux"
    then fail "only linux OCI platforms are supported"
    else if !(builtins.elem architecture ["amd64" "arm64"])
    then fail "unsupported OCI architecture ${builtins.toJSON architecture}"
    else if variant != null && !(builtins.isString variant && builtins.match "^[A-Za-z0-9._-]+$" variant != null)
    then fail "platform.variant is invalid"
    else {inherit os architecture variant;};

  # `jq -cS` writes one trailing newline.  OCI digests cover exact JSON bytes,
  # so remove that byte explicitly rather than relying on shell substitution.
  jsonScript = ''
    write_compact_json() {
      json_source="$1"
      json_destination="$2"
      jq -cS . "$json_source" > "$json_destination.with-newline"
      json_size=$(stat -c %s "$json_destination.with-newline")
      if [ "$json_size" -le 0 ]; then
        echo "jq emitted an empty JSON document" >&2
        exit 1
      fi
      truncate -s "$((json_size - 1))" "$json_destination.with-newline"
      mv "$json_destination.with-newline" "$json_destination"
    }
  '';

  # Layer ABI v1, frozen by RFC-0017 and tests/containers/phase0.nix.
  archiveScript = ''
    verify_archive_tools() {
      tar_version=$(tar --version | head -n 1)
      gzip_version=$(gzip --version | head -n 1)
      if [ "$tar_version" != "tar (GNU tar) 1.35" ]; then
        echo "OCI layer ABI v1 requires AOS GNU tar 1.35, found: $tar_version" >&2
        exit 1
      fi
      if [ "$gzip_version" != "gzip 1.13" ]; then
        echo "OCI layer ABI v1 requires AOS gzip 1.13, found: $gzip_version" >&2
        exit 1
      fi
    }

    make_deterministic_tar() {
      archive_root="$1"
      member_file="$2"
      tar_output="$3"

      special=$(find "$archive_root" -mindepth 1 \
        \( -type b -o -type c -o -type p -o -type s \) -print -quit)
      if [ -n "$special" ]; then
        echo "OCI archives reject device, FIFO, and socket entries: $special" >&2
        exit 1
      fi

      find "$archive_root" -mindepth 1 -printf '%P\0' | sort -z > "$member_file"
      tar \
        -C "$archive_root" \
        --null \
        --verbatim-files-from \
        --no-recursion \
        --format=gnu \
        --mtime=@1 \
        --clamp-mtime \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        --no-acls \
        --no-selinux \
        --no-xattrs \
        --hard-dereference \
        -cf "$tar_output" \
        --files-from="$PWD/$member_file"
    }

    make_gzip_layer() {
      layer_root="$1"
      member_file="$2"
      tar_output="$3"
      gzip_output="$4"
      make_deterministic_tar "$layer_root" "$member_file" "$tar_output"
      gzip -n -9 -c "$tar_output" > "$gzip_output"
    }
  '';

  # These checks operate on realized closure inventories.  Keeping them in the
  # shared builder policy lets both production builders and focused negative
  # tests execute the exact same fail-closed code.
  realizedStorePolicyScript = ''
    validate_disjoint_layer_inventories() {
      inventory_work="$1"
      shift
      : > "$inventory_work.all"
      for inventory_layer in "$@"; do
        if [ -f "$inventory_layer/closure.json" ]; then
          jq -e '
            .schema == "aos.container.closure-layer/v1"
            and (.paths | type == "array")
            and ([.paths[].path] | length == (unique | length))
          ' "$inventory_layer/closure.json" >/dev/null
          jq -r '.paths[].path' "$inventory_layer/closure.json" \
            >> "$inventory_work.all"
        fi
      done

      sort "$inventory_work.all" > "$inventory_work.sorted"
      duplicate_store_path=$(uniq -d "$inventory_work.sorted" | head -n 1)
      if [ -n "$duplicate_store_path" ]; then
        echo "OCI layers contain the same realized store path more than once: $duplicate_store_path" >&2
        return 1
      fi
      uniq "$inventory_work.sorted" > "$inventory_work.allowed"
    }

    validate_store_symlink_target() {
      allowed_store_paths="$1"
      target="$2"
      require_executable="$3"

      case "$target" in
        /nix/store/*/*) ;;
        *)
          echo "metadata store target is not a file below a canonical store output: $target" >&2
          return 1
          ;;
      esac
      store_tail=''${target#/nix/store/}
      store_name=''${store_tail%%/*}
      store_root="/nix/store/$store_name"
      admitted=0
      while IFS= read -r allowed_store_path; do
        if [ "$allowed_store_path" = "$store_root" ]; then
          admitted=1
          break
        fi
      done < "$allowed_store_paths"
      if [ "$admitted" -ne 1 ]; then
        echo "metadata store target is absent from the image closure: $target" >&2
        return 1
      fi
      if [ ! -f "$target" ] || [ -L "$target" ]; then
        echo "metadata store target is not a regular non-symlink file: $target" >&2
        return 1
      fi
      if [ "$require_executable" = 1 ] && [ ! -x "$target" ]; then
        echo "metadata facade target is not executable: $target" >&2
        return 1
      fi
    }
  '';
in {
  inherit
    archiveScript
    fail
    jsonScript
    realizedStorePolicyScript
    validateMetadataEntries
    validateMode
    validatePath
    validatePlatform
    validateRepository
    validateStorePath
    validateStoreFile
    validateStringAttrs
    validateStringList
    validateTag
    validateTaggedReference
    validateTarget
    validateText
    ;

  layerMediaType = "application/vnd.oci.image.layer.v1.tar+gzip";
  configMediaType = "application/vnd.oci.image.config.v1+json";
  manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
  indexMediaType = "application/vnd.oci.image.index.v1+json";
  layoutVersion = "1.0.0";
  normalizedTimestamp = "1970-01-01T00:00:01Z";
}
