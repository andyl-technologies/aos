# Patches shell entry points with their declared interpreter.
# Invoke through the build shell; this file is not an executable entry point.
# The caller supplies AOS_RUNTIME_SHELL and optionally AOS_BUILD_SHELL.

set -eu

: "${AOS_RUNTIME_SHELL:?missing runtime shell}"
runtime_root=$1
runtime_list=${TMPDIR:?missing temporary directory}/aos-runtime-scripts-$$

# Snapshot the input names before creating temporary siblings in the tree.
find "$runtime_root" -type f -print0 > "$runtime_list"
while IFS= read -r -d '' runtime_file; do
    runtime_magic=$(head -c 2 "$runtime_file")
    [ "$runtime_magic" = '#!' ] || continue

    IFS= read -r runtime_header < "$runtime_file" || true
    runtime_header=${runtime_header#\#!}
    IFS=' 	' read -r runtime_interpreter runtime_arguments <<EOF
$runtime_header
EOF
    runtime_program=${runtime_interpreter##*/}

    if [ "$runtime_program" = env ]; then
        if [ "${runtime_arguments#-S }" != "$runtime_arguments" ]; then
            runtime_arguments=${runtime_arguments#-S }
        fi
        IFS=' 	' read -r runtime_program runtime_arguments <<EOF
$runtime_arguments
EOF
    fi

    case "$runtime_program" in
        sh|bash)
            runtime_interpreter=$AOS_RUNTIME_SHELL
            ;;
        *)
            continue
            ;;
    esac

    # Stream back into the existing inode: old sed's in-place mode is not
    # reliable on every kernel, and replacing an inode can split hard links.
    {
        printf '#!%s%s\n' "$runtime_interpreter" "${runtime_arguments:+ $runtime_arguments}"
        sed '1d' "$runtime_file"
    } > "$runtime_file.aos-runtime"

    if [ -n "${AOS_BUILD_SHELL:-}" ] && [ "$AOS_BUILD_SHELL" != "$AOS_RUNTIME_SHELL" ]; then
        sed "s|$AOS_BUILD_SHELL|$AOS_RUNTIME_SHELL|g" \
            "$runtime_file.aos-runtime" > "$runtime_file.aos-runtime-body"
        cat "$runtime_file.aos-runtime-body" > "$runtime_file.aos-runtime"
        rm "$runtime_file.aos-runtime-body"
    fi

    # Match whole FHS shell paths, including quoted defaults, without
    # rewriting the suffix of an already qualified store path.
    sed ":again; s@\(^\|[^/[:alnum:]_.]\)/\(usr/bin/\|bin/\)\(sh\|bash\)\([^/[:alnum:]_.-]\|$\)@\1$AOS_RUNTIME_SHELL\4@g; t again" \
        "$runtime_file.aos-runtime" > "$runtime_file.aos-runtime-body"
    cat "$runtime_file.aos-runtime-body" > "$runtime_file.aos-runtime"
    rm "$runtime_file.aos-runtime-body"

    chmod --reference="$runtime_file" "$runtime_file.aos-runtime"
    # Source trees also use this pass. Preserve dependency timestamps so
    # pinning an interpreter does not trigger autotools regeneration.
    touch -r "$runtime_file" "$runtime_file.aos-runtime"
    chmod u+w "$runtime_file"
    cat "$runtime_file.aos-runtime" > "$runtime_file"
    chmod --reference="$runtime_file.aos-runtime" "$runtime_file"
    touch -r "$runtime_file.aos-runtime" "$runtime_file"
    rm "$runtime_file.aos-runtime"
done < "$runtime_list"
rm "$runtime_list"
