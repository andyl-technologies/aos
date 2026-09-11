# Filesystem, candidate, process, and PostgreSQL data invariants.
stat_fields() {
    "$COREUTILS/stat" -c '%F|%u|%g|%a|%h|%s' -- "$1"
}

validate_directory() {
    local path=$1
    local owner=$2
    local group=$3
    local expected_mode=$4
    local kind uid gid actual_mode links size

    [[ -d $path && ! -L $path ]] || fail 'PostgreSQL directory is not protected'
    IFS='|' read -r kind uid gid actual_mode links size < <(stat_fields "$path")
    [[ $kind == directory && $uid == "$owner" && $gid == "$group" \
        && $actual_mode == "$expected_mode" ]] \
        || fail 'PostgreSQL directory ownership or mode is invalid'
}

validate_regular() {
    local path=$1
    local owner=$2
    local group=$3
    local expected_mode=$4
    local maximum=$5
    local kind uid gid actual_mode links size

    [[ -f $path && ! -L $path ]] || fail 'PostgreSQL file is not protected'
    IFS='|' read -r kind uid gid actual_mode links size < <(stat_fields "$path")
    [[ $kind == 'regular file' && $uid == "$owner" && $gid == "$group" \
        && $actual_mode == "$expected_mode" && $links == 1 ]] \
        || fail 'PostgreSQL file ownership, mode, or link count is invalid'
    ((size <= maximum)) || fail 'PostgreSQL file exceeds its size bound'
}

validate_socket_directory() {
    validate_directory "$expected_run_directory" "$server_uid" "$probe_gid" 2710
}

validate_server_paths() {
    local storage_directory
    local cluster_digest
    local storage_digest

    cluster_digest=${cluster_directory#"$POSTGRESQL_ROOT/"}
    [[ $cluster_directory == "$POSTGRESQL_ROOT/$cluster_digest" \
        && $cluster_digest =~ ^[0-9a-f]{64}$ ]] \
        || fail 'PostgreSQL cluster path is not canonical'

    storage_directory=${data_directory%/data}
    storage_digest=${storage_directory#"$STORAGE_ROOT/"}
    [[ $data_directory == "$STORAGE_ROOT/$storage_digest/data" \
        && $storage_digest =~ ^[0-9a-f]{64}$ ]] \
        || fail 'PostgreSQL data path is not canonical'

    validate_directory "$cluster_directory" "$server_uid" "$server_gid" 700
    validate_directory "$storage_directory" "$server_uid" "$server_gid" 700
    validate_socket_directory
}

if [[ -n $cluster_directory ]]; then
    validate_server_paths
elif [[ -n $run_directory ]]; then
    validate_socket_directory
fi

active_config=${cluster_directory:+$cluster_directory/postgresql.conf}
active_hba=${cluster_directory:+$cluster_directory/pg_hba.conf}
active_ident=${cluster_directory:+$cluster_directory/pg_ident.conf}
final_config=${cluster_directory:+$cluster_directory/postgresql.final.conf}
final_hba=${cluster_directory:+$cluster_directory/pg_hba.final.conf}
final_ident=${cluster_directory:+$cluster_directory/pg_ident.final.conf}
quarantine_config=${cluster_directory:+$cluster_directory/postgresql.quarantine.conf}
quarantine_hba=${cluster_directory:+$cluster_directory/pg_hba.quarantine.conf}
quarantine_ident=${cluster_directory:+$cluster_directory/pg_ident.quarantine.conf}
server_log=${cluster_directory:+$cluster_directory/server.log}

final_config_text() {
    "$COREUTILS/printf" '%s\n' \
        "data_directory = '$data_directory'" \
        "hba_file = '$active_hba'" \
        "ident_file = '$active_ident'" \
        "listen_addresses = ''" \
        'shared_buffers = 8MB' \
        'max_connections = 8' \
        "port = $port" \
        "unix_socket_directories = '$run_directory'" \
        'unix_socket_permissions = 0770' \
        "password_encryption = 'scram-sha-256'" \
        "$REVISION_GUC = '$configuration_revision'"
}

quarantine_config_text() {
    "$COREUTILS/printf" '%s\n' \
        "data_directory = '$data_directory'" \
        "hba_file = '$active_hba'" \
        "ident_file = '$active_ident'" \
        "listen_addresses = ''" \
        'shared_buffers = 8MB' \
        'max_connections = 8' \
        "port = $port" \
        "unix_socket_directories = '$run_directory'" \
        'unix_socket_permissions = 0770' \
        "password_encryption = 'scram-sha-256'" \
        "$REVISION_GUC = '$configuration_revision'"
}

final_hba_text() {
    local method
    if [[ $auth == scram ]]; then
        method=scram-sha-256
    else
        method=trust
    fi

    "$COREUTILS/printf" '%s\n' \
        "local all \"$ADMIN_ROLE\" peer map=aos_slot_$slot" \
        "local \"$database\" \"$role\" $method" \
        'local all all reject' \
        'host all all 127.0.0.1/32 reject' \
        'host all all ::1/128 reject'
}

quarantine_hba_text() {
    "$COREUTILS/printf" '%s\n' \
        "local all \"$ADMIN_ROLE\" peer map=aos_slot_$slot" \
        'local all all reject' \
        'host all all 127.0.0.1/32 reject' \
        'host all all ::1/128 reject'
}

quarantine_ident_text() {
    "$COREUTILS/printf" '%s %s %s\n' \
        "aos_slot_$slot" "$probe_principal" "$ADMIN_ROLE"
}

final_ident_text() {
    "$COREUTILS/printf" '%s %s %s\n' \
        "aos_slot_$slot" "$server_principal" "$ADMIN_ROLE"
}

atomic_from_function() {
    local destination=$1
    local producer=$2
    local temporary

    temporary=$("$COREUTILS/mktemp" "$cluster_directory/.postgresql-control.XXXXXX")
    "$COREUTILS/chmod" 0600 "$temporary"
    if ! "$producer" > "$temporary"; then
        "$COREUTILS/rm" -f -- "$temporary"
        fail 'PostgreSQL candidate rendering failed'
    fi
    "$COREUTILS/sync" -d -- "$temporary"
    "$COREUTILS/mv" -T -- "$temporary" "$destination"
    "$COREUTILS/sync" -f -- "$cluster_directory"
}

validate_function_bytes() {
    local path=$1
    local producer=$2
    local actual expected

    validate_regular "$path" "$server_uid" "$server_gid" 600 262144
    actual=$($COREUTILS/sha256sum -- "$path")
    actual=${actual%% *}
    expected=$("$producer" | "$COREUTILS/sha256sum")
    expected=${expected%% *}
    [[ $actual == "$expected" ]] \
        || fail 'PostgreSQL candidate differs from canonical bytes'
}

validate_candidates() {
    validate_function_bytes "$final_config" final_config_text
    validate_function_bytes "$final_hba" final_hba_text
    validate_function_bytes "$final_ident" final_ident_text
    validate_function_bytes "$quarantine_config" quarantine_config_text
    validate_function_bytes "$quarantine_hba" quarantine_hba_text
    validate_function_bytes "$quarantine_ident" quarantine_ident_text
}

atomic_from_file() {
    local source=$1
    local destination=$2
    local temporary

    temporary=$("$COREUTILS/mktemp" "$cluster_directory/.postgresql-control.XXXXXX")
    "$COREUTILS/chmod" 0600 "$temporary"
    "$COREUTILS/cat" -- "$source" > "$temporary"
    "$COREUTILS/sync" -d -- "$temporary"
    "$COREUTILS/mv" -T -- "$temporary" "$destination"
    "$COREUTILS/sync" -f -- "$cluster_directory"
}

validate_active_set() {
    local variant=$1

    if [[ $variant == final ]]; then
        validate_function_bytes "$active_config" final_config_text
        validate_function_bytes "$active_hba" final_hba_text
        validate_function_bytes "$active_ident" final_ident_text
    else
        validate_function_bytes "$active_config" quarantine_config_text
        validate_function_bytes "$active_hba" quarantine_hba_text
        validate_function_bytes "$active_ident" quarantine_ident_text
    fi
}

validate_active_member() {
    local path=$1
    local quarantine_producer=$2
    local final_producer=$3
    local actual
    local final_digest
    local quarantine_digest

    validate_regular "$path" "$server_uid" "$server_gid" 600 262144
    actual=$("$COREUTILS/sha256sum" -- "$path")
    actual=${actual%% *}
    quarantine_digest=$("$quarantine_producer" | "$COREUTILS/sha256sum")
    quarantine_digest=${quarantine_digest%% *}
    final_digest=$("$final_producer" | "$COREUTILS/sha256sum")
    final_digest=${final_digest%% *}
    [[ $actual == "$quarantine_digest" || $actual == "$final_digest" ]] \
        || fail 'PostgreSQL active file differs from both authenticated candidates'
}

validate_active_members() {
    validate_active_member "$active_config" quarantine_config_text final_config_text
    validate_active_member "$active_hba" quarantine_hba_text final_hba_text
    validate_active_member "$active_ident" quarantine_ident_text final_ident_text
}

authenticate_quarantine_member() {
    local path=$1
    local prior_digest=$2
    local quarantine_producer=$3
    local actual_digest
    local quarantine_digest

    [[ $prior_digest == absent || $prior_digest =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail 'PostgreSQL prior active digest is invalid'
    quarantine_digest=$($quarantine_producer | "$COREUTILS/sha256sum")
    quarantine_digest="sha256:${quarantine_digest%% *}"

    if [[ ! -e $path && ! -L $path ]]; then
        [[ $prior_digest == absent ]] \
            || fail 'PostgreSQL prior active file is unexpectedly absent'
        return
    fi

    validate_regular "$path" "$server_uid" "$server_gid" 600 262144
    actual_digest=$($COREUTILS/sha256sum -- "$path")
    actual_digest="sha256:${actual_digest%% *}"
    [[ $actual_digest == "$prior_digest" || $actual_digest == "$quarantine_digest" ]] \
        || fail 'PostgreSQL active file is neither prior nor quarantine content'
}

converge_active_file() {
    local active=$1
    local final_candidate=$2
    local final_producer=$3

    local actual
    local expected

    validate_regular "$active" "$server_uid" "$server_gid" 600 262144
    actual=$("$COREUTILS/sha256sum" -- "$active")
    actual=${actual%% *}
    expected=$("$final_producer" | "$COREUTILS/sha256sum")
    expected=${expected%% *}
    if [[ $actual != "$expected" ]]; then
        atomic_from_file "$final_candidate" "$active"
    fi
    validate_function_bytes "$active" "$final_producer"
}

remove_stale_postmaster_pid() {
    "$COREUTILS/rm" -f -- "$data_directory/postmaster.pid"
    "$COREUTILS/sync" -f -- "$data_directory"
    reject_unrecorded_target_process
}

arguments_select_protected_data() {
    local -a arguments=("$@")
    local index
    local selected_data
    local saw_data_option=false
    local selects_data=false

    for ((index = 0; index < ${#arguments[@]}; index++)); do
        case ${arguments[index]} in
            -D | --pgdata | --data-directory | --data_directory)
                saw_data_option=true
                ((index + 1 < ${#arguments[@]})) || return 3
                ((index++))
                selected_data=${arguments[index]}
                ;;
            -D?*)
                saw_data_option=true
                selected_data=${arguments[index]#-D}
                ;;
            --pgdata=*)
                saw_data_option=true
                selected_data=${arguments[index]#--pgdata=}
                ;;
            --data-directory=*)
                saw_data_option=true
                selected_data=${arguments[index]#--data-directory=}
                ;;
            --data_directory=*)
                saw_data_option=true
                selected_data=${arguments[index]#--data_directory=}
                ;;
            -c)
                ((index + 1 < ${#arguments[@]})) || return 3
                ((index++))
                if [[ ${arguments[index]} != data_directory=* ]]; then
                    [[ ${arguments[index]} != data_directory* ]] || return 3
                    continue
                fi
                saw_data_option=true
                selected_data=${arguments[index]#data_directory=}
                ;;
            -cdata_directory=*)
                saw_data_option=true
                selected_data=${arguments[index]#-cdata_directory=}
                ;;
            -cdata_directory | -cdata_directory?*) return 3 ;;
            "$data_directory")
                selects_data=true
                continue
                ;;
            *) continue ;;
        esac

        [[ -n $selected_data ]] || return 3
        [[ $selected_data == "$data_directory" ]] && selects_data=true
    done

    [[ $selects_data == true ]] && return 0
    [[ $saw_data_option == true ]] && return 1
    return 2
}

environment_selects_protected_data() {
    local process_directory=$1
    local -a environment=()
    local variable

    if ! mapfile -d '' -t environment < "$process_directory/environ"; then
        [[ ! -d $process_directory ]] && return 1
        return 2
    fi
    for variable in "${environment[@]}"; do
        [[ $variable == "PGDATA=$data_directory" ]] && return 0
    done
    return 1
}

validate_target_process_stability() {
    local process_directory=$1
    local process_owner=$2
    local process_group=$3
    local session_id=$4
    local start_time=$5
    local executable=$6
    local argv_digest=$7
    local stable_owner
    local stable_stat
    local -a stable_stat_fields=()
    local stable_executable
    local stable_argv_digest

    if ! stable_owner=$("$COREUTILS/stat" -c %u -- \
        "$process_directory" 2>/dev/null) \
        || ! stable_stat=$("$COREUTILS/cat" -- \
        "$process_directory/stat" 2>/dev/null) \
        || ! stable_executable=$("$COREUTILS/readlink" -f -- \
        "$process_directory/exe" 2>/dev/null) \
        || ! stable_argv_digest=$("$COREUTILS/sha256sum" -- \
        "$process_directory/cmdline" 2>/dev/null); then
        [[ ! -d $process_directory ]] && return 1
        fail 'PostgreSQL target process changed during inspection'
    fi
    stable_stat=${stable_stat##*) }
    read -r -a stable_stat_fields <<< "$stable_stat"
    ((${#stable_stat_fields[@]} >= 20)) \
        || fail 'PostgreSQL target process changed during inspection'
    stable_argv_digest=${stable_argv_digest%% *}
    [[ $stable_owner == "$process_owner" \
        && ${stable_stat_fields[2]} == "$process_group" \
        && ${stable_stat_fields[3]} == "$session_id" \
        && ${stable_stat_fields[19]} == "$start_time" \
        && $stable_executable == "$executable" \
        && $stable_argv_digest == "$argv_digest" ]] \
        || fail 'PostgreSQL target process changed during inspection'
}

validate_target_process_confinement() {
    local process_directory=$1
    local process_owner=$2
    local status_text
    local key
    local value
    local extra
    local -a uid_fields=()
    local -a gid_fields=()
    local -a group_fields=()
    local cap_inh=
    local cap_prm=
    local cap_eff=
    local cap_bnd=
    local cap_amb=
    local no_new_privs=

    status_text=$("$COREUTILS/cat" -- \
        "$process_directory/status" 2>/dev/null) \
        || fail 'PostgreSQL target process status is unreadable'
    while read -r key value extra; do
        case $key in
            Uid:) read -r -a uid_fields <<< "$value $extra" ;;
            Gid:) read -r -a gid_fields <<< "$value $extra" ;;
            Groups:) read -r -a group_fields <<< "$value $extra" ;;
            CapInh:) cap_inh=$value ;;
            CapPrm:) cap_prm=$value ;;
            CapEff:) cap_eff=$value ;;
            CapBnd:) cap_bnd=$value ;;
            CapAmb:) cap_amb=$value ;;
            NoNewPrivs:) no_new_privs=$value ;;
        esac
    done <<< "$status_text"

    [[ $process_owner == "$server_uid" \
        && ${#uid_fields[@]} == 4 \
        && ${uid_fields[*]} == \
            "$server_uid $server_uid $server_uid $server_uid" ]] \
        || fail 'PostgreSQL target process has the wrong UID'
    [[ ${#gid_fields[@]} == 4 \
        && ${gid_fields[*]} == \
            "$server_gid $server_gid $server_gid $server_gid" \
        && ${#group_fields[@]} == 0 ]] \
        || fail 'PostgreSQL target process has the wrong groups'
    [[ $cap_inh == 0000000000000000 \
        && $cap_prm == 0000000000000000 \
        && $cap_eff == 0000000000000000 \
        && $cap_bnd == 0000000000000000 \
        && $cap_amb == 0000000000000000 \
        && $no_new_privs == 1 ]] \
        || fail 'PostgreSQL target process has invalid confinement'
}

validate_slot_process_groups() {
    local authorized_process_group=${1:-}
    local pinned_executable
    local control_stat
    local -a control_stat_fields=()
    local control_process_group
    local process_directory
    local pid
    local process_owner
    local stat_line
    local -a process_stat_fields=()
    local state
    local process_group
    local session_id
    local start_time
    local -a process_arguments=()
    local argument_selection
    local executable
    local argv_digest

    pinned_executable=$("$COREUTILS/readlink" -f -- "$POSTGRES") \
        || fail 'Pinned PostgreSQL executable is unreadable'
    control_stat=$("$COREUTILS/cat" -- "/proc/$$/stat") \
        || fail 'PostgreSQL control process stat is unreadable'
    control_stat=${control_stat##*) }
    read -r -a control_stat_fields <<< "$control_stat"
    ((${#control_stat_fields[@]} >= 3)) \
        || fail 'PostgreSQL control process stat is malformed'
    control_process_group=${control_stat_fields[2]}
    [[ $control_process_group =~ ^[1-9][0-9]{0,9}$ ]] \
        || fail 'PostgreSQL control process group is malformed'

    for process_directory in /proc/[0-9]*; do
        [[ -d $process_directory ]] || continue
        pid=${process_directory##*/}
        executable=
        if ! process_owner=$("$COREUTILS/stat" -c %u -- "$process_directory" 2>/dev/null); then
            [[ ! -d $process_directory ]] || fail 'PostgreSQL process scan is unreadable'
            continue
        fi
        if ! stat_line=$("$COREUTILS/cat" -- "$process_directory/stat" 2>/dev/null); then
            [[ ! -d $process_directory ]] \
                || fail 'PostgreSQL process scan stat is unreadable'
            continue
        fi
        stat_line=${stat_line##*) }
        read -r -a process_stat_fields <<< "$stat_line"
        ((${#process_stat_fields[@]} >= 20)) \
            || fail 'PostgreSQL process scan stat is malformed'
        state=${process_stat_fields[0]}
        process_group=${process_stat_fields[2]}
        session_id=${process_stat_fields[3]}
        start_time=${process_stat_fields[19]}
        [[ $state == Z ]] && continue

        process_arguments=()
        if ! mapfile -d '' -t process_arguments < "$process_directory/cmdline"; then
            [[ ! -d $process_directory ]] && continue
            fail 'PostgreSQL process scan arguments are unreadable'
        fi
        if ((${#process_arguments[@]} > 0)); then
            if arguments_select_protected_data "${process_arguments[@]}"; then
                argument_selection=0
            else
                argument_selection=$?
            fi
        else
            argument_selection=2
        fi
        if [[ $argument_selection == 3 \
            && ${process_arguments[0]:-} != "$POSTGRES" \
            && ${process_arguments[0]:-} != "$pinned_executable" ]]; then
            # Generic programs also use options such as `-D` and `-c`. A
            # malformed-selector finding becomes authoritative only when the
            # process names the pinned PostgreSQL executable as argv[0].
            argument_selection=2
        fi

        if [[ $argument_selection == 0 || $argument_selection == 3 ]]; then
            if ! executable=$("$COREUTILS/readlink" -f -- \
                "$process_directory/exe" 2>/dev/null); then
                [[ ! -d $process_directory ]] && continue
                fail 'PostgreSQL target process executable is unreadable'
            fi
            if [[ $executable == "$pinned_executable" ]]; then
                [[ $argument_selection != 3 ]] \
                    || fail 'PostgreSQL target process data arguments are malformed'
                argv_digest=$("$COREUTILS/printf" '%s\0' \
                    "${process_arguments[@]}" | "$COREUTILS/sha256sum")
                argv_digest=${argv_digest%% *}

                validate_target_process_stability \
                    "$process_directory" "$process_owner" \
                    "$process_group" "$session_id" "$start_time" \
                    "$executable" "$argv_digest" \
                    || continue
                validate_target_process_confinement \
                    "$process_directory" "$process_owner"
                [[ -n $authorized_process_group \
                    && $pid == "$authorized_process_group" \
                    && $process_group == "$pid" \
                    && $session_id == "$pid" ]] \
                    || fail 'PostgreSQL target process has no exact process authority'
            fi
        fi

        [[ $process_owner == "$server_uid" ]] || continue
        if [[ -z $executable ]]; then
            if ! executable=$("$COREUTILS/readlink" -f -- \
                "$process_directory/exe" 2>/dev/null); then
                [[ ! -d $process_directory ]] && continue
                fail 'PostgreSQL slot process executable is unreadable'
            fi
        fi
        [[ $process_group == "$control_process_group" ]] && continue
        [[ $executable == "$pinned_executable" ]] \
            || fail 'PostgreSQL slot principal runs an unauthenticated executable'
        if [[ -n $authorized_process_group \
            && $process_group == "$authorized_process_group" \
            && $session_id == "$authorized_process_group" ]]; then
            continue
        fi

        # Coreutils children share the control process group. Every other
        # process under the dedicated slot UID must belong to the authenticated
        # postmaster group.
        fail 'PostgreSQL slot has an unauthorized live process group'
    done
}

reject_unrecorded_target_process() {
    validate_slot_process_groups
}

process_identity_filter() {
    "$COREUTILS/cat" <<'JQ'
{
    schema: $schema,
    boot_id: $boot_id,
    pid: $pid,
    process_group: $process_group,
    start_time: $start_time,
    executable: $executable,
    arguments: [
        $executable,
        "-D",
        $data_directory,
        "-c",
        ("config_file=" + $active_config)
    ],
    uid: $uid,
    gid: $gid,
    groups: [],
    no_new_privileges: true,
    capabilities: {
        inheritable: $zero,
        permitted: $zero,
        effective: $zero,
        bounding: $zero,
        ambient: $zero
    }
}
JQ
}

reconcile_postmaster_pid() {
    local pidfile="$data_directory/postmaster.pid"
    local pidfile_present=false
    local pid
    local recorded_epoch
    local stat_line
    local -a pidfile_lines=()
    local -a stat_fields=()
    local state
    local process_group
    local session_id
    local start_ticks
    local boot_id
    local status_text
    local key
    local value
    local extra
    local -a uid_fields=()
    local -a gid_fields=()
    local -a group_fields=()
    local cap_inh=
    local cap_prm=
    local cap_eff=
    local cap_bnd=
    local cap_amb=
    local no_new_privs=
    local executable
    local stable_executable
    local stable_stat_line
    local -a stable_stat_fields=()
    local stable_start_time
    local stable_argv_digest
    local -a process_arguments=()
    local actual_argv_digest
    local expected_argv_digest
    local argument_selection
    local environment_selection
    local identity_matches=false
    local leader_identity_matches=false
    local confinement_matches=false
    local exact_argv_matches=false
    local targets_data_directory=false

    if [[ -e $pidfile || -L $pidfile ]]; then
        pidfile_present=true
        validate_regular "$pidfile" "$server_uid" "$server_gid" 600 4096
        mapfile -t pidfile_lines < "$pidfile"
        ((${#pidfile_lines[@]} >= 3)) \
            || fail 'PostgreSQL postmaster PID file is truncated'
        pid=${pidfile_lines[0]}
        recorded_epoch=${pidfile_lines[2]}
        [[ $pid =~ ^[1-9][0-9]{0,9}$ && $recorded_epoch =~ ^[0-9]{1,18}$ ]] \
            || fail 'PostgreSQL postmaster PID identity is malformed'
        ((pid <= 4194304)) \
            || fail 'PostgreSQL postmaster PID is outside the Linux bound'
    else
        reject_unrecorded_target_process
        return
    fi

    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id \
        || fail 'Linux boot identity is unreadable'
    [[ $boot_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || fail 'Linux boot identity is malformed'

    if [[ ! -d /proc/$pid ]]; then
        [[ $pidfile_present == false ]] || remove_stale_postmaster_pid
        return
    fi
    if ! stat_line=$("$COREUTILS/cat" -- "/proc/$pid/stat" 2>/dev/null); then
        if [[ -d /proc/$pid ]]; then
            fail 'PostgreSQL live process stat is unreadable'
        fi
        [[ $pidfile_present == false ]] || remove_stale_postmaster_pid
        return
    fi
    stat_line=${stat_line##*) }
    read -r -a stat_fields <<< "$stat_line"
    ((${#stat_fields[@]} >= 20)) \
        || fail 'PostgreSQL live process stat is malformed'
    state=${stat_fields[0]}
    process_group=${stat_fields[2]}
    session_id=${stat_fields[3]}
    start_ticks=${stat_fields[19]}
    [[ $process_group =~ ^[1-9][0-9]{0,9}$ \
        && $session_id =~ ^[1-9][0-9]{0,9}$ \
        && $start_ticks =~ ^[0-9]{1,18}$ ]] \
        || fail 'PostgreSQL live process identity is malformed'
    if [[ $process_group == "$pid" && $session_id == "$pid" ]]; then
        leader_identity_matches=true
    fi
    if [[ $expected_process_absent == false \
        && $boot_id == "$expected_boot_id" \
        && $pid == "$expected_pid" \
        && $process_group == "$expected_process_group" \
        && $start_ticks == "$expected_start_time" ]]; then
        identity_matches=true
    fi

    if [[ $state == Z ]]; then
        [[ $pidfile_present == false ]] || remove_stale_postmaster_pid
        return
    fi

    if ! status_text=$("$COREUTILS/cat" -- "/proc/$pid/status" 2>/dev/null) \
        || ! executable=$("$COREUTILS/readlink" -- "/proc/$pid/exe" 2>/dev/null); then
        if [[ -d /proc/$pid ]]; then
            fail 'PostgreSQL live process identity is unreadable'
        fi
        [[ $pidfile_present == false ]] || remove_stale_postmaster_pid
        return
    fi
    while read -r key value extra; do
        case $key in
            Uid:) read -r -a uid_fields <<< "$value $extra" ;;
            Gid:) read -r -a gid_fields <<< "$value $extra" ;;
            Groups:) read -r -a group_fields <<< "$value $extra" ;;
            CapInh:) cap_inh=$value ;;
            CapPrm:) cap_prm=$value ;;
            CapEff:) cap_eff=$value ;;
            CapBnd:) cap_bnd=$value ;;
            CapAmb:) cap_amb=$value ;;
            NoNewPrivs:) no_new_privs=$value ;;
        esac
    done <<< "$status_text"
    if [[ ${#uid_fields[@]} == 4 \
        && ${uid_fields[*]} == "$server_uid $server_uid $server_uid $server_uid" \
        && ${#gid_fields[@]} == 4 \
        && ${gid_fields[*]} == "$server_gid $server_gid $server_gid $server_gid" \
        && ${#group_fields[@]} == 0 \
        && $cap_inh == 0000000000000000 \
        && $cap_prm == 0000000000000000 \
        && $cap_eff == 0000000000000000 \
        && $cap_bnd == 0000000000000000 \
        && $cap_amb == 0000000000000000 \
        && $no_new_privs == 1 \
        && $executable == "$POSTGRES" ]]; then
        confinement_matches=true
    fi

    if ! mapfile -d '' -t process_arguments < "/proc/$pid/cmdline"; then
        if [[ -d /proc/$pid ]]; then
            fail 'PostgreSQL live process arguments are unreadable'
        fi
        [[ $pidfile_present == false ]] || remove_stale_postmaster_pid
        return
    fi
    ((${#process_arguments[@]} > 0)) \
        || fail 'PostgreSQL live process arguments are empty'
    actual_argv_digest=$("$COREUTILS/printf" '%s\0' "${process_arguments[@]}" \
        | "$COREUTILS/sha256sum")
    actual_argv_digest=${actual_argv_digest%% *}
    expected_argv_digest=$("$COREUTILS/printf" '%s\0' \
        "$POSTGRES" -D "$data_directory" -c "config_file=$active_config" \
        | "$COREUTILS/sha256sum")
    expected_argv_digest=${expected_argv_digest%% *}
    if [[ $executable == "$POSTGRES" \
        && $actual_argv_digest == "$expected_argv_digest" ]]; then
        exact_argv_matches=true
    fi

    if [[ $executable == "$POSTGRES" ]]; then
        if arguments_select_protected_data "${process_arguments[@]}"; then
            targets_data_directory=true
        else
            argument_selection=$?
            case $argument_selection in
                1 | 2) ;;
                *) fail 'PostgreSQL live process data arguments are malformed' ;;
            esac
        fi
        if environment_selects_protected_data "/proc/$pid"; then
            targets_data_directory=true
        else
            environment_selection=$?
            [[ $environment_selection == 1 ]] \
                || fail 'PostgreSQL live process environment is unreadable'
        fi
    fi

    if ! stable_stat_line=$("$COREUTILS/cat" -- "/proc/$pid/stat" 2>/dev/null) \
        || ! stable_executable=$("$COREUTILS/readlink" -- "/proc/$pid/exe" 2>/dev/null) \
        || ! stable_argv_digest=$("$COREUTILS/sha256sum" -- "/proc/$pid/cmdline" 2>/dev/null); then
        [[ ! -d /proc/$pid ]] || fail 'PostgreSQL live process changed during inspection'
        remove_stale_postmaster_pid
        return
    fi
    stable_stat_line=${stable_stat_line##*) }
    read -r -a stable_stat_fields <<< "$stable_stat_line"
    ((${#stable_stat_fields[@]} >= 20)) \
        || fail 'PostgreSQL live process changed during inspection'
    stable_start_time=${stable_stat_fields[19]}
    stable_argv_digest=${stable_argv_digest%% *}
    [[ $stable_start_time == "$start_ticks" \
        && $stable_executable == "$executable" \
        && $stable_argv_digest == "$actual_argv_digest" ]] \
        || fail 'PostgreSQL live process changed during inspection'

    if [[ $exact_argv_matches == true ]]; then
        targets_data_directory=true
    fi
    if [[ $executable == "$POSTGRES" \
        && $exact_argv_matches == false \
        && ( $targets_data_directory == true \
            || ${uid_fields[1]:-} == "$server_uid" ) ]]; then
        fail 'PostgreSQL slot process has unauthorized arguments'
    fi

    if [[ $identity_matches == true ]]; then
        [[ $targets_data_directory == true \
            && $exact_argv_matches == true \
            && $leader_identity_matches == true \
            && $confinement_matches == true ]] \
            || fail 'PostgreSQL authorized process lost its exact identity'
        validate_slot_process_groups "$process_group"
        return
    fi
    if [[ $targets_data_directory == true ]]; then
        [[ $exact_argv_matches == true ]] \
            || fail 'PostgreSQL target process has unauthorized arguments'
        [[ $leader_identity_matches == true ]] \
            || fail 'PostgreSQL target process is not its process-group and session leader'
        [[ $confinement_matches == true ]] \
            || fail 'PostgreSQL target process has invalid confinement'
        [[ $mode == quarantine-start || $mode == start-final ]] \
            || fail 'PostgreSQL exact process has no matching process authority'
        validate_slot_process_groups "$process_group"
        return
    fi

    # Readable evidence proves this PID does not target the data directory.
    # Only PostgreSQL's stale file is removed; the foreign process is untouched.
    remove_stale_postmaster_pid
}

process_identity_json() {
    local pid
    local stat_line
    local -a stat_fields=()
    local process_group
    local session_id
    local start_time
    local boot_id

    reconcile_postmaster_pid
    "$PG_CTL" -D "$data_directory" status >/dev/null 2>&1 \
        || fail 'PostgreSQL process is not running'
    IFS= read -r pid < "$data_directory/postmaster.pid" \
        || fail 'PostgreSQL postmaster PID is absent'
    stat_line=$("$COREUTILS/cat" -- "/proc/$pid/stat") \
        || fail 'PostgreSQL process stat is unreadable'
    stat_line=${stat_line##*) }
    read -r -a stat_fields <<< "$stat_line"
    ((${#stat_fields[@]} >= 20)) \
        || fail 'PostgreSQL process stat is malformed'
    process_group=${stat_fields[2]}
    session_id=${stat_fields[3]}
    start_time=${stat_fields[19]}
    [[ $process_group =~ ^[1-9][0-9]{0,9}$ \
        && $session_id =~ ^[1-9][0-9]{0,9}$ \
        && $start_time =~ ^[0-9]{1,18}$ ]] \
        || fail 'PostgreSQL process identity is malformed'
    [[ $process_group == "$pid" && $session_id == "$pid" ]] \
        || fail 'PostgreSQL process is not its process-group and session leader'
    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id \
        || fail 'Linux boot identity is unreadable'
    [[ $boot_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || fail 'Linux boot identity is malformed'

    "$JQ" -cSn \
        --arg schema 'aos.postgresql.control-process/v1' \
        --arg boot_id "$boot_id" \
        --arg executable "$POSTGRES" \
        --arg data_directory "$data_directory" \
        --arg active_config "$active_config" \
        --arg zero 0000000000000000 \
        --argjson pid "$pid" \
        --argjson process_group "$process_group" \
        --argjson start_time "$start_time" \
        --argjson uid "$server_uid" \
        --argjson gid "$server_gid" \
        "$(process_identity_filter)"
}

is_running() {
    reconcile_postmaster_pid
    "$PG_CTL" -D "$data_directory" status >/dev/null 2>&1
}

stop_server() {
    if is_running; then
        "$PG_CTL" -D "$data_directory" -m fast -w stop >/dev/null
    fi
}

start_server() {
    is_running && fail 'PostgreSQL is already running'
    "$PG_CTL" \
        -D "$data_directory" \
        -l "$server_log" \
        -w start \
        -o "-c config_file=$active_config" \
        >/dev/null
}

postgresql_data_is_complete() {
    local selected_data_directory=$1
    local control_data
    local field
    local pg_version
    local server_major
    local server_version
    local value

    validate_directory "$selected_data_directory" "$server_uid" "$server_gid" 700
    if [[ ! -f $selected_data_directory/PG_VERSION ]]; then
        return 1
    fi
    validate_regular "$selected_data_directory/PG_VERSION" "$server_uid" "$server_gid" 600 32
    IFS= read -r pg_version < "$selected_data_directory/PG_VERSION" \
        || return 1
    [[ $pg_version =~ ^[0-9]{1,3}$ ]] \
        || fail 'PostgreSQL data version is invalid'

    server_version=$("$PG_CONFIG" --version)
    server_major=${server_version#PostgreSQL }
    server_major=${server_major%%.*}
    [[ $pg_version == "$server_major" ]] \
        || fail 'PostgreSQL data has an incompatible server major'

    data_system_identifier=
    if ! control_data=$("$PG_CONTROLDATA" "$selected_data_directory" 2>/dev/null); then
        return 1
    fi
    while IFS=: read -r field value; do
        if [[ $field == 'Database system identifier' ]]; then
            data_system_identifier=${value#"${value%%[![:space:]]*}"}
            break
        fi
    done <<< "$control_data"
    [[ $data_system_identifier =~ ^[0-9]{1,32}$ ]] || return 1

    postgresql_major=$server_major
    observed_pg_version=$pg_version
    return 0
}

validate_postgresql_data() {
    postgresql_data_is_complete "$data_directory" \
        || fail 'PostgreSQL data directory is incomplete'
}

run_initdb() {
    local initdb_pid

    crash_at crash-initdb-before-pg-version
    "$INITDB" \
        --pgdata="$staging_data" \
        --username="$ADMIN_ROLE" \
        --auth-host=reject \
        --auth-local=reject \
        --encoding=UTF8 \
        --no-locale \
        >/dev/null &
    initdb_pid=$!

    if [[ $FAULT_POINT == crash-initdb-after-pg-version ]]; then
        while kill -0 "$initdb_pid" 2>/dev/null; do
            if [[ -f $staging_data/PG_VERSION ]]; then
                crash_at crash-initdb-after-pg-version "$initdb_pid"
            fi
            "$COREUTILS/sleep" 0.01
        done
    fi
    wait "$initdb_pid"
    crash_at crash-initdb-after-pg-version
}
