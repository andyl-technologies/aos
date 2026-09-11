#!@bash@/bin/bash
# Signed, permanently unprivileged PostgreSQL lifecycle control.

set -euo pipefail
umask 077

COREUTILS=@coreutils@/bin
JQ=@jq@/bin/jq
POSTGRESQL=@postgresql@

INITDB="$POSTGRESQL/bin/initdb"
PG_CONFIG="$POSTGRESQL/bin/pg_config"
PG_CONTROLDATA="$POSTGRESQL/bin/pg_controldata"
PG_CTL="$POSTGRESQL/bin/pg_ctl"
POSTGRES="$POSTGRESQL/bin/postgres"
PSQL="$POSTGRESQL/bin/psql"

POSTGRESQL_ROOT=/var/lib/aos/ability-runtime/postgresql
STORAGE_ROOT=/var/lib/aos/ability-runtime/storage
SOCKET_ROOT=/run/aos-ability-postgresql
REVISION_GUC=aos.configuration_revision
ADMIN_ROLE=aos-ability-postgresql
MAX_SECRET_BYTES=65536
FAULT_POINT='@faultPoint@'

usage() {
    "$COREUTILS/printf" '%s\n' \
        'usage: postgresql-control MODE --slot NN --postgresql-artifact STORE [mode arguments]' \
        >&2
    exit 64
}

fail() {
    "$COREUTILS/printf" '%s\n' "$1" >&2
    exit 65
}

crash_at() {
    local requested_point=$1
    local child_pid=${2:-}
    local marker="$cluster_directory/.fault-fired-$FAULT_POINT"

    [[ $FAULT_POINT == "$requested_point" ]] || return
    if [[ -e $marker || -L $marker ]]; then
        validate_function_bytes "$marker" fault_marker_text
        return
    fi

    # Persist the cut before terminating so the same retained signed artifact
    # can resume the interrupted transaction without firing indefinitely.
    atomic_from_function "$marker" fault_marker_text
    validate_function_bytes "$marker" fault_marker_text
    if [[ -n $child_pid ]]; then
        kill -KILL "$child_pid" "$$"
    else
        kill -KILL "$$"
    fi
}

fault_marker_text() {
    "$COREUTILS/printf" '%s|%s|%s\n' \
        "$FAULT_POINT" "$POSTGRESQL" "$configuration_revision"
}

hold_at() {
    local requested_point=$1
    local release=/run/aos-postgresql-quarantine-hold-release
    local fields

    [[ $FAULT_POINT == "$requested_point" ]] || return
    while [[ ! -e $release && ! -L $release ]]; do
        "$COREUTILS/sleep" 0.05
    done
    fields=$("$COREUTILS/stat" -c '%F|%u|%g|%a|%h|%s' -- "$release")
    [[ $fields == 'regular empty file|0|0|600|1|0' ]] \
        || fail 'PostgreSQL quarantine hold release is not protected'
}

assign_once() {
    local name=$1
    local value=$2

    if [[ -n ${!name:-} ]]; then
        usage
    fi
    printf -v "$name" '%s' "$value"
}

require_argument() {
    [[ -n ${!1:-} ]] || usage
}

reject_argument() {
    [[ -z ${!1:-} ]] || usage
}

[[ $# -ge 1 ]] || usage
mode=$1
shift

slot=
postgresql_artifact=
data_directory=
cluster_directory=
run_directory=
port=
configuration_revision=
database=
role=
auth=
address=
prior_config_digest=
prior_hba_digest=
prior_ident_digest=
expected_boot_id=
expected_pid=
expected_process_group=
expected_start_time=

while [[ $# -gt 0 ]]; do
    [[ $# -ge 2 ]] || usage
    case $1 in
        --slot) assign_once slot "$2" ;;
        --postgresql-artifact) assign_once postgresql_artifact "$2" ;;
        --data-directory) assign_once data_directory "$2" ;;
        --cluster-directory) assign_once cluster_directory "$2" ;;
        --run-directory) assign_once run_directory "$2" ;;
        --port) assign_once port "$2" ;;
        --configuration-revision) assign_once configuration_revision "$2" ;;
        --database) assign_once database "$2" ;;
        --role) assign_once role "$2" ;;
        --auth) assign_once auth "$2" ;;
        --address) assign_once address "$2" ;;
        --prior-config-digest) assign_once prior_config_digest "$2" ;;
        --prior-hba-digest) assign_once prior_hba_digest "$2" ;;
        --prior-ident-digest) assign_once prior_ident_digest "$2" ;;
        --expected-boot-id) assign_once expected_boot_id "$2" ;;
        --expected-pid) assign_once expected_pid "$2" ;;
        --expected-process-group) assign_once expected_process_group "$2" ;;
        --expected-start-time) assign_once expected_start_time "$2" ;;
        *) usage ;;
    esac
    shift 2
done

case $mode in
    prepare)
        for name in postgresql_artifact data_directory cluster_directory run_directory \
            port configuration_revision database role auth expected_boot_id \
            expected_pid expected_process_group expected_start_time; do
            require_argument "$name"
        done
        reject_argument address
        ;;
    authenticate-active | authenticate-stop)
        for name in postgresql_artifact data_directory cluster_directory run_directory \
            port configuration_revision database role auth expected_boot_id \
            expected_pid expected_process_group expected_start_time; do
            require_argument "$name"
        done
        reject_argument address
        ;;
    quarantine-start)
        for name in postgresql_artifact data_directory cluster_directory run_directory \
            port configuration_revision database role auth prior_config_digest \
            prior_hba_digest prior_ident_digest expected_boot_id expected_pid \
            expected_process_group expected_start_time; do
            require_argument "$name"
        done
        reject_argument address
        ;;
    publish-final | start-final | stop)
        for name in postgresql_artifact data_directory cluster_directory run_directory \
            port configuration_revision database role auth expected_boot_id \
            expected_pid expected_process_group expected_start_time; do
            require_argument "$name"
        done
        for name in address prior_config_digest prior_hba_digest prior_ident_digest; do
            reject_argument "$name"
        done
        ;;
    repair)
        for name in postgresql_artifact run_directory port configuration_revision \
            database role auth; do
            require_argument "$name"
        done
        for name in data_directory cluster_directory address expected_boot_id \
            expected_pid expected_process_group expected_start_time; do
            reject_argument "$name"
        done
        ;;
    observe)
        for name in postgresql_artifact address port database role \
            configuration_revision auth; do
            require_argument "$name"
        done
        for name in data_directory cluster_directory run_directory expected_boot_id \
            expected_pid expected_process_group expected_start_time; do
            reject_argument "$name"
        done
        ;;
    *) usage ;;
esac
require_argument slot

if [[ $mode != quarantine-start ]]; then
    for name in prior_config_digest prior_hba_digest prior_ident_digest; do
        reject_argument "$name"
    done
fi

if [[ -n $data_directory ]]; then
    expected_process_values=(
        "$expected_boot_id"
        "$expected_pid"
        "$expected_process_group"
        "$expected_start_time"
    )
    if [[ ${expected_process_values[*]} == 'absent absent absent absent' ]]; then
        expected_process_absent=true
    else
        expected_process_absent=false
        [[ $expected_boot_id =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ \
            && $expected_pid =~ ^[1-9][0-9]{0,9}$ \
            && $expected_process_group =~ ^[1-9][0-9]{0,9}$ \
            && $expected_start_time =~ ^[0-9]{1,18}$ ]] \
            || usage
    fi
fi

[[ $slot =~ ^(0[0-9]|[1-5][0-9]|6[0-3])$ ]] || usage
slot_number=$((10#$slot))
server_uid=$((7100 + slot_number))
server_gid=71
server_principal="aos-ability-pg-$slot"
probe_uid=$((7200 + slot_number))
probe_gid=$probe_uid
probe_principal="aos-ability-pg-probe-$slot"
expected_run_directory="$SOCKET_ROOT/$slot"

case $mode in
    repair | observe)
        expected_uid=$probe_uid
        expected_gid=$probe_gid
        ;;
    *)
        expected_uid=$server_uid
        expected_gid=$server_gid
        ;;
esac

[[ $("$COREUTILS/id" -u) == "$expected_uid" \
    && $("$COREUTILS/id" -g) == "$expected_gid" \
    && $("$COREUTILS/id" -G) == "$expected_gid" ]] \
    || fail 'postgresql-control has the wrong permanent identity'
((expected_uid != 0 && expected_gid != 0)) \
    || fail 'postgresql-control refuses a privileged identity'

validate_process_boundary() {
    local key
    local value
    local cap_inh=
    local cap_prm=
    local cap_eff=
    local cap_bnd=
    local cap_amb=
    local no_new_privs=

    while read -r key value _; do
        case $key in
            CapInh:) cap_inh=$value ;;
            CapPrm:) cap_prm=$value ;;
            CapEff:) cap_eff=$value ;;
            CapBnd:) cap_bnd=$value ;;
            CapAmb:) cap_amb=$value ;;
            NoNewPrivs:) no_new_privs=$value ;;
        esac
    done < /proc/self/status

    [[ $cap_inh == 0000000000000000 \
        && $cap_prm == 0000000000000000 \
        && $cap_eff == 0000000000000000 \
        && $cap_bnd == 0000000000000000 \
        && $cap_amb == 0000000000000000 \
        && $no_new_privs == 1 ]] \
        || fail 'postgresql-control privilege boundary is incomplete'
}

validate_process_boundary
[[ $postgresql_artifact == "$POSTGRESQL" ]] \
    || fail 'postgresql-control received another PostgreSQL artifact'

validate_common_value() {
    [[ $database =~ ^[A-Za-z0-9._-]{1,63}$ \
        && $database != postgres \
        && $database != template0 \
        && $database != template1 ]] \
        || usage
    [[ $role =~ ^[A-Za-z0-9._-]{1,63}$ \
        && $role != aos-ability-postgresql \
        && $role != aos-ability-pg-* ]] \
        || usage
}

if [[ -n $database || -n $role ]]; then
    validate_common_value
fi
if [[ -n $auth ]]; then
    [[ $auth == scram || $auth == trust ]] || usage
fi
if [[ -n $configuration_revision ]]; then
    [[ $configuration_revision =~ ^sha256:[0-9a-f]{64}$ ]] || usage
fi
if [[ -n $port ]]; then
    [[ $port =~ ^[0-9]{4,5}$ ]] || usage
    ((10#$port >= 1024 && 10#$port <= 65535)) || usage
fi
if [[ -n $address ]]; then
    [[ $address == 127.0.0.1 ]] || usage
fi
if [[ -n $run_directory ]]; then
    [[ $run_directory == "$expected_run_directory" ]] \
        || fail 'PostgreSQL socket path differs from the selected slot'
fi

. @stateHelpers@
. @sqlHelpers@

case $mode in
    prepare)
        storage_directory=${data_directory%/data}
        staging_data="$storage_directory/.postgresql-data-staging-$slot"
        if [[ -e $data_directory || -L $data_directory ]]; then
            validate_postgresql_data
        elif [[ -e $staging_data || -L $staging_data ]]; then
            validate_directory "$staging_data" "$server_uid" "$server_gid" 700
            if postgresql_data_is_complete "$staging_data"; then
                "$COREUTILS/sync" -f -- "$staging_data"
                "$COREUTILS/mv" -T -- "$staging_data" "$data_directory"
                "$COREUTILS/sync" -f -- "$storage_directory"
            else
                "$COREUTILS/rm" -rf -- "$staging_data"
                "$COREUTILS/sync" -f -- "$storage_directory"
            fi
        fi

        if [[ ! -e $data_directory ]]; then
            "$COREUTILS/mkdir" -m 0700 -- "$staging_data"
            run_initdb
            postgresql_data_is_complete "$staging_data" \
                || fail 'PostgreSQL staged data directory is incomplete'
            "$COREUTILS/sync" -f -- "$staging_data"
            "$COREUTILS/mv" -T -- "$staging_data" "$data_directory"
            "$COREUTILS/sync" -f -- "$storage_directory"
        fi
        validate_postgresql_data

        atomic_from_function "$final_config" final_config_text
        atomic_from_function "$final_hba" final_hba_text
        atomic_from_function "$final_ident" final_ident_text
        atomic_from_function "$quarantine_config" quarantine_config_text
        atomic_from_function "$quarantine_hba" quarantine_hba_text
        atomic_from_function "$quarantine_ident" quarantine_ident_text
        validate_candidates

        observed_revision=$("$POSTGRES" \
            -D "$data_directory" \
            -C "$REVISION_GUC" \
            -c "config_file=$final_config")
        [[ $observed_revision == "$configuration_revision" ]] \
            || fail 'PostgreSQL candidate revision is invalid'
        ;;
    authenticate-active)
        validate_postgresql_data
        validate_active_set final
        query_admin_observation 'aos.postgresql.control-authenticate-active/v1'
        ;;
    authenticate-stop)
        validate_postgresql_data
        validate_active_set final
        if is_running; then
            output=$(query_stop_observation)
            stop_server
            "$COREUTILS/printf" '%s\n' "$output"
        else
            "$JQ" -cSn \
                '{schema: "aos.postgresql.control-authenticate-stopped/v1", running: false}'
        fi
        ;;
    quarantine-start)
        validate_postgresql_data
        validate_candidates
        if is_running; then
            validate_active_set quarantine
        else
            authenticate_quarantine_member \
                "$active_config" "$prior_config_digest" quarantine_config_text
            authenticate_quarantine_member \
                "$active_hba" "$prior_hba_digest" quarantine_hba_text
            authenticate_quarantine_member \
                "$active_ident" "$prior_ident_digest" quarantine_ident_text
            atomic_from_file "$quarantine_config" "$active_config"
            crash_at crash-quarantine-config
            atomic_from_file "$quarantine_hba" "$active_hba"
            crash_at crash-quarantine-hba
            atomic_from_file "$quarantine_ident" "$active_ident"
            crash_at crash-quarantine-ident
            validate_active_set quarantine
            start_server
        fi
        hold_at hold-quarantine-after-start
        process_identity_json
        ;;
    repair)
        read_secret
        repair_role_and_database
        ;;
    stop)
        validate_postgresql_data
        validate_active_set quarantine
        stop_server
        ;;
    publish-final)
        validate_postgresql_data
        validate_candidates
        is_running && fail 'PostgreSQL must stop before final publication'
        validate_active_members
        converge_active_file "$active_config" "$final_config" final_config_text
        crash_at crash-publish-final-config
        converge_active_file "$active_hba" "$final_hba" final_hba_text
        crash_at crash-publish-final-hba
        converge_active_file "$active_ident" "$final_ident" final_ident_text
        crash_at crash-publish-final-ident
        validate_active_set final
        ;;
    start-final)
        validate_postgresql_data
        validate_candidates
        validate_active_set final
        if ! is_running; then
            start_server
        fi
        process_identity_json
        ;;
    observe)
        read_secret
        observe_application
        ;;
esac
