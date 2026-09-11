# Quarantine repair and closed PostgreSQL observation proofs.
admin_observation_sql() {
    "$COREUTILS/cat" <<SQL
SELECT
    current_setting('$REVISION_GUC'),
    current_user,
    application_role.rolname,
    application_role.rolcanlogin,
    application_role.rolinherit,
    application_role.rolsuper,
    application_role.rolcreatedb,
    application_role.rolcreaterole,
    application_role.rolreplication,
    application_role.rolbypassrls,
    owner_role.rolname,
    application_role.rolpassword,
    (
        SELECT count(*)
        FROM pg_auth_members
        WHERE member = application_role.oid OR roleid = application_role.oid
    )
FROM pg_authid AS application_role
JOIN pg_database AS application_database
    ON application_database.datname = '$database'
JOIN pg_roles AS owner_role
    ON owner_role.oid = application_database.datdba
WHERE application_role.rolname = '$role'
SQL
}

stop_observation_sql() {
    "$COREUTILS/cat" <<SQL
SELECT
    current_setting('$REVISION_GUC'),
    current_user,
    EXISTS (SELECT 1 FROM pg_authid WHERE rolname = '$role'),
    EXISTS (SELECT 1 FROM pg_database WHERE datname = '$database'),
    COALESCE((SELECT rolcanlogin::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolinherit::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolsuper::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolcreatedb::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolcreaterole::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolreplication::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((SELECT rolbypassrls::text FROM pg_authid WHERE rolname = '$role'), ''),
    COALESCE((
        SELECT owner_role.rolname
        FROM pg_database AS application_database
        JOIN pg_roles AS owner_role
            ON owner_role.oid = application_database.datdba
        WHERE application_database.datname = '$database'
    ), ''),
    COALESCE((SELECT rolpassword FROM pg_authid WHERE rolname = '$role'), ''),
    (
        SELECT count(*)
        FROM pg_auth_members AS membership
        JOIN pg_roles AS application_role
            ON application_role.oid = membership.member
            OR application_role.oid = membership.roleid
        WHERE application_role.rolname = '$role'
    )
SQL
}

application_observation_sql() {
    "$COREUTILS/cat" <<SQL
SELECT
    current_setting('$REVISION_GUC'),
    current_user,
    application_role.rolname,
    application_role.rolcanlogin,
    application_role.rolinherit,
    application_role.rolsuper,
    application_role.rolcreatedb,
    application_role.rolcreaterole,
    application_role.rolreplication,
    application_role.rolbypassrls,
    owner_role.rolname,
    (
        SELECT count(*)
        FROM pg_auth_members
        WHERE member = application_role.oid OR roleid = application_role.oid
    )
FROM pg_roles AS application_role
JOIN pg_database AS application_database
    ON application_database.datname = '$database'
JOIN pg_roles AS owner_role
    ON owner_role.oid = application_database.datdba
WHERE application_role.rolname = '$role'
SQL
}

revoke_parent_memberships_sql() {
    "$COREUTILS/cat" <<SQL
SELECT format('REVOKE %I FROM %I;', parent.rolname, member_role.rolname)
FROM pg_auth_members AS membership
JOIN pg_roles AS parent ON parent.oid = membership.roleid
JOIN pg_roles AS member_role ON member_role.oid = membership.member
WHERE member_role.rolname = '$role'
SQL
}

revoke_member_grants_sql() {
    "$COREUTILS/cat" <<SQL
SELECT format('REVOKE %I FROM %I;', parent.rolname, member_role.rolname)
FROM pg_auth_members AS membership
JOIN pg_roles AS parent ON parent.oid = membership.roleid
JOIN pg_roles AS member_role ON member_role.oid = membership.member
WHERE parent.rolname = '$role'
SQL
}

admin_observation_filter() {
    "$COREUTILS/cat" <<'JQ'
{
    schema: $schema,
    configuration_revision: $configuration_revision,
    current_user: $current_user,
    role: $role,
    login: true,
    inherit: false,
    superuser: false,
    createdb: false,
    createrole: false,
    replication: false,
    bypassrls: false,
    memberships: 0,
    database_owner: $database_owner,
    role_verifier_digest: $role_verifier_digest,
    postgresql_major: $postgresql_major,
    pg_version: $pg_version,
    data_system_identifier: $data_system_identifier,
    postgres_executable: $postgres_executable,
    process: $process
}
JQ
}

stop_observation_filter() {
    "$COREUTILS/cat" <<'JQ'
{
    schema: $schema,
    configuration_revision: $configuration_revision,
    current_user: $current_user,
    requested_role: $requested_role,
    requested_database: $requested_database,
    role_exists: ($role_exists == "t"),
    database_exists: ($database_exists == "t"),
    login: (if $login == "" then null else $login == "t" end),
    inherit: (if $inherit == "" then null else $inherit == "t" end),
    superuser: (if $superuser == "" then null else $superuser == "t" end),
    createdb: (if $createdb == "" then null else $createdb == "t" end),
    createrole: (if $createrole == "" then null else $createrole == "t" end),
    replication: (if $replication == "" then null else $replication == "t" end),
    bypassrls: (if $bypassrls == "" then null else $bypassrls == "t" end),
    memberships: $memberships,
    database_owner: (if $database_owner == "" then null else $database_owner end),
    role_verifier_digest: $role_verifier_digest,
    postgresql_major: $postgresql_major,
    pg_version: $pg_version,
    data_system_identifier: $data_system_identifier,
    postgres_executable: $postgres_executable,
    process: $process
}
JQ
}

application_observation_filter() {
    "$COREUTILS/cat" <<'JQ'
{
    schema: $schema,
    configuration_revision: $configuration_revision,
    current_user: $current_user,
    role: $role,
    login: true,
    inherit: false,
    superuser: false,
    createdb: false,
    createrole: false,
    replication: false,
    bypassrls: false,
    memberships: 0,
    database_owner: $database_owner,
    role_verifier_digest: null
}
JQ
}

local_psql() {
    "$PSQL" \
        -X --no-psqlrc --no-align --tuples-only --set ON_ERROR_STOP=1 \
        -h "$run_directory" -p "$port" -U "$ADMIN_ROLE" -d postgres \
        "$@"
}

query_admin_observation() {
    local observation_schema=$1
    local result
    local revision current_user observed_role login inherit superuser createdb createrole replication bypassrls owner verifier memberships extra
    local verifier_digest=null
    local process

    result=$(local_psql --field-separator '|' -c "$(admin_observation_sql)")
    IFS='|' read -r revision current_user observed_role login inherit superuser \
        createdb createrole replication bypassrls owner verifier memberships \
        extra <<< "$result"
    [[ -z ${extra:-} \
        && ( -z $configuration_revision || $revision == "$configuration_revision" ) \
        && $current_user == "$ADMIN_ROLE" \
        && $observed_role == "$role" \
        && $login == t \
        && $inherit == f \
        && $superuser == f \
        && $createdb == f \
        && $createrole == f \
        && $replication == f \
        && $bypassrls == f \
        && $owner == "$role" \
        && $memberships == 0 ]] \
        || fail 'PostgreSQL local SQL identity is not authorized'

    if [[ -n $verifier ]]; then
        verifier_digest="sha256:$(printf '%s' "$verifier" | "$COREUTILS/sha256sum")"
        verifier_digest=${verifier_digest%% *}
    fi
    if [[ $auth == scram ]]; then
        [[ $verifier_digest =~ ^sha256:[0-9a-f]{64}$ ]] \
            || fail 'PostgreSQL SCRAM role has no verifier'
    else
        [[ $verifier_digest == null ]] \
            || fail 'PostgreSQL trust role retains a verifier'
    fi

    if [[ -z $observation_schema ]]; then
        return
    fi

    process=$(process_identity_json)

    "$JQ" -cSn \
        --arg schema "$observation_schema" \
        --arg configuration_revision "$revision" \
        --arg current_user "$current_user" \
        --arg role "$observed_role" \
        --arg database_owner "$owner" \
        --arg pg_version "$observed_pg_version" \
        --arg data_system_identifier "$data_system_identifier" \
        --arg postgres_executable "$POSTGRES" \
        --argjson process "$process" \
        --argjson postgresql_major "$postgresql_major" \
        --argjson role_verifier_digest \
            "$(if [[ $verifier_digest == null ]]; then "$COREUTILS/printf" null; else "$JQ" -cn --arg value "$verifier_digest" '$value'; fi)" \
        "$(admin_observation_filter)"
}

query_stop_observation() {
    local result
    local revision current_user role_exists database_exists
    local login inherit superuser createdb createrole replication bypassrls
    local owner verifier memberships extra
    local verifier_digest=null
    local process

    result=$(local_psql --field-separator '|' -c "$(stop_observation_sql)")
    IFS='|' read -r revision current_user role_exists database_exists \
        login inherit superuser createdb createrole replication bypassrls \
        owner verifier memberships extra <<< "$result"
    [[ -z ${extra:-} \
        && $revision == "$configuration_revision" \
        && $current_user == "$ADMIN_ROLE" \
        && ( $role_exists == t || $role_exists == f ) \
        && ( $database_exists == t || $database_exists == f ) \
        && $memberships =~ ^[0-9]+$ ]] \
        || fail 'PostgreSQL stop observation has an invalid core identity'
    for value in "$login" "$inherit" "$superuser" "$createdb" \
        "$createrole" "$replication" "$bypassrls"; do
        [[ -z $value || $value == t || $value == f ]] \
            || fail 'PostgreSQL stop observation has an invalid role flag'
    done

    if [[ -n $verifier ]]; then
        verifier_digest="sha256:$(printf '%s' "$verifier" | "$COREUTILS/sha256sum")"
        verifier_digest=${verifier_digest%% *}
    fi
    process=$(process_identity_json)

    "$JQ" -cSn \
        --arg schema 'aos.postgresql.control-authenticate-stop/v1' \
        --arg configuration_revision "$revision" \
        --arg current_user "$current_user" \
        --arg requested_role "$role" \
        --arg requested_database "$database" \
        --arg role_exists "$role_exists" \
        --arg database_exists "$database_exists" \
        --arg login "$login" \
        --arg inherit "$inherit" \
        --arg superuser "$superuser" \
        --arg createdb "$createdb" \
        --arg createrole "$createrole" \
        --arg replication "$replication" \
        --arg bypassrls "$bypassrls" \
        --arg database_owner "$owner" \
        --argjson memberships "$memberships" \
        --arg pg_version "$observed_pg_version" \
        --arg data_system_identifier "$data_system_identifier" \
        --arg postgres_executable "$POSTGRES" \
        --argjson postgresql_major "$postgresql_major" \
        --argjson process "$process" \
        --argjson role_verifier_digest \
            "$(if [[ $verifier_digest == null ]]; then "$COREUTILS/printf" null; else "$JQ" -cn --arg value "$verifier_digest" '$value'; fi)" \
        "$(stop_observation_filter)"
}

read_secret() {
    password=
    local trailing=

    if [[ $auth == trust ]]; then
        if IFS= read -r trailing || [[ -n $trailing ]]; then
            fail 'trust-mode PostgreSQL control rejects credential input'
        fi
        return
    fi

    IFS= read -r password \
        || fail 'PostgreSQL control requires one newline-terminated credential'
    (( ${#password} > 0 && ${#password} <= MAX_SECRET_BYTES )) \
        || fail 'PostgreSQL credential is empty or too large'
    [[ $password != *$'\r'* ]] \
        || fail 'PostgreSQL credential contains a carriage return'
    if IFS= read -r trailing || [[ -n $trailing ]]; then
        fail 'PostgreSQL control rejects trailing credential input'
    fi
}

repair_role_and_database() {
    local exists
    local verifier
    local verifier_digest=null

    exists=$(local_psql -c "SELECT 1 FROM pg_roles WHERE rolname = '$role'")
    if [[ $exists != 1 ]]; then
        "$COREUTILS/printf" \
            'CREATE ROLE "%s" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n' \
            "$role" \
            | local_psql -f - >/dev/null
    else
        "$COREUTILS/printf" \
            'ALTER ROLE "%s" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n' \
            "$role" \
            | local_psql -f - >/dev/null
    fi

    local_psql -c "$(revoke_parent_memberships_sql)" \
        | local_psql -f - >/dev/null
    local_psql -c "$(revoke_member_grants_sql)" \
        | local_psql -f - >/dev/null

    if [[ $auth == scram ]]; then
        if ! printf '\\password "%s"\n%s\n%s\n' \
            "$role" "$password" "$password" \
            | local_psql -f - >/dev/null 2>&1; then
            fail 'PostgreSQL application credential repair failed'
        fi
    else
        "$COREUTILS/printf" 'ALTER ROLE "%s" PASSWORD NULL;\n' "$role" \
            | local_psql -f - >/dev/null
    fi

    exists=$(local_psql -c "SELECT 1 FROM pg_database WHERE datname = '$database'")
    if [[ $exists != 1 ]]; then
        "$COREUTILS/printf" 'CREATE DATABASE "%s" OWNER "%s";\n' "$database" "$role" \
            | local_psql -f - >/dev/null
    fi
    "$COREUTILS/printf" 'ALTER DATABASE "%s" OWNER TO "%s";\n' "$database" "$role" \
        | local_psql -f - >/dev/null

    verifier=$(local_psql -c "SELECT COALESCE(rolpassword, '') FROM pg_authid WHERE rolname = '$role'")
    if [[ -n $verifier ]]; then
        verifier_digest="sha256:$(printf '%s' "$verifier" | "$COREUTILS/sha256sum")"
        verifier_digest=${verifier_digest%% *}
    fi
    if [[ $auth == scram ]]; then
        [[ $verifier_digest =~ ^sha256:[0-9a-f]{64}$ ]] \
            || fail 'PostgreSQL SCRAM repair produced no verifier'
    else
        [[ $verifier_digest == null ]] \
            || fail 'PostgreSQL trust repair retained a verifier'
    fi

    # Reuse the closed observation query to enforce flags and ownership, while
    # suppressing its record in favor of the narrower repair result.
    query_admin_observation ''
    "$JQ" -cSn \
        --arg schema 'aos.postgresql.control-repair/v1' \
        --argjson role_verifier_digest \
            "$(if [[ $verifier_digest == null ]]; then "$COREUTILS/printf" null; else "$JQ" -cn --arg value "$verifier_digest" '$value'; fi)" \
        '{schema: $schema, role_verifier_digest: $role_verifier_digest}'
}

observe_application() {
    local result
    local revision current_user observed_role login inherit superuser createdb createrole replication bypassrls owner memberships extra

    if [[ $auth == scram ]]; then
        result=$(printf '%s\n' "$password" \
            | "$PSQL" \
                -X --no-psqlrc -W --no-align --tuples-only --set ON_ERROR_STOP=1 \
                --field-separator '|' \
                -h "$address" -p "$port" -U "$role" -d "$database" \
                -c "$(application_observation_sql)" \
                2>/dev/null)
    else
        result=$("$PSQL" \
            -X --no-psqlrc --no-align --tuples-only --set ON_ERROR_STOP=1 \
            --field-separator '|' \
            -h "$address" -p "$port" -U "$role" -d "$database" \
            -c "$(application_observation_sql)")
    fi
    IFS='|' read -r revision current_user observed_role login inherit superuser createdb createrole replication bypassrls owner memberships extra <<< "$result"
    [[ -z ${extra:-} \
        && $revision == "$configuration_revision" \
        && $current_user == "$role" \
        && $observed_role == "$role" \
        && $login == t \
        && $inherit == f \
        && $superuser == f \
        && $createdb == f \
        && $createrole == f \
        && $replication == f \
        && $bypassrls == f \
        && $owner == "$role" \
        && $memberships == 0 ]] \
        || fail 'PostgreSQL application SQL identity is not ready'

    "$JQ" -cSn \
        --arg schema 'aos.postgresql.control-observe/v1' \
        --arg configuration_revision "$revision" \
        --arg current_user "$current_user" \
        --arg role "$observed_role" \
        --arg database_owner "$owner" \
        "$(application_observation_filter)"
}
