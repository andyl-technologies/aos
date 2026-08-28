##! Real-binary PostgreSQL configuration and lifecycle contract.
{
  testing,
  self,
  coreutils,
  util-linux,
}:
testing.mkVMTest {
  name = "storage-postgresql-runtime-contract";
  rootfsDeps = [
    self
    coreutils
    util-linux
  ];
  memory = 768;
  testScript = ''
    set -eu

    printf '%s\n' 'postgres:x:71:71:PostgreSQL:/tmp/postgresql:/sbin/nologin' >> /etc/passwd
    printf '%s\n' 'postgres:x:71:' >> /etc/group
    install -d -m 0700 -o 71 -g 71 /tmp/postgresql/data
    install -d -m 0750 -o 71 -g 71 /tmp/postgresql/run

    setpriv --reuid=71 --regid=71 --clear-groups \
      initdb --pgdata=/tmp/postgresql/data --username=postgres \
        --auth-local=trust --auth-host=trust --encoding=UTF8 --locale=C

    cat > /tmp/postgresql/postgresql.conf <<'EOF'
    data_directory = '/tmp/postgresql/data'
    hba_file = '/tmp/postgresql/pg_hba.conf'
    listen_addresses = '127.0.0.1'
    port = 55432
    unix_socket_directories = '/tmp/postgresql/run'
    shared_buffers = '32MB'
    max_connections = 20
    logging_collector = off
    log_destination = 'stderr'
    log_min_messages = warning
    EOF
    cat > /tmp/postgresql/pg_hba.conf <<'EOF'
    local all all trust
    host all all 127.0.0.1/32 trust
    EOF
    chown 71:71 /tmp/postgresql/postgresql.conf /tmp/postgresql/pg_hba.conf

    setpriv --reuid=71 --regid=71 --clear-groups \
      postgres -D /tmp/postgresql/data -C port \
        -c config_file=/tmp/postgresql/postgresql.conf | grep -qx 55432

    cp /tmp/postgresql/postgresql.conf /tmp/postgresql/invalid.conf
    printf '%s\n' "not_a_real_postgresql_parameter = 'rejected'" >> /tmp/postgresql/invalid.conf
    chown 71:71 /tmp/postgresql/invalid.conf
    if setpriv --reuid=71 --regid=71 --clear-groups \
      postgres -D /tmp/postgresql/data -C port \
        -c config_file=/tmp/postgresql/invalid.conf >/tmp/invalid.out 2>&1; then
      echo "postgres accepted an unknown configuration parameter" >&2
      exit 1
    fi
    grep -q 'unrecognized configuration parameter' /tmp/invalid.out

    setpriv --reuid=71 --regid=71 --clear-groups \
      pg_ctl -D /tmp/postgresql/data -l /tmp/postgresql/server.log -w start \
        -o '-c config_file=/tmp/postgresql/postgresql.conf'
    psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
      -Atc 'select current_setting('"'"'cluster_name'"'"', true) is null' | grep -qx t
    psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
      -Atc 'show log_min_messages' | grep -qx warning

    sed -i 's/log_min_messages = warning/log_min_messages = error/' \
      /tmp/postgresql/postgresql.conf
    setpriv --reuid=71 --regid=71 --clear-groups \
      pg_ctl -D /tmp/postgresql/data reload
    i=0
    while [ "$i" -lt 20 ]; do
      if psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
        -Atc 'show log_min_messages' | grep -qx error; then
        break
      fi
      i=$((i + 1))
    done
    test "$i" -lt 20

    setpriv --reuid=71 --regid=71 --clear-groups \
      pg_ctl -D /tmp/postgresql/data -m fast -w stop
    ! setpriv --reuid=71 --regid=71 --clear-groups \
      pg_ctl -D /tmp/postgresql/data status
  '';
}
