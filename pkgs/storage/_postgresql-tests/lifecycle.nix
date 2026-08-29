##! Real-binary PostgreSQL configuration and lifecycle contract.
{
  testing,
  self,
  coreutils,
  grep,
  sed,
}:
testing.mkVMTest {
  name = "storage-postgresql-runtime-contract";
  rootfsDeps = [
    self
    coreutils
    grep
    sed
  ];
  memory = 768;
  testScript = ''
    set -eu

    printf '%s\n' 'postgres:x:71:71:PostgreSQL:/tmp/postgresql:/sbin/nologin' >> /etc/passwd
    printf '%s\n' 'postgres:x:71:' >> /etc/group
    install -d -m 0750 -o 71 -g 71 /tmp/postgresql
    install -d -m 0700 -o 71 -g 71 /tmp/postgresql/data
    install -d -m 0750 -o 71 -g 71 /tmp/postgresql/run

    ${coreutils}/bin/chroot --userspec=71:71 / \
      initdb --pgdata=/tmp/postgresql/data --username=postgres \
        --auth-local=trust --auth-host=trust --encoding=UTF8 --locale=C

    cat > /tmp/postgresql/postgresql.conf <<'EOF'
    data_directory = '/tmp/postgresql/data'
    hba_file = '/tmp/postgresql/pg_hba.conf'
    listen_addresses = '127.0.0.1'
    port = 55432
    unix_socket_directories = '/tmp/postgresql/run'
    shared_buffers = '32MB'
    dynamic_shared_memory_type = 'mmap'
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

    ${coreutils}/bin/chroot --userspec=71:71 / \
      postgres -D /tmp/postgresql/data -C port \
        -c config_file=/tmp/postgresql/postgresql.conf | ${grep}/bin/grep -qx 55432

    cp /tmp/postgresql/postgresql.conf /tmp/postgresql/invalid.conf
    printf '%s\n' "not_a_real_postgresql_parameter = 'rejected'" >> /tmp/postgresql/invalid.conf
    chown 71:71 /tmp/postgresql/invalid.conf
    if ${coreutils}/bin/chroot --userspec=71:71 / \
      postgres -D /tmp/postgresql/data -C port \
        -c config_file=/tmp/postgresql/invalid.conf >/tmp/invalid.out 2>&1; then
      echo "postgres accepted an unknown configuration parameter" >&2
      exit 1
    fi
    ${grep}/bin/grep -q 'unrecognized configuration parameter' /tmp/invalid.out

    if ! ${coreutils}/bin/chroot --userspec=71:71 / \
      pg_ctl -D /tmp/postgresql/data -l /tmp/postgresql/server.log -w start \
        -o '-c config_file=/tmp/postgresql/postgresql.conf'; then
      cat /tmp/postgresql/server.log >&2
      exit 1
    fi
    psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
      -Atc 'show port' | ${grep}/bin/grep -qx 55432
    psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
      -Atc 'show log_min_messages' | ${grep}/bin/grep -qx warning

    ${sed}/bin/sed -i 's/log_min_messages = warning/log_min_messages = error/' \
      /tmp/postgresql/postgresql.conf
    ${coreutils}/bin/chroot --userspec=71:71 / \
      pg_ctl -D /tmp/postgresql/data reload
    i=0
    while [ "$i" -lt 20 ]; do
      if psql -h /tmp/postgresql/run -p 55432 -U postgres -d postgres \
        -Atc 'show log_min_messages' | ${grep}/bin/grep -qx error; then
        break
      fi
      i=$((i + 1))
    done
    test "$i" -lt 20

    ${coreutils}/bin/chroot --userspec=71:71 / \
      pg_ctl -D /tmp/postgresql/data -m fast -w stop
    ! ${coreutils}/bin/chroot --userspec=71:71 / \
      pg_ctl -D /tmp/postgresql/data status
  '';
}
