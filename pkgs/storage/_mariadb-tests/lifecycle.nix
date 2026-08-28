##! Real-binary MariaDB configuration and lifecycle contract.
{
  testing,
  self,
  renderedFile,
  coreutils,
  grep,
  iproute2,
}:
testing.mkVMTest {
  name = "storage-mariadb-runtime-contract";
  rootfsDeps = [
    self
    renderedFile
    coreutils
    grep
    iproute2
  ];
  memory = 1536;
  testScript = ''
    set -eu

    ip link set lo up
    printf '%s\n' 'mariadb:x:803:803:MariaDB:/var/lib/aos-pkg-mariadb:/sbin/nologin' >> /etc/passwd
    printf '%s\n' 'mariadb:x:803:' >> /etc/group
    install -d -m 0750 -o 803 -g 803 \
      /var/lib/aos-pkg-mariadb /run/mariadb /var/log/mariadb
    install -m 0600 -o 803 -g 803 /dev/null /run/mariadb/bootstrap.sql

    mariadbd --defaults-file=${renderedFile}/my.cnf --verbose --help >/tmp/valid.out
    printf '%s\n' '[mariadbd]' 'unknown-aos-option=1' >/tmp/invalid.cnf
    if mariadbd --defaults-file=/tmp/invalid.cnf --verbose --help \
      >/tmp/invalid.out 2>&1; then
      echo "MariaDB accepted an unknown generated option" >&2
      exit 1
    fi
    grep -q 'unknown-aos-option' /tmp/invalid.out

    chroot --userspec=803:803 / \
      mariadb-install-db --defaults-file=${renderedFile}/my.cnf \
        --auth-root-authentication-method=socket --skip-test-db

    chroot --userspec=803:803 / \
      mariadbd --defaults-file=${renderedFile}/my.cnf >/tmp/mariadb.log 2>&1 &
    server_pid=$!
    cleanup() {
      if kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
      fi
    }
    trap cleanup EXIT

    ready=false
    for attempt in $(seq 1 60); do
      if mariadb-admin --socket=/run/mariadb/mariadb.sock --user=root ping \
        >/dev/null 2>&1; then
        ready=true
        break
      fi
      sleep 1
    done
    if [ "$ready" != true ]; then
      cat /tmp/mariadb.log >&2
      exit 1
    fi

    mariadb --socket=/run/mariadb/mariadb.sock --user=root \
      -e 'CREATE DATABASE aos_runtime; CREATE TABLE aos_runtime.state (value VARCHAR(16)); INSERT INTO aos_runtime.state VALUES ("persistent");'
    mariadb --socket=/run/mariadb/mariadb.sock --user=root --batch --skip-column-names \
      -e 'SELECT value FROM aos_runtime.state' | grep -qx persistent

    kill "$server_pid"
    wait "$server_pid"
    trap - EXIT

    chroot --userspec=803:803 / \
      mariadbd --defaults-file=${renderedFile}/my.cnf >/tmp/mariadb-restart.log 2>&1 &
    server_pid=$!
    trap cleanup EXIT
    ready=false
    for attempt in $(seq 1 60); do
      if mariadb-admin --socket=/run/mariadb/mariadb.sock --user=root ping \
        >/dev/null 2>&1; then
        ready=true
        break
      fi
      sleep 1
    done
    test "$ready" = true
    mariadb --socket=/run/mariadb/mariadb.sock --user=root --batch --skip-column-names \
      -e 'SELECT value FROM aos_runtime.state' | grep -qx persistent

    mariadb-admin --socket=/run/mariadb/mariadb.sock --user=root shutdown
    wait "$server_pid"
    trap - EXIT
  '';
}
