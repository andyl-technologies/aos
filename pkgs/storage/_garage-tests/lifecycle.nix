##! Real-binary Garage configuration and lifecycle contract.
{
  testing,
  self,
  renderedConfig,
  coreutils,
  grep,
  iproute2,
}:
testing.mkVMTest {
  name = "storage-garage-runtime-contract";
  rootfsDeps = [
    self
    renderedConfig
    coreutils
    grep
    iproute2
  ];
  memory = 1536;
  testScript = ''
    set -eu

    ip link set lo up
    printf '%s\n' 'garage:x:804:804:Garage:/var/lib/aos-pkg-garage:/sbin/nologin' >> /etc/passwd
    printf '%s\n' 'garage:x:804:' >> /etc/group
    install -d -m 0750 -o 804 -g 804 \
      /var/lib/aos-pkg-garage /var/lib/aos-pkg-garage/meta \
      /var/lib/aos-pkg-garage/data /run/garage /var/log/garage
    printf '%s\n' '1799bccfd7411eddcf9ebd316bc1f5287ad12a68094e1c6ac6abde7e6feae1ec' \
      >/run/garage/rpc-secret
    chown 804:804 /run/garage/rpc-secret
    chmod 0600 /run/garage/rpc-secret

    cat >/tmp/invalid.toml <<'EOF'
    metadata_dir = "/tmp/meta"
    data_dir = "/tmp/data"
    replication_factor = "not-an-integer"
    rpc_bind_addr = "127.0.0.1:43901"
    [s3_api]
    s3_region = "garage"
    api_bind_addr = "127.0.0.1:43900"
    EOF
    if GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c /tmp/invalid.toml status >/tmp/invalid.out 2>&1; then
      echo "Garage accepted a malformed typed configuration" >&2
      exit 1
    fi
    grep -Eq 'replication_factor|invalid type' /tmp/invalid.out

    start_garage() {
      chroot --userspec=804:804 / \
        env GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
        garage -c ${renderedConfig} server >/tmp/garage.log 2>&1 &
      server_pid=$!
      ready=false
      for attempt in $(seq 1 60); do
        if GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
          garage -c ${renderedConfig} status >/tmp/status.out 2>&1; then
          ready=true
          break
        fi
        sleep 1
      done
      if [ "$ready" != true ]; then
        cat /tmp/garage.log >&2
        exit 1
      fi
    }
    stop_garage() {
      kill "$server_pid"
      wait "$server_pid" || true
    }
    cleanup() {
      if kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
      fi
    }
    trap cleanup EXIT

    start_garage
    node_id=$(GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} node id -q | cut -d@ -f1)
    test -n "$node_id"
    GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} layout assign -z dc1 -c 1G "$node_id"
    GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} layout apply --version 1
    GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} key create lifecycle-key
    GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} key list | grep -q lifecycle-key

    stop_garage
    start_garage
    GARAGE_RPC_SECRET_FILE=/run/garage/rpc-secret \
      garage -c ${renderedConfig} key list | grep -q lifecycle-key
    stop_garage
    trap - EXIT
  '';
}
