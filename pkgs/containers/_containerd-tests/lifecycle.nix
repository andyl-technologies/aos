##! Real-binary lifecycle contract for standalone containerd.
{
  testing,
  self,
  coreutils,
  grep,
  iproute2,
}:
testing.mkVMTest {
  name = "containers-containerd-runtime-contract";
  rootfsDeps = [self coreutils grep iproute2];
  memory = 1536;
  testScript = ''
    set -eu

    ip link set lo up
    install -d -m 0755 /var/lib/containerd /run/containerd /etc/containerd
    cat >/etc/containerd/config.toml <<'EOF'
    version = 3
    root = "/var/lib/containerd"
    state = "/run/containerd"

    [grpc]
    address = "/run/containerd/containerd.sock"

    [plugins."io.containerd.cri.v1.images"]
    snapshotter = "native"

    [plugins."io.containerd.cri.v1.images".pinned_images]
    sandbox = "registry.k8s.io/pause:3.10"

    [plugins."io.containerd.cri.v1.runtime".containerd]
    default_runtime_name = "runc"

    [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
    runtime_type = "io.containerd.runc.v2"

    [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
    SystemdCgroup = true
    EOF

    cat >/tmp/invalid.toml <<'EOF'
    version = "invalid"
    EOF
    if containerd --config /tmp/invalid.toml config dump >/tmp/invalid.out 2>&1; then
      echo "containerd accepted a malformed typed configuration" >&2
      exit 1
    fi

    start_runtime() {
      containerd --config /etc/containerd/config.toml >/tmp/containerd.log 2>&1 &
      runtime_pid=$!
      ready=false
      for attempt in $(seq 1 60); do
        if ctr --address /run/containerd/containerd.sock version >/tmp/version.out 2>&1; then
          ready=true
          break
        fi
        sleep 1
      done
      if [ "$ready" != true ]; then
        cat /tmp/containerd.log >&2
        exit 1
      fi
    }
    stop_runtime() {
      kill "$runtime_pid"
      wait "$runtime_pid" || true
    }
    cleanup() {
      if kill -0 "$runtime_pid" 2>/dev/null; then
        kill "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
      fi
    }
    trap cleanup EXIT

    start_runtime
    ctr --address /run/containerd/containerd.sock plugins ls \
      | grep -q 'io.containerd.snapshotter.v1.*native.*ok'
    test -s /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db
    stop_runtime

    start_runtime
    ctr --address /run/containerd/containerd.sock version | grep -q 'Server:'
    stop_runtime
    trap - EXIT
  '';
}
