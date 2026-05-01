# tests/fleet/k3s-control-plane-worker.nix — Two-machine smoke test
# for the k3s-control-plane + k3s-worker pair.
#
# Topology:
#   controlplane: aos.roles.k3s-control-plane (k3s server --disable-agent)
#   worker:       aos.roles.k3s-worker        (k3s agent)
#
# Both receive `K3S_TOKEN` via instanceMetadata.config.storage.files.
# The worker additionally receives `K3S_URL` pointing at the control
# plane's hostname (resolved by the fleet identity fragment's
# /etc/hosts to the harness-assigned 192.168.50.10).
#
# Test cadence:
#   1. Wait for k3s-preflight + k3s on each machine.
#   2. From the control plane, kubectl get nodes — assert the worker
#      registered and reached the `Ready` condition. Worker
#      registration covers the round trip: token ok, TLS ok, agent
#      pulled flannel config from the API server, kubelet started.
{
  pkgs,
  systems,
}: let
  # k3s's token parser (`pkg/clientaccess/token.go:251`) accepts
  # kubeadm bootstrap tokens, `username:password` pairs, or K10-
  # wrapped variants — but `k3s server`'s `pkg/util.NormalizeToken`
  # then rejects anything that came out as a `BootstrapTokenString`,
  # leaving only basic-auth shapes (`<password>` or
  # `K10<CA-HASH>::<USERNAME>:<PASSWORD>`). A bare password is the
  # simplest form that satisfies both ends; see the longer note in
  # `tests/fleet/k3s-combined-worker.nix`.
  testToken = "aoscontrolplanefleet1";

  # Shape an env-file as a `storage.files` entry. `mode = 384` is
  # 0600 — the file holds K3S_TOKEN and shouldn't be world-readable
  # even on a test VM.
  #
  # The encoder replaces `\n` with `%0A` and ` ` (space) with `%20`,
  # so any leading whitespace in `body` ends up encoded into the
  # decoded file. systemd's `EnvironmentFile=` parser does NOT
  # strip leading whitespace per `systemd.exec(5)`, so an indented
  # body like `''  K3S_TOKEN=…''` would produce the (invalid) line
  # `  K3S_TOKEN=…` and the preflight unit would fail at parse
  # time. Always pass fully de-indented Nix indented strings into
  # `envFile`.
  #
  # TODO(spec follow-up): replace this inline encoder with a public
  # `lib.testing.dataUrl` once `lib/testing/fleet.nix`'s `uriEncode`
  # is exported. Two copies in two test files is the status quo;
  # documenting the duplication so the next test author doesn't get
  # a third drift.
  uriEncode =
    builtins.replaceStrings
    ["%" "\n" " " "&" "+" "=" "[" "]" "#" "?"]
    ["%25" "%0A" "%20" "%26" "%2B" "%3D" "%5B" "%5D" "%23" "%3F"];

  envFile = body: {
    path = "/etc/rancher/k3s/k3s.env";
    mode = 384;
    overwrite = true;
    contents.source = "data:," + uriEncode body;
  };

  # /etc/rancher/k3s/config.yaml is k3s's default config-file
  # location. Both `k3s server` and `k3s agent` read it
  # automatically; the loader (`pkg/configfilearg`) merges its keys
  # in as if they were CLI flags. We use it to pin `node-ip` per
  # machine without having to bake the IP into the role's
  # ExecStart (the role is image-shared and doesn't know the IP).
  #
  # Why we have to pin node-ip in tests: k3s would otherwise call
  # `apimachinery/pkg/util/net.ChooseHostInterface()`, which reads
  # `/proc/net/route` to find the default-route interface and
  # picks its address. The fleet harness in lib/testing/fleet.nix
  # only writes `[Network] Address=` on eth0 — no gateway, no
  # default route — so that lookup fatals with "no default routes
  # found". Real-world hosts always have a default route via
  # DHCP / a real gateway; pinning node-ip here is test-only glue.
  configFile = ip: {
    path = "/etc/rancher/k3s/config.yaml";
    mode = 420; # 0644
    overwrite = true;
    contents.source = "data:," + uriEncode "node-ip: ${ip}\n";
  };
in {
  name = "k3s-control-plane-worker";
  # k3s server takes ~30-45s to become Ready on a 2-vCPU VM
  # (datastore init + cert gen + apiserver bootstrap). Worker
  # registration takes another ~15-30s once the server is up.
  # Budget 6 minutes total so a slow CI runner doesn't tip over.
  timeout = 360;

  # The fleet harness in lib/testing/fleet.nix assigns
  # `192.168.50.${i + 10}` per machine via `lib.imap` over
  # `builtins.attrNames machines`. `builtins.attrNames` is
  # specified to return names in lexicographic order, so the
  # mapping is deterministic and depends only on the attribute
  # names — `controlplane` < `worker`, so controlplane→.10,
  # worker→.11.
  machines = {
    controlplane = {
      system = systems.server;
      roles = ["k3s-control-plane"];
      instanceMetadata.config.storage.files = [
        (envFile ''
          K3S_TOKEN=${testToken}
        '')
        (configFile "192.168.50.10")
      ];
    };

    worker = {
      system = systems.server;
      roles = ["k3s-worker"];
      instanceMetadata.config.storage.files = [
        (envFile ''
          K3S_TOKEN=${testToken}
          K3S_URL=https://controlplane:6443
        '')
        (configFile "192.168.50.11")
      ];
    };
  };

  testScript = ''
    # ── Pre-flight on each machine ─────────────────────────────────
    # k3s-preflight is a oneshot — `is-active` returns "active"
    # only after exit-0. A failure here means either ignition
    # didn't land the env file (ConditionPathExists short-circuits
    # the unit to "skipped", which is-active reports as
    # "inactive"), or systemd's EnvironmentFile= parser rejected
    # the file's contents, or one of the required vars is empty.
    wait_until_succeeds_on controlplane \
      "systemctl is-active k3s-preflight.service" 60 \
      "controlplane k3s-preflight reaches active"

    wait_until_succeeds_on worker \
      "systemctl is-active k3s-preflight.service" 60 \
      "worker k3s-preflight reaches active"

    # ── k3s.service active on both ─────────────────────────────────
    # `Type=notify` flips active once k3s emits READY=1 on its
    # sd_notify socket. For `--disable-agent`, that's apiserver +
    # startup-hooks ready; for the agent it's kubelet up +
    # node-registration done. On 2-vCPU VMs cert-gen + apiserver
    # bootstrap typically takes 60-120s; the timeout below has
    # slack for a slow runner.
    wait_until_succeeds_on controlplane \
      "systemctl is-active k3s.service" 240 \
      "controlplane k3s.service reaches active"

    wait_until_succeeds_on worker \
      "systemctl is-active k3s.service" 240 \
      "worker k3s.service reaches active"

    # ── Apiserver reachable + healthy on the control plane ────────
    # /healthz returns the literal string "ok" when the apiserver
    # is fully up. We don't `kubectl get componentstatuses` because
    # k3s lies about scheduler/controller-manager component health
    # in some versions — /healthz is the load-bearing probe.
    wait_until_succeeds_on controlplane \
      "${pkgs.curl}/bin/curl -sfk https://127.0.0.1:6443/healthz | grep -qx 'ok'" \
      60 \
      "controlplane apiserver /healthz returns ok"

    # ── Worker registered + Ready ─────────────────────────────────
    # With `--disable-agent`, the control-plane is invisible in
    # `kubectl get nodes` — only the worker registers. Asserting
    # the worker reaches Ready proves the full join round-trip:
    # token verified, TLS verified against the auto-computed SAN
    # list (which includes the hostname "controlplane" via
    # /etc/hosts + os.Hostname()), agent pulled flannel config
    # from the apiserver, kubelet started, configureNode wrote
    # the Node object.
    wait_until_succeeds_on controlplane \
      "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get node worker -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -Fxq True" \
      180 \
      "worker node Ready (cross-host registration)"

    # ── Sanity: exactly one Node exists ───────────────────────────
    # `assert_output_on` uses `grep -q` (substring match), so
    # passing "1" as the expected value would also match "11", "12",
    # … Use `assert_on` with a numeric `test -eq` instead — that
    # asserts an exact integer equality and returns exit 0/1.
    assert_on controlplane \
      "test $(${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get nodes --no-headers | wc -l) -eq 1" \
      "exactly one node registered (control-plane is invisible by design)"
  '';
}
