# tests/fleet/k3s-control-plane-worker.nix — Two-machine smoke test
# for the k3s-control-plane + k3s-worker pair.
#
# Topology:
#   controlplane: pkgs.k3s-control-plane (k3s server --disable-agent)
#   worker:       pkgs.k3s-worker        (k3s agent)
#
# Both receive `K3S_TOKEN` baked into the image /etc via extendModules
# (extraModules). The worker additionally receives `K3S_URL` pointing at
# the control plane's harness-assigned IP.
#
# Test cadence:
#   1. Wait for k3s-preflight + k3s on each machine.
#   2. From the control plane, kubectl get nodes — assert the worker
#      registered and reached the `Ready` condition. Worker
#      registration covers the round trip: token ok, TLS ok, agent
#      pulled flannel config from the API server, kubelet started.
{
  dataUrl,
  mkSystem,
  pkgs,
  ...
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

  # Per-node k3s config, baked into the image /etc via extendModules (the
  # baked machine configuration). Two files:
  #
  #   /etc/rancher/k3s/k3s.env    — K3S_TOKEN (+ K3S_URL for the worker),
  #                                 mode 0600 (holds the join token).
  #   /etc/rancher/k3s/config.yaml — k3s's default config-file location. Both
  #                                 `k3s server` and `k3s agent` read it
  #                                 automatically (`pkg/configfilearg` merges
  #                                 its keys as CLI flags). Pins node-ip +
  #                                 flannel-iface per machine.
  #
  # Why we pin node-ip: k3s would otherwise call
  # `apimachinery/pkg/util/net.ChooseHostInterface()`, which reads
  # `/proc/net/route` for the default-route interface. The fleet harness only
  # writes `[Network] Address=` on eth0 — no gateway, no default route — so the
  # lookup fatals with "no default routes found". Pinning node-ip is test glue.
  #
  # Why we pin flannel-iface: k3s's embedded flannel walks the same routing
  # table (`pkg/agent/flannel.LookupExtIface`). With no default route it
  # `os.Exit(1)`s the agent, trapping the unit in `activating`/`failed`. Pinning
  # the iface skips the gateway probe. eth0 is deterministic (net.ifnames=0 in
  # the cmdline; a single mcast NIC per sandbox VM).
  k3sEtcModule = {
    token,
    ip,
    url ? null,
  }: {
    environment.etc = {
      "rancher/k3s/k3s.env" = {
        mode = "0600";
        text =
          "K3S_TOKEN=${token}\n"
          + (
            if url == null
            then ""
            else "K3S_URL=${url}\n"
          );
      };
      "rancher/k3s/config.yaml".text = ''
        node-ip: ${ip}
        flannel-iface: eth0
      '';
    };
  };

  controlPlaneSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.k3s-control-plane = {
        package = pkgs.k3s-control-plane;
        bundle = true;
        preset = false;
      };
    }
  ];

  workerSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.k3s-worker = {
        package = pkgs.k3s-worker;
        bundle = true;
        preset = false;
      };
    }
  ];
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
      system = controlPlaneSystem;
      packages = ["k3s-control-plane"];
      extraModules = [
        (k3sEtcModule {
          token = testToken;
          ip = "192.168.50.10";
        })
      ];
    };

    worker = {
      system = workerSystem;
      packages = ["k3s-worker"];
      extraModules = [
        (k3sEtcModule {
          token = testToken;
          ip = "192.168.50.11";
          url = "https://192.168.50.10:6443";
        })
      ];
    };
  };

  testScript = ''
    def dump_unit(machine, unit):
        print(f"--- {machine.name}: systemctl status {unit} ---")
        print(
            machine.succeed(
                f"systemctl status --no-pager -l {unit} 2>&1 || true",
                timeout=30,
            )
        )
        print(f"--- {machine.name}: journalctl -u {unit} ---")
        print(
            machine.succeed(
                f"journalctl -u {unit} --no-pager -n 200 2>&1 || true",
                timeout=30,
            )
        )

    def wait_unit_active(machine, unit, timeout):
        try:
            machine.wait_until_succeeds(
                f"systemctl is-active {unit}", timeout=timeout
            )
        except Exception:
            dump_unit(machine, unit)
            print(f"--- {machine.name}: failed units ---")
            print(machine.succeed("systemctl --failed --no-pager 2>&1 || true"))
            print(f"--- {machine.name}: pending jobs ---")
            print(machine.succeed("systemctl list-jobs --no-pager 2>&1 || true"))
            raise

    # ── Package activation targets ─────────────────────────────────
    controlplane.wait_until_succeeds(
        "systemctl is-active aos-pkg-k3s-control-plane.target", timeout=60
    )
    worker.wait_until_succeeds(
        "systemctl is-active aos-pkg-k3s-worker.target", timeout=60
    )

    # ── Pre-flight on each machine ─────────────────────────────────
    # k3s-preflight is a oneshot — `is-active` returns "active"
    # only after exit-0. A failure here means either the baked env
    # file is missing (ConditionPathExists short-circuits the unit
    # to "skipped", which is-active reports as "inactive"), or
    # systemd's EnvironmentFile= parser rejected the file's
    # contents, or one of the required vars is empty.
    controlplane.wait_until_succeeds(
        "systemctl is-active k3s-preflight.service", timeout=60
    )
    worker.wait_until_succeeds(
        "systemctl is-active k3s-preflight.service", timeout=60
    )

    # ── Control-plane service active ────────────────────────────────
    # `Type=notify` flips active once k3s emits READY=1 on its
    # sd_notify socket. For `--disable-agent`, that's apiserver +
    # startup-hooks ready. On 2-vCPU VMs cert-gen + apiserver
    # bootstrap typically takes 60-120s; the timeout below has
    # slack for a slow runner.
    wait_unit_active(controlplane, "k3s.service", timeout=240)

    # ── Apiserver reachable + healthy on the control plane ────────
    # /healthz returns the literal string "ok" when the apiserver
    # is fully up. We don't `kubectl get componentstatuses` because
    # k3s lies about scheduler/controller-manager component health
    # in some versions — /healthz is the load-bearing probe.
    #
    # k3s 1.35 (kubernetes 1.35) returns 401 to anonymous requests
    # against /healthz; the apiserver routes it through the auth
    # chain and `--anonymous-auth=false` is the new default. So we
    # probe via `kubectl get --raw=/healthz`, which authenticates
    # using the admin client cert from /etc/rancher/k3s/k3s.yaml
    # — same endpoint, same response body, just past the authn
    # gate.
    controlplane.wait_until_succeeds(
        "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get --raw=/healthz | grep -qx 'ok'",
        timeout=60,
    )

    # ── Worker service active ───────────────────────────────────────
    try:
        wait_unit_active(worker, "k3s.service", timeout=240)
    except Exception:
        dump_unit(controlplane, "k3s.service")
        print("--- controlplane: listeners ---")
        print(controlplane.succeed("${pkgs.iproute2}/sbin/ss -ltnp 2>&1 || true"))
        print("--- controlplane: nft ruleset ---")
        print(controlplane.succeed("${pkgs.nftables}/sbin/nft list ruleset 2>&1 || true"))
        print("--- worker: host resolution ---")
        print(worker.succeed("cat /etc/hosts 2>&1 || true"))
        print("--- worker: tcp probe 192.168.50.10:6443 ---")
        print(
            worker.succeed(
                "${pkgs.coreutils}/bin/timeout 5 ${pkgs.bash}/bin/bash -c '</dev/tcp/192.168.50.10/6443' 2>&1 || true"
            )
        )
        raise

    # ── Worker registered + Ready ─────────────────────────────────
    # With `--disable-agent`, the control-plane is invisible in
    # `kubectl get nodes` — only the worker registers. Asserting
    # the worker reaches Ready proves the full join round-trip:
    # token verified, TLS verified against the server SAN list,
    # agent pulled flannel config from the apiserver, kubelet
    # started, configureNode wrote the Node object.
    controlplane.wait_until_succeeds(
        r"""${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml \
            get node worker \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' \
            | grep -Fxq True""",
        timeout=180,
    )

    # ── Sanity: exactly one Node exists ───────────────────────────
    # The bash-escape gymnastics around `\$(…)` are gone: Python
    # strings are not subject to host-side shell expansion, so the
    # command we write is the command the agent runs.
    out = controlplane.succeed(
        "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get nodes --no-headers"
    )
    assert len(out.splitlines()) == 1, (
        f"expected exactly one node (control-plane is invisible by design),"
        f" got {out!r}"
    )
  '';
}
