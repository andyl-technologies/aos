# tests/fleet/k3s-control-plane-worker.nix — Two-machine smoke test
# for the k3s-control-plane + k3s-worker pair.
#
# Topology:
#   controlplane: pkgs.k3s-control-plane (k3s server --disable-agent)
#   worker:       pkgs.k3s-worker        (k3s agent)
#
# Both use the package-owned typed k3s module. The shared join token is
# generated after boot and resolved through an opaque system-credential
# reference; its bytes never enter the Nix store.
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
  timeout = 1200;

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
    };

    worker = {
      system = workerSystem;
      packages = ["k3s-worker"];
    };
  };

  testScript = ''
    import base64
    import shlex

    APM = "${pkgs.aos}/bin/apm"


    def apply_k3s_module(machine, name, module):
        encoded = base64.b64encode(module.encode()).decode()
        path = f"/run/{name}.nix"
        cache = f"/run/{name}-cache"
        machine.succeed(
            f"mkdir -p {cache} && "
            f"printf '%s' '{encoded}' | base64 -d > {path} && "
            f"XDG_CACHE_HOME={cache} {APM} config add "
            f"{path} --name {name}.nix && "
            f"XDG_CACHE_HOME={cache} {APM} config apply "
            f"--eval-root /run/{name}-eval || {{ "
            "systemctl status --no-pager -l aos-activate.service; "
            "journalctl -u aos-activate.service --no-pager -n 200; "
            "exit 1; }",
            timeout=600,
        )


    # Generate the token inside the control-plane guest and copy it to the
    # worker's platform credential namespace through the test channel.
    token = controlplane.succeed(
        "${pkgs.coreutils}/bin/head -c 24 /dev/urandom | "
        "${pkgs.coreutils}/bin/od -An -tx1 | "
        "${pkgs.coreutils}/bin/tr -d ' \\n'"
    ).strip()
    assert len(token) == 48, token
    for machine in (controlplane, worker):
        machine.succeed(
            "mkdir -p /run/credentials/@system && "
            f"printf %s {shlex.quote(token)} > "
            "/run/credentials/@system/k3s-token && "
            "chmod 0600 /run/credentials/@system/k3s-token"
        )

    controlplane.wait_until_succeeds(
        "systemctl is-active --quiet aos-config.target", timeout=300
    )
    worker.wait_until_succeeds(
        "systemctl is-active --quiet aos-config.target", timeout=300
    )

    # The fleet test network is intentionally gateway-less. k3s still requires
    # a default route while discovering the host interface, even when node-ip
    # and flannel-iface are pinned, so provide a link-scope route for discovery.
    for machine in (controlplane, worker):
        machine.succeed("${pkgs.iproute2}/sbin/ip route replace default dev eth0")

    apply_k3s_module(controlplane, "k3s-control-plane", """{
      aos.apm.desiredPackages = [ "k3s-control-plane" ];
      k3s = {
        enable = true;
        token.ref = "system-credential:k3s-token";
        node.ip = "192.168.50.10";
        networking.flannelInterface = "eth0";
      };
    }
    """)
    apply_k3s_module(worker, "k3s-worker", """{
      aos.apm.desiredPackages = [ "k3s-worker" ];
      k3s = {
        enable = true;
        serverUrl = "https://192.168.50.10:6443";
        token.ref = "system-credential:k3s-token";
        node = {
          name = "worker";
          ip = "192.168.50.11";
        };
        networking.flannelInterface = "eth0";
      };
    }
    """)

    for machine, package in (
        (controlplane, "k3s-control-plane"),
        (worker, "k3s-worker"),
    ):
        source = f"/run/credstore/{package}/token"
        machine.succeed(f"test -s {source} && test $(stat -c %a {source}) = 600")
        manifest = machine.succeed("cat /run/aos/manifest.json")
        assert token not in manifest, "cluster token leaked into the manifest"


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
    # only after exit-0. A failure here means the package-owned
    # projection or the resolved token credential is unavailable.
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
