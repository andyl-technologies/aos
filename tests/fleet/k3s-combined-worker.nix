# tests/fleet/k3s-combined-worker.nix — Two-machine smoke test for
# the k3s-combined + k3s-worker pair.
#
# Topology:
#   combined: pkgs.k3s-combined (k3s server, no --disable-agent)
#   worker:   pkgs.k3s-worker   (k3s agent)
#
# Combined plays both control-plane and worker; worker joins
# pointing at combined's harness-assigned IP. Functionally a
# 2-node cluster where one node also runs the API server.
{
  dataUrl,
  mkSystem,
  pkgs,
  lib,
  ...
}: let
  workloadImage = import ../../lib/testing/k3s-workload-image.nix {inherit pkgs lib;};
  combinedSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.k3s-combined = {
        package = pkgs.k3s-combined;
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
  name = "k3s-combined-worker";
  timeout = 1200;

  # The fleet harness in lib/testing/fleet.nix assigns
  # `192.168.50.${i + 10}` per machine via `lib.imap` over
  # `builtins.attrNames machines`. `builtins.attrNames` is
  # specified to return names in lexicographic order, so the
  # mapping is deterministic and depends only on the attribute
  # names — `combined` < `worker`, so combined→.10, worker→.11.
  machines = {
    combined = {
      system = combinedSystem;
      packages = ["k3s-combined"];
      extraClosures = [workloadImage];
      # Containerd retains both image content and writable snapshots in /var.
      varSizeMiB = 4096;
    };

    worker = {
      system = workerSystem;
      packages = ["k3s-worker"];
      extraClosures = [workloadImage];
      varSizeMiB = 4096;
    };
  };

  testScript = ''
    ${builtins.readFile ../../lib/testing/k3s-lifecycle.py}

    import base64
    import shlex

    APM = "${pkgs.aos.apm}/bin/apm"


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


    # Generate the shared join token only after boot, then publish it through
    # each machine's platform system-credential namespace. The typed k3s
    # module carries only the opaque reference.
    token = combined.succeed(
        "${pkgs.coreutils}/bin/head -c 24 /dev/urandom | "
        "${pkgs.coreutils}/bin/od -An -tx1 | "
        "${pkgs.coreutils}/bin/tr -d ' \\n'"
    ).strip()
    assert len(token) == 48, token
    for machine in (combined, worker):
        machine.succeed(
            "mkdir -p /run/credentials/@system && "
            f"printf %s {shlex.quote(token)} > "
            "/run/credentials/@system/k3s-token && "
            "chmod 0600 /run/credentials/@system/k3s-token"
        )

    combined.wait_until_succeeds(
        "systemctl is-active --quiet aos-config.target", timeout=300
    )
    worker.wait_until_succeeds(
        "systemctl is-active --quiet aos-config.target", timeout=300
    )

    # The fleet test network is intentionally gateway-less. k3s still requires
    # a default route while discovering the host interface, even when node-ip
    # and flannel-iface are pinned, so provide a link-scope route for discovery.
    for machine in (combined, worker):
        machine.succeed("${pkgs.iproute2}/sbin/ip route replace default dev eth0")

    apply_k3s_module(combined, "k3s-combined", """{
      aos.apm.desiredPackages = [ "k3s-combined" ];
      k3s = {
        enable = true;
        token.ref = "system-credential:k3s-token";
        node = {
          name = "combined";
          ip = "192.168.50.10";
        };
        networking.flannelInterface = "eth0";
        integrations.resources.aos-contract = {
          priority = 10;
          content = "apiVersion: v1\\nkind: Namespace\\nmetadata:\\n  name: aos-runtime-addon-contract\\n";
        };
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
        (combined, "k3s-combined"),
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
    combined.wait_until_succeeds(
        "systemctl is-active aos-pkg-k3s-combined.target", timeout=60
    )
    worker.wait_until_succeeds(
        "systemctl is-active aos-pkg-k3s-worker.target", timeout=60
    )

    # ── Pre-flight ─────────────────────────────────────────────────
    combined.wait_until_succeeds(
        "systemctl is-active k3s-preflight.service", timeout=60
    )
    worker.wait_until_succeeds(
        "systemctl is-active k3s-preflight.service", timeout=60
    )

    # ── Combined server active ──────────────────────────────────────
    # `Type=notify` on combined waits for apiserver+kubelet+node-
    # registration (not just apiserver, like the --disable-agent
    # case in k3s-control-plane-worker.nix), so 240s gives the same
    # slack we used there.
    wait_unit_active(combined, "k3s.service", timeout=240)

    combined.wait_until_succeeds(
        "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml "
        "get namespace aos-runtime-addon-contract",
        timeout=120,
    )

    # ── Worker service active ───────────────────────────────────────
    wait_unit_active(worker, "k3s.service", timeout=240)

    assert_k3s_cluster(combined, "${pkgs.k3s}/bin/kubectl", ["combined", "worker"], combined_node="combined")
    assert_k3s_default_addons(combined, "${pkgs.k3s}/bin/kubectl")
    assert_k3s_addon_services(
        combined,
        "${pkgs.k3s}/bin/kubectl",
        "${pkgs.k3s}/share/k3s/aos-addon-images.json",
        "worker",
        "qualification-addon-services",
    )

    manifest_hash = worker.succeed(
        "${pkgs.coreutils}/bin/sha256sum ${workloadImage}/manifest.json"
    ).split()[0]
    for node_name, machine in (("combined", combined), ("worker", worker)):
        import_k3s_workload(
            machine,
            "${pkgs.k3s}/bin/ctr",
            "${pkgs.k3s}/bin/crictl",
            "${workloadImage}/image.oci.tar",
            "aos.invalid/qualification@sha256:" + manifest_hash,
        )
        assert_k3s_workload(
            combined,
            "${pkgs.k3s}/bin/kubectl",
            "aos.invalid/qualification@sha256:" + manifest_hash,
            ["${pkgs.coreutils}/bin/printf", "k3s-workload-passed\n"],
            "k3s-workload-passed\n",
            node_name,
            "qualification-workload-" + node_name,
        )
  '';
}
