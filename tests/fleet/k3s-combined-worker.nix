# tests/fleet/k3s-combined-worker.nix — Two-machine smoke test for
# the k3s-combined + k3s-worker pair.
#
# Topology:
#   combined: aos.roles.k3s-combined (k3s server, no --disable-agent)
#   worker:   aos.roles.k3s-worker   (k3s agent)
#
# Combined plays both control-plane and worker; worker joins
# pointing at combined's hostname. Functionally a 2-node cluster
# where one node also runs the API server.
{
  pkgs,
  systems,
  ...
}: let
  # k3s's token parser (`pkg/clientaccess/token.go:251`) accepts:
  #   - a kubeadm bootstrap token: `[a-z0-9]{6}\.[a-z0-9]{16}`
  #   - a `username:password` pair (basic auth)
  #   - the same forms wrapped in a `K10[<ca-hash>]::<creds>` shell
  # ...but `k3s server` then runs `pkg/util.NormalizeToken` on the
  # K3S_TOKEN, which rejects anything that comes out of the parser
  # as a `BootstrapTokenString` (kubeadm form) — leaving it with
  # only basic-auth shapes:
  #   - `<password>`
  #   - `K10<CA-HASH>::<USERNAME>:<PASSWORD>`
  # We use a bare password here. The parser wraps it as
  # `K10:::<password>`, splits to caHash="" + creds=":<password>",
  # falls back to username:password split → ("", "<password>"), and
  # NormalizeToken takes the password.
  testToken = "aoscombinedfleettoken1";

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
  # in as if they were CLI flags. We use it to pin `node-ip` and
  # `flannel-iface` per machine without having to bake them into
  # the role's ExecStart (the role is image-shared and doesn't
  # know the IP or interface name).
  #
  # See `tests/fleet/k3s-control-plane-worker.nix` for the longer
  # rationale on both pins; the same gateway-less fleet harness
  # forces the same workaround here. Both `combined` (running
  # `k3s server` without `--disable-agent`) and `worker` run the
  # flannel daemon, so both need the iface pin.
  configFile = ip: {
    path = "/etc/rancher/k3s/config.yaml";
    mode = 420; # 0644
    overwrite = true;
    contents.source =
      "data:,"
      + uriEncode ''
        node-ip: ${ip}
        flannel-iface: eth0
      '';
  };
in {
  name = "k3s-combined-worker";
  timeout = 360;

  # The fleet harness in lib/testing/fleet.nix assigns
  # `192.168.50.${i + 10}` per machine via `lib.imap` over
  # `builtins.attrNames machines`. `builtins.attrNames` is
  # specified to return names in lexicographic order, so the
  # mapping is deterministic and depends only on the attribute
  # names — `combined` < `worker`, so combined→.10, worker→.11.
  machines = {
    combined = {
      system = systems.server;
      roles = ["k3s-combined"];
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
          K3S_URL=https://combined:6443
        '')
        (configFile "192.168.50.11")
      ];
    };
  };

  testScript = ''
    # ── Pre-flight ─────────────────────────────────────────────────
    wait_until_succeeds_on combined \
      "systemctl is-active k3s-preflight.service" 60 \
      "combined k3s-preflight reaches active"

    wait_until_succeeds_on worker \
      "systemctl is-active k3s-preflight.service" 60 \
      "worker k3s-preflight reaches active"

    # ── k3s.service active on both ─────────────────────────────────
    # `Type=notify` on combined waits for apiserver+kubelet+node-
    # registration (not just apiserver, like the --disable-agent
    # case in k3s-control-plane-worker.nix), so 240s gives the same
    # slack we used there.
    wait_until_succeeds_on combined \
      "systemctl is-active k3s.service" 240 \
      "combined k3s.service reaches active"

    wait_until_succeeds_on worker \
      "systemctl is-active k3s.service" 240 \
      "worker k3s.service reaches active"

    # ── Both nodes Ready ───────────────────────────────────────────
    # `grep -Fxq True` (fixed-string, full-line, quiet) requires
    # the kubectl jsonpath output to BE exactly `True`, not just
    # contain it — guards against jsonpath ever expanding to e.g.
    # `[True]` and matching loosely.
    wait_until_succeeds_on combined \
      "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get node combined -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -Fxq True" \
      180 \
      "combined node Ready (server + agent on same host)"

    wait_until_succeeds_on combined \
      "${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get node worker -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -Fxq True" \
      180 \
      "worker node Ready"

    # ── Combined node is schedulable ──────────────────────────────
    # `k3s server` (without --disable-agent) does NOT add the
    # control-plane:NoSchedule taint by default — the whole point
    # of combined is co-locating workloads on the control-plane.
    # We assert the taints field is absent: kubectl's jsonpath
    # prints the empty string when `.spec.taints` is unset.
    # `assert_on … "test -z"` checks the captured output is empty;
    # `assert_output_on machine cmd ""` would have used
    # `grep -q ""`, which matches any non-empty input — exactly
    # backwards from the intent.
    #
    # `\$(…)` (and `\"`) defer command substitution until the
    # guest shell — see the parallel note in
    # `k3s-control-plane-worker.nix`. Without the escape this
    # silently passed for the wrong reason: kubectl ran (and
    # failed) on the build host, the substitution produced an
    # empty string, and `test -z ""` was trivially true.
    assert_on combined \
      "test -z \"\$(${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get node combined -o jsonpath='{.spec.taints}')\"" \
      "combined node has no NoSchedule taint"

    # ── Sanity: exactly two nodes ─────────────────────────────────
    # Numeric equality, not substring match — see the rationale in
    # k3s-control-plane-worker.nix's testScript. The `\$(…)` escape
    # is for the same outer-shell substitution reason documented
    # in that file.
    assert_on combined \
      "test \$(${pkgs.k3s}/bin/kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml get nodes --no-headers | wc -l) -eq 2" \
      "exactly two nodes registered"
  '';
}
