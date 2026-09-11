##! Signed K3s bootstrap and Kubernetes-object activation acceptance.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
in {
  name = "ability-native-kubernetes";
  timeout = 4800;
  bootTimeout = 600;

  machines.runtime = {
    system = fixture.runtimeSystem;
    extraClosures = fixture.extraClosures;
    varSizeMiB = 12288;
    memoryMiB = 6144;
  };

  testScript =
    fixture.testPrelude
    + # python
    ''
      def prepare_activation(
          label, replicas, include_longhorn, fault=None, authorize=True
      ):
          output = f"/run/kubernetes-activation-{label}"
          authority = f"/run/kubernetes-authority-{label}"
          activation = generate_kubernetes_activation(
              output, replicas, include_longhorn, authority, fault
          )
          if authorize:
              provision_kubernetes_authority(activation, authority)
          host = f"/run/kubernetes-host-{label}.nix"
          write_kubernetes_host(host, activation)
          return activation, host


      def native_resource_map(activation):
          sidecar = activation["authenticated_policy_set"]
          path = f"{sidecar['store_path']}/{sidecar['document']}"
          policy = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(path)}"
          ))
          return policy["native_resource_map"]


      def helm_chart(name):
          return json.loads(kubectl(
              f"get helmchart.helm.cattle.io {shlex.quote(name)} "
              "-n kube-system -o json"
          ))


      def expected_object_evidence(native_map):
          evidence = {}
          for mapping in native_map["entries"]:
              qualification = mapping["qualification"]
              if qualification["kind"] != "kubernetes-object":
                  continue
              owner_input = (
                  b"aos.ability.kubernetes-object-owner/v1\0"
                  + json.dumps(
                      mapping["resource"], sort_keys=True, separators=(",", ":")
                  ).encode()
              )
              evidence[qualification["name"]] = {
                  "revision": mapping["revision"],
                  "owner": "sha256:" + hashlib.sha256(owner_input).hexdigest(),
              }
          return evidence


      def owned_projection(chart):
          annotations = chart["metadata"]["annotations"]
          return {
              "apiVersion": chart["apiVersion"],
              "kind": chart["kind"],
              "name": chart["metadata"]["name"],
              "namespace": chart["metadata"]["namespace"],
              "uid": chart["metadata"]["uid"],
              "revision": annotations["aos.andyl.com/object-revision"],
              "owner": annotations["aos.andyl.com/resource-owner"],
              "spec": chart["spec"],
          }


      def retained_transactions(generation):
          root = f"/var/lib/profiles/system/gen-{generation}/ability-transactions"
          output = runtime.succeed(
              f"${pkgs.findutils}/bin/find {root} -mindepth 2 -maxdepth 2 "
              "-name plan-bundle.json -type f -print"
          ).splitlines()
          return {path.rsplit("/", 2)[-2]: path for path in output}


      def assert_no_independent_containerd_start():
          properties = runtime.succeed(
              "systemctl show -p LoadState -p ExecMainStartTimestampMonotonic "
              "containerd.service"
          )
          observed = dict(
              line.split("=", 1) for line in properties.splitlines() if "=" in line
          )
          assert observed["LoadState"] == "not-found" or (
              observed["ExecMainStartTimestampMonotonic"] == "0"
          ), observed


      def assert_kubernetes_runtime_pristine(expected_generation):
          generation = int(runtime.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())
          assert generation == expected_generation, (generation, expected_generation)
          for unit in ("k3s.service", "containerd.service"):
              properties = runtime.succeed(
                  "systemctl show "
                  "-p LoadState -p ActiveState -p SubState "
                  "-p ExecMainStartTimestampMonotonic "
                  + shlex.quote(unit)
              )
              observed = dict(
                  line.split("=", 1)
                  for line in properties.splitlines()
                  if "=" in line
              )
              assert observed["ActiveState"] == "inactive", (unit, observed)
              assert observed["SubState"] == "dead", (unit, observed)
              assert observed["ExecMainStartTimestampMonotonic"] == "0", (
                  unit,
                  observed,
              )
              journal = runtime.succeed(
                  f"journalctl --quiet --output=cat --unit {shlex.quote(unit)}"
              )
              assert journal == "", (unit, journal)
          runtime.fail("test -e /etc/rancher/k3s/k3s.yaml")
          runtime.fail("test -e /var/lib/rancher/k3s")


      def assert_planning_rejection(label, fault, expected_code, expected_reason):
          output = f"/run/kubernetes-activation-{label}"
          authority = f"/run/kubernetes-authority-{label}"
          reset_kubernetes_activation_paths(output, authority)
          status, stdout, stderr = runtime.execute(
              kubernetes_activation_command(
                  output, 1, True, authority, fault
              ),
              timeout=1200,
          )
          assert status != 0, (status, stdout, stderr)
          evidence_path = f"{output}/planning-rejection.json"
          evidence = json.loads(runtime.succeed(
              f"{COREUTILS}/cat {shlex.quote(evidence_path)}"
          ))
          assert evidence["schema"] == (
              "aos.test.kubernetes-planning-rejection/v1"
          ), evidence
          assert evidence["fault"] == expected_code, evidence
          assert evidence["disposition"] == "rejected-before-effect-plan", evidence
          assert expected_reason in evidence["diagnostic"], evidence
          expected_stderr = (
              "Kubernetes planning rejected before effect plan "
              f"({expected_code}): {evidence['diagnostic']}"
          )
          assert expected_stderr in stderr, (expected_stderr, stderr)
          assert evidence["bounds"]["maximum_rounds"] == 64, evidence
          assert evidence["bounds"]["maximum_entries"] == 1_000_000, evidence
          assert evidence["bounds"]["maximum_bytes"] == 32 * 1024 * 1024, evidence
          assert evidence["bounds"]["retained_rounds"] == len(evidence["trace"])
          assert 0 < len(evidence["trace"]) <= 64, evidence
          assert evidence["seed"] == evidence["trace"][0]["desired_state"], evidence
          assert evidence["seed_digest"] == (
              evidence["trace"][0]["desired_state_digest"]
          ), evidence
          retained_entries = 0
          for entry in evidence["trace"]:
              assert entry["desired_state"]["environment"] == (
                  evidence["environment_digest"]
              ), entry
              assert entry["policy"]["desired_state"] == (
                  entry["desired_state_digest"]
              ), entry
              assert entry["policy"]["environment"] == (
                  evidence["environment_digest"]
              ), entry
              retained_entries += len(entry["attempted_selections"])
              if entry["result"]["status"] == "resolved":
                  retained_entries += len(entry["result"]["decisions"])
                  retained_entries += len(entry["result"]["bindings"])
                  retained_entries += len(entry["result"]["recursive_lineage"])
          assert evidence["bounds"]["retained_entries"] == retained_entries, evidence
          assert retained_entries <= evidence["bounds"]["maximum_entries"], evidence
          runtime.fail(f"test -e {shlex.quote(output + '/activation.json')}")
          runtime.fail(f"test -e {shlex.quote(output + '/desired.json')}")
          runtime.fail(f"test -e {shlex.quote(output + '/policy.json')}")
          return evidence


      runtime.wait_until_succeeds(
          "systemctl is-active --quiet aos-config.target", timeout=300
      )
      runtime.succeed("${pkgs.iproute2}/sbin/ip route replace default dev eth0")
      runtime.succeed(
          f"{COREUTILS}/install -d -o root -g root -m 0700 "
          "/run/credstore/k3s-combined && "
          f"{COREUTILS}/install -o root -g root -m 0600 /dev/null "
          "/run/credstore/k3s-combined/token && "
          f"{COREUTILS}/printf '%s' ability-kubernetes-token "
          "> /run/credstore/k3s-combined/token"
      )
      runtime.fail("systemctl is-active --quiet k3s.service")
      runtime.fail("systemctl is-active --quiet containerd.service")
      assert_no_independent_containerd_start()
      runtime.fail("test -e /etc/rancher/k3s/k3s.yaml")

      publish_kubernetes_packages()

      pristine_generation = int(runtime.succeed(
          f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
      ).strip())
      missing_bootstrap = assert_planning_rejection(
          "missing-bootstrap",
          "missing-systemd-bootstrap",
          "missing-available-systemd-bootstrap-root",
          "binding has no exact usable environment inventory or desired-package "
          "provider evidence",
      )
      assert missing_bootstrap["cycle"] is None, missing_bootstrap
      assert missing_bootstrap["trace"][-1]["result"]["status"] == "rejected", (
          missing_bootstrap
      )
      assert not any(
          provider["interface"]["name"] == "aos.systemd-provider-bootstrap"
          for provider in missing_bootstrap["environment"]["providers"]
      ), missing_bootstrap
      assert not any(
          provider["state"] == "Available"
          for provider in missing_bootstrap["environment"]["providers"]
      ), missing_bootstrap
      assert_kubernetes_runtime_pristine(pristine_generation)

      cyclic_bootstrap = assert_planning_rejection(
          "cyclic-bootstrap",
          "cyclic-k3s-bootstrap",
          "cyclic-k3s-bootstrap-lineage",
          "provider dependency lineage contains a cycle",
      )
      cycle = cyclic_bootstrap["cycle"]
      assert cycle is not None, cyclic_bootstrap
      assert len(cycle["nodes"]) == 1, cycle
      assert len(cycle["edges"]) == 1, cycle
      cycle_edge = cycle["edges"][0]
      assert cycle_edge["consumer"] == cycle_edge["provider"], cycle_edge
      assert cycle_edge["request"]["key"] == "bootstrap-lineage-cycle", cycle_edge
      assert cycle_edge["interface"]["name"] == "aos.k3s-cluster", cycle_edge
      cycle_provider_states = {
          (provider["interface"]["name"], provider["state"])
          for provider in cyclic_bootstrap["environment"]["providers"]
      }
      assert (
          "aos.systemd-provider-bootstrap", "Available"
      ) in cycle_provider_states, cycle_provider_states
      assert (
          "aos.kubernetes-object-effects", "Planned"
      ) in cycle_provider_states, cycle_provider_states
      assert_kubernetes_runtime_pristine(pristine_generation)

      activation_v1, host_v1 = prepare_activation("v1", 1, True)
      mapping_v1 = native_resource_map(activation_v1)
      service_mappings = [
          entry for entry in mapping_v1["entries"]
          if entry["qualification"]["kind"] == "systemd-service"
      ]
      assert len(service_mappings) == 1, service_mappings
      assert "consumer_observation" not in service_mappings[0]["qualification"], (
          service_mappings
      )
      assert {
          entry["qualification"]["name"] for entry in mapping_v1["entries"]
          if entry["qualification"]["kind"] == "kubernetes-object"
      } == {"cilium", "longhorn"}, mapping_v1

      generation_v1 = switch_kubernetes_host(host_v1, "v1")
      assert generation_v1 > 0, generation_v1
      runtime.wait_until_succeeds(
          "systemctl is-active --quiet k3s.service", timeout=300
      )
      runtime.wait_until_succeeds(
          f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get --raw=/healthz | ${pkgs.grep}/bin/grep -qx ok",
          timeout=180,
      )
      runtime.wait_until_succeeds(
          f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get helmchart.helm.cattle.io cilium -n kube-system -o json",
          timeout=180,
      )
      runtime.wait_until_succeeds(
          f"{KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get helmchart.helm.cattle.io longhorn -n kube-system -o json",
          timeout=180,
      )
      cilium_v1 = helm_chart("cilium")
      longhorn_v1 = helm_chart("longhorn")
      expected_v1 = expected_object_evidence(mapping_v1)
      assert "replicas: 1" in cilium_v1["spec"]["valuesContent"], cilium_v1
      assert longhorn_v1["spec"]["chart"] == "longhorn", longhorn_v1
      for name, chart in (("cilium", cilium_v1), ("longhorn", longhorn_v1)):
          annotations = chart["metadata"]["annotations"]
          assert annotations["aos.andyl.com/object-revision"] == (
              expected_v1[name]["revision"]
          ), (annotations, expected_v1[name])
          assert annotations["aos.andyl.com/resource-owner"] == (
              expected_v1[name]["owner"]
          ), (annotations, expected_v1[name])

      # Each forged policy is authorized as a test input, then rejected before
      # it can alter either admitted object.
      admitted_v1 = {
          "cilium": owned_projection(cilium_v1),
          "longhorn": owned_projection(longhorn_v1),
      }
      for fault in ("mapping-namespace", "mapping-kind", "resource-grant"):
          invalid_activation, invalid_host = prepare_activation(
              f"invalid-{fault}", 9, True, fault
          )
          runtime.fail(
              f"{APM} switch --from {shlex.quote(invalid_host)} "
              f"--eval-root /run/kubernetes-invalid-{fault}",
              timeout=1200,
          )
          assert owned_projection(helm_chart("cilium")) == admitted_v1["cilium"]
          assert owned_projection(helm_chart("longhorn")) == admitted_v1["longhorn"]
      runtime.succeed(
          f"result=$({KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get helmchart.helm.cattle.io cilium -n default "
          "--ignore-not-found=true -o name) && test -z \"$result\""
      )
      runtime.succeed(
          f"result=$({KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get configmap cilium -n kube-system "
          "--ignore-not-found=true -o name) && test -z \"$result\""
      )

      # A signed package can compose a canonical cluster-scoped RBAC object,
      # but the existing operator grant authorizes only the exact admitted map.
      cluster_activation, cluster_host = prepare_activation(
          "cluster-rbac", 9, True, "cluster-rbac", authorize=False
      )
      cluster_map = native_resource_map(cluster_activation)
      cluster_mapping = next(
          entry for entry in cluster_map["entries"]
          if entry["resource"]["key"] == "cilium-helmchart"
      )
      v1_cilium_mapping = next(
          entry for entry in mapping_v1["entries"]
          if entry["resource"]["key"] == "cilium-helmchart"
      )
      assert cluster_mapping["resource"] == v1_cilium_mapping["resource"]
      assert cluster_mapping["qualification"]["api_version"] == (
          "rbac.authorization.k8s.io/v1"
      )
      assert cluster_mapping["qualification"]["object_kind"] == "ClusterRole"
      assert cluster_mapping["qualification"]["namespace"] is None
      assert cluster_mapping["qualification"]["name"] == (
          "aos-forbidden-cluster-role"
      )
      admitted_digest = activation_v1["authenticated_policy_set"][
          "document_sha256"
      ].removeprefix("sha256:")
      cluster_digest = cluster_activation["authenticated_policy_set"][
          "document_sha256"
      ].removeprefix("sha256:")
      assert cluster_digest != admitted_digest
      runtime.succeed(
          f"test -f /var/lib/aos/ability-authority/policy-sets/"
          f"{admitted_digest}.json"
      )
      runtime.fail(
          f"test -e /var/lib/aos/ability-authority/policy-sets/"
          f"{cluster_digest}.json"
      )
      transactions_before_cluster = retained_transactions(generation_v1)
      status, stdout, stderr = runtime.execute(
          f"{APM} switch --from {shlex.quote(cluster_host)} "
          "--eval-root /run/kubernetes-invalid-cluster-rbac",
          timeout=1200,
      )
      assert status != 0, (status, stdout, stderr)
      assert (
          "authenticating native policy set through operator authority"
          in stdout + stderr
      ), (stdout, stderr)
      generation_after_cluster = int(runtime.succeed(
          f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
      ).strip())
      assert generation_after_cluster == generation_v1, (
          generation_v1,
          generation_after_cluster,
      )
      assert retained_transactions(generation_v1) == transactions_before_cluster
      assert owned_projection(helm_chart("cilium")) == admitted_v1["cilium"]
      assert owned_projection(helm_chart("longhorn")) == admitted_v1["longhorn"]
      runtime.succeed(
          f"result=$({KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get clusterrole aos-forbidden-cluster-role "
          "--ignore-not-found=true -o name) && test -z \"$result\""
      )

      invocation_v1 = runtime.succeed(
          "systemctl show -p InvocationID --value k3s.service"
      ).strip()
      activation_v2, host_v2 = prepare_activation("v2", 2, True)
      mapping_v2 = native_resource_map(activation_v2)
      generation_v2 = switch_kubernetes_host(host_v2, "v2")
      assert generation_v2 > generation_v1, (generation_v1, generation_v2)
      invocation_v2 = runtime.succeed(
          "systemctl show -p InvocationID --value k3s.service"
      ).strip()
      assert invocation_v2 == invocation_v1, (invocation_v1, invocation_v2)
      cilium_v2 = helm_chart("cilium")
      longhorn_v2 = helm_chart("longhorn")
      expected_v2 = expected_object_evidence(mapping_v2)
      assert "replicas: 2" in cilium_v2["spec"]["valuesContent"], cilium_v2
      assert cilium_v2["metadata"]["uid"] == cilium_v1["metadata"]["uid"], (
          cilium_v1,
          cilium_v2,
      )
      assert longhorn_v2["metadata"]["uid"] == longhorn_v1["metadata"]["uid"], (
          longhorn_v1,
          longhorn_v2,
      )
      for name, chart in (("cilium", cilium_v2), ("longhorn", longhorn_v2)):
          annotations = chart["metadata"]["annotations"]
          assert annotations["aos.andyl.com/object-revision"] == (
              expected_v2[name]["revision"]
          ), (annotations, expected_v2[name])
          assert annotations["aos.andyl.com/resource-owner"] == (
              expected_v2[name]["owner"]
          ), (annotations, expected_v2[name])

      # Replaying the same desired content takes the retained native no-op path.
      transactions_before_no_op = retained_transactions(generation_v2)
      generation_no_op = switch_kubernetes_host(host_v2, "v2-no-op")
      assert generation_no_op == generation_v2, (generation_v2, generation_no_op)
      transactions_after_no_op = retained_transactions(generation_v2)
      new_transactions = transactions_after_no_op.keys() - transactions_before_no_op.keys()
      assert len(new_transactions) == 1, new_transactions
      no_op_transaction = next(iter(new_transactions))
      no_op_bundle_path = transactions_after_no_op[no_op_transaction]
      no_op_bundle = json.loads(runtime.succeed(
          f"{COREUTILS}/cat {shlex.quote(no_op_bundle_path)}"
      ))
      assert no_op_bundle["transition"]["effect_document"]["operations"] == [], (
          no_op_bundle
      )
      no_op_root = no_op_bundle_path.rsplit("/", 1)[0]
      marker = json.loads(runtime.succeed(
          f"{COREUTILS}/cat "
          f"{shlex.quote(no_op_root + '/native-no-op-verification.json')}"
      ))
      assert marker["transaction"] == no_op_transaction, marker
      invocation_no_op = runtime.succeed(
          "systemctl show -p InvocationID --value k3s.service"
      ).strip()
      assert invocation_no_op == invocation_v1, (invocation_v1, invocation_no_op)
      assert "replicas: 2" in helm_chart("cilium")["spec"]["valuesContent"]
      assert helm_chart("longhorn")["metadata"]["uid"] == longhorn_v1["metadata"]["uid"]

      activation_v3, host_v3 = prepare_activation("v3", 2, False)
      generation_v3 = switch_kubernetes_host(host_v3, "v3")
      assert generation_v3 > generation_v2, (generation_v2, generation_v3)
      runtime.wait_until_succeeds(
          f"result=$({KUBECTL} --kubeconfig=/etc/rancher/k3s/k3s.yaml "
          "get helmchart.helm.cattle.io longhorn -n kube-system "
          "--ignore-not-found=true -o name) && test -z \"$result\"",
          timeout=180,
      )
      assert "replicas: 2" in helm_chart("cilium")["spec"]["valuesContent"]
      assert runtime.succeed(
          "systemctl show -p InvocationID --value k3s.service"
      ).strip() == invocation_v1
      runtime.fail("systemctl is-active --quiet containerd.service")
      assert_no_independent_containerd_start()
    '';
  }
  // lib.optionalAttrs qualificationImage {
    qualification = {
      candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
      extraClosures = fixture.extraClosures;
      setupBody = fixture.qualificationSetupBody;
    };
  }
