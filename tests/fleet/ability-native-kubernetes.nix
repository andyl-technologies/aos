##! Signed K3s bootstrap and Kubernetes-object activation acceptance.
{
  lib,
  mkSystem,
  pkgs,
}: let
  fixture = import ./_kubernetes-runtime-reference.nix {
    inherit lib mkSystem pkgs;
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
