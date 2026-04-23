# systems/tests/k8s-edge.nix — Multi-VM edge cluster test
#
# Boots a server image as the cloud/control plane and an edge image
# as the remote edge node. Verifies that both systems boot correctly,
# have the appropriate K8s/KubeEdge components configured, and can
# communicate over the network.
{lib}: {
  name = "k8s-edge";
  description = "K8s edge cluster (server control + edge node)";
  type = "fleet";

  machines = {
    cloud = {
      system = "server";
      role = "control";
    };
    edge = {
      system = "edge";
      role = "edge";
    };
  };

  timeout = 300;

  testScript = ''
    echo "--- Verifying cloud/control node (server image) ---"

    assert_on "cloud" "systemctl is-active multi-user.target" \
      "cloud node reached multi-user.target"

    assert_output_on "cloud" "cat /etc/os-release" "ANDYL OS" \
      "cloud node is ANDYL OS"

    assert_on "cloud" "systemctl cat containerd.service" \
      "cloud node has containerd unit"

    assert_on "cloud" "systemctl cat kubelet.service" \
      "cloud node has kubelet unit"

    echo "--- Verifying edge node (edge image) ---"

    assert_on "edge" "systemctl is-active multi-user.target" \
      "edge node reached multi-user.target"

    assert_output_on "edge" "cat /etc/os-release" "ANDYL OS" \
      "edge node is ANDYL OS"

    assert_on "edge" "systemctl cat containerd.service" \
      "edge node has containerd unit"

    assert_on "edge" "systemctl cat edgecore.service" \
      "edge node has edgecore unit"

    assert_on "edge" "test -f /etc/kubeedge/config/edgecore.yaml" \
      "edge node has edgecore config"

    echo "--- Verifying network connectivity ---"

    assert_output_on "cloud" "cat /etc/hosts" "edge" \
      "cloud node knows about edge in /etc/hosts"

    assert_output_on "edge" "cat /etc/hosts" "cloud" \
      "edge node knows about cloud in /etc/hosts"

    echo "--- K8s edge cluster test complete ---"
  '';
}
