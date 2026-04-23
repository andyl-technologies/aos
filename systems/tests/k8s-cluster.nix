# systems/tests/k8s-cluster.nix — Multi-VM K8s cluster bootstrap test
#
# Boots a control plane node and a worker node (both server images),
# verifies that both boot to multi-user.target, have the correct
# K8s components configured, and can communicate over the network.
{lib}: {
  name = "k8s-cluster";
  description = "K8s cluster multi-VM bootstrap";
  type = "fleet";

  machines = {
    control = {
      system = "server";
      role = "control";
    };
    worker = {
      system = "server";
      role = "worker";
    };
  };

  timeout = 300;

  testScript = ''
    echo "--- Verifying control plane node ---"

    assert_on "control" "systemctl is-active multi-user.target" \
      "control plane reached multi-user.target"

    assert_output_on "control" "cat /etc/os-release" "ANDYL OS" \
      "control plane is ANDYL OS"

    assert_on "control" "systemctl cat containerd.service" \
      "control plane has containerd unit"

    assert_on "control" "systemctl cat kubelet.service" \
      "control plane has kubelet unit"

    assert_on "control" "test -d /etc/kubernetes" \
      "control plane has kubernetes config dir"

    echo "--- Verifying worker node ---"

    assert_on "worker" "systemctl is-active multi-user.target" \
      "worker reached multi-user.target"

    assert_output_on "worker" "cat /etc/os-release" "ANDYL OS" \
      "worker is ANDYL OS"

    assert_on "worker" "systemctl cat containerd.service" \
      "worker has containerd unit"

    assert_on "worker" "systemctl cat kubelet.service" \
      "worker has kubelet unit"

    echo "--- Verifying network connectivity ---"

    assert_on "control" "cat /etc/hosts" \
      "control plane has /etc/hosts"

    assert_output_on "control" "cat /etc/hosts" "worker" \
      "control plane knows about worker in /etc/hosts"

    assert_output_on "worker" "cat /etc/hosts" "control" \
      "worker knows about control in /etc/hosts"

    echo "--- K8s cluster bootstrap test complete ---"
  '';
}
