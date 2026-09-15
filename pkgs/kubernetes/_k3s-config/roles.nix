##! Authoritative package and service semantics for each k3s role package.
let
  agentStateDirectories = [
    "rancher/k3s"
    "kubelet"
  ];
  agentHostPaths = [
    {
      path = "/var/lib/rancher";
      mode = "rw";
    }
    {
      path = "/var/lib/kubelet";
      mode = "rw";
    }
    {
      path = "/etc/rancher/k3s";
      mode = "rw";
    }
    {
      path = "/etc/rancher/node";
      mode = "rw";
    }
    {
      path = "/lib/modules";
      mode = "read-only";
    }
  ];
  serverHostPaths = [
    {
      path = "/var/lib/rancher";
      mode = "rw";
    }
    {
      path = "/etc/rancher/k3s";
      mode = "rw";
    }
    {
      path = "/etc/rancher/node";
      mode = "rw";
    }
    {
      path = "/lib/modules";
      mode = "read-only";
    }
  ];
  common = {
    kernelModules = [
      "br_netfilter"
      "vxlan"
      "ip_set"
    ];
    kernelTunables = {
      "net.ipv4.ip_forward" = "1";
      "net.ipv6.conf.all.forwarding" = "1";
      "net.bridge.bridge-nf-call-iptables" = "1";
      "net.bridge.bridge-nf-call-ip6tables" = "1";
    };
  };
in
{
  k3s-worker = common // {
    role = "worker";
    description = "Lightweight Kubernetes agent";
    command = "agent";
    stateDirectories = agentStateDirectories;
    hostPaths = agentHostPaths;
    ingressEndpoints = [
      {
        transport = "tcp";
        port = 10250;
      }
      {
        transport = "udp";
        port = 8472;
      }
    ];
    acceptForwardedTraffic = true;
  };

  k3s-control-plane = common // {
    role = "control-plane";
    description = "Lightweight Kubernetes control plane without an agent";
    command = "server --disable-agent";
    stateDirectories = [ "rancher/k3s" ];
    hostPaths = serverHostPaths;
    ingressEndpoints = [
      {
        transport = "tcp";
        port = 6443;
      }
    ];
    acceptForwardedTraffic = false;
  };

  k3s-combined = common // {
    role = "combined";
    description = "Lightweight Kubernetes combined server and agent";
    command = "server";
    stateDirectories = agentStateDirectories;
    hostPaths = agentHostPaths;
    ingressEndpoints = [
      {
        transport = "tcp";
        port = 6443;
      }
      {
        transport = "tcp";
        port = 10250;
      }
      {
        transport = "udp";
        port = 8472;
      }
    ];
    acceptForwardedTraffic = true;
  };
}
