# 7. Networking

## 7.1 Default Network (No Cloud-Init)

The golden image ships a catch-all DHCP config at priority 80:

```ini
# /etc/systemd/network/80-dhcp.network
[Match]
Name=en*
Type=ether

[Network]
DHCP=yes
LLDP=yes

[DHCPv4]
UseDNS=yes
UseNTP=yes
UseHostname=yes
SendHostname=yes
RouteMetric=100
```

Cloud-init-generated files use priority `10-` and override this default.
DNS resolution via `systemd-resolved` with DHCP-provided servers.

## 7.2 Cloud-Init Network Configuration (v2)

AOS uses cloud-init network config version 2 with the `networkd` renderer.
Cloud-init translates v2 YAML into `.network` and `.netdev` files.

**Static IP**:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens3:
      dhcp4: false
      addresses: [10.0.1.50/24]
      routes:
        - to: default
          via: 10.0.1.1
      nameservers:
        addresses: [10.0.1.2, 10.0.1.3]
        search: [prod.internal]
```

**VLAN**:

```yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
  vlans:
    vlan100:
      id: 100
      link: ens3
      addresses: [10.100.0.50/24]
      routes:
        - to: default
          via: 10.100.0.1
```

**Bond (LACP)**:

```yaml
network:
  version: 2
  ethernets:
    ens3: {}
    ens4: {}
  bonds:
    bond0:
      interfaces: [ens3, ens4]
      mtu: 9000
      parameters:
        mode: 802.3ad
        lacp-rate: fast
        transmit-hash-policy: layer3+4
      addresses: [10.0.1.50/24]
      routes:
        - to: default
          via: 10.0.1.1
```

**Multi-NIC (management + data)**:

```yaml
network:
  version: 2
  ethernets:
    ens3:
      addresses: [10.0.1.50/24]
      routes:
        - to: default
          via: 10.0.1.1
          metric: 100
    ens4:
      addresses: [10.10.0.50/24]
      mtu: 9000
      routes:
        - to: 10.10.0.0/16
          via: 10.10.0.1
          metric: 200
```

## 7.3 Cloud Provider Integration

| Provider    | Datasource | Single NIC | Multi-NIC | Notes |
|-------------|------------|------------|-----------|-------|
| AWS EC2     | Ec2        | DHCP works | Policy routing needed | IMDSv2 enforced |
| GCP GCE     | GCE        | DHCP works | Per-NIC per-VPC | /32 with link-local GW |
| Azure       | Azure      | DHCP works | Policy routing needed | Accelerated networking via SR-IOV |
| Bare-metal  | NoCloud    | DHCP works | Full control via v2 | Config drive or seed URL |

## 7.4 Cilium Networking

When Kubernetes is activated, Cilium manages all pod networking:

- **Pod CIDR**: Allocated by k3s, announced to Cilium via K8s API
- **Overlay**: VXLAN (default) or Geneve for cross-node pod traffic
- **WireGuard**: Optional node-to-node encryption (`wireguard: {enabled: true}`)
- **Direct routing**: Can use native routing instead of overlay when nodes share L2
- **L2 announcements**: Cilium announces LoadBalancer IPs via ARP/NDP on the local network, replacing MetalLB for bare-metal clusters
- **BGP**: Optional BGP peering for data center integration
