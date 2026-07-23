##! systems/edge.nix — Edge/IoT golden image
##!
##! Builds an edge image for IoT and edge deployments (Jetson Nano,
##! Raspberry Pi, small appliances). Signed host configuration configures the system
##! at first boot; Kubernetes role configuration is applied separately.
##!
##! Profiles: edge
##!
##! Buildable with empty config root — all required options have defaults.
{...}: {
  aos.profiles.edge.enable = true;
}
