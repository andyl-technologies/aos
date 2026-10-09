##! Focused VM checks for the package service.
{cfg}: {
  description = "Tailscale service checks";
  checks = [
    {
      name = "tailscale-local-api";
      description = "tailscaled creates its protected local API socket";
      script = ''
        vm.succeed("test -S /run/tailscale/tailscaled.sock")
        vm.wait_until_succeeds(
            "tailscale --socket=/run/tailscale/tailscaled.sock debug prefs "
            "| grep -F '\"LoggedOut\": true'",
            timeout=30,
        )
      '';
    }
  ];
}
