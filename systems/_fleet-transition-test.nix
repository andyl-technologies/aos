# Test-only image policy for evaluator-compatible image transitions.
#
# This source-backed system module keeps the package-owned guest-agent request
# in every generated transition without creating a second service definition.
# The leading underscore excludes it from production system auto-discovery.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.aos-test-agent];
  aos-test-agent.enable = true;
}
