##! Verifies merged definitions and manager ownership through native evaluation.
{
  lib,
  package,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "firewall"];
    packages = [package];
    operatorModules = [
      {
        aos.networkPolicy = {
          enable = true;
          allowedTCP = [22];
        };
      }
      {
        aos.networkPolicy.ingress.web.endpoints = [
          {
            transport = "tcp";
            port = 443;
          }
        ];
      }
    ];
  };
  nodes = builtins.attrValues evaluated.deployment.graph.nodes;
  node = builtins.head nodes;
  invalid = lib.evalPackageModules {
    scope = ["test" "invalid-firewall"];
    packages = [package];
    operatorModules = [
      {
        aos.networkPolicy = {
          enable = true;
          allowedTCP = [0];
        };
      }
    ];
  };
in {
  mergedContributions = assert builtins.length nodes == 1;
  assert node.input.allowedTCP == [22];
  assert node.input.ingress.web.endpoints
  == [
    {
      transport = "tcp";
      port = 443;
    }
  ]; true;
  managerOwnership = assert node.owner == "nftables";
  assert node.identity == ["test" "firewall" "nftables" "networkPolicy" "ruleset" "host"]; true;
  selectedHandler = assert node.handler.executable == "${package}/bin/aos-network-ruleset-provider"; true;
  invalidPort = assert !(builtins.tryEval (builtins.deepSeq invalid.deployment.graph true)).success; true;
}
