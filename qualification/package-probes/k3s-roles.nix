##! Qualifies staged role modules before the existing K3s fleet lifecycle runs.
{testing}: let
  probe = package:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "Enable the staged role with a credential, node identity and label; workers receive an HTTPS server URL.";
          operation = "Evaluate the staged configuration module with the staged base library and inspect its service environment.";
          expected = "The module preserves its fixed role and renders the endpoint, identity, label, credential and resource contract.";
          files = {
            "role.nix" = builtins.readFile ./_k3s-role-eval.nix;
            "probe.py" = builtins.readFile ./_k3s-role-probe.py;
          };
          steps = [
            {
              argv = ["@python@" "probe.py" package "primary"];
              exit_code = 0;
              timeout_seconds = 240;
              stdout.exact = "role configuration rendered and bound\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input =
            if package == "k3s-worker"
            then "Enable a worker with a credential but no server URL."
            else "Enable a server role without its required credential.";
          operation = "Evaluate the same staged module with an invalid operational configuration.";
          expected = "The module rejects the input with its specific required-URL or required-credential assertion.";
          files = {
            "role.nix" = builtins.readFile ./_k3s-role-eval.nix;
            "probe.py" = builtins.readFile ./_k3s-role-probe.py;
          };
          steps = [
            {
              argv = ["@python@" "probe.py" package "bad-input"];
              exit_code = 0;
              timeout_seconds = 240;
              observes_rejection = true;
              stdout.exact = "invalid role configuration rejected\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
      };
    };
in
  builtins.listToAttrs (map (package: {
    name = package;
    value = probe package;
  }) ["k3s-combined" "k3s-control-plane" "k3s-worker"])
