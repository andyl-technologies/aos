##! Checks containerd's native declarations without requiring enabled handlers.
{
  pkgs,
  lib,
}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "containerd-declarations"];
    packages = [pkgs.containerd];
  };
in
  assert pkgs.containerd ? module;
  assert pkgs.containerd.deployment.module.source == builtins.toString pkgs.containerd.module;
  assert evaluated.config.aos.services.containerd.lifecycle.start != [];
  assert !evaluated.config.aos.services.containerd.enable;
  assert evaluated.deployment.graph.nodes == {};
  assert evaluated.documentation.abilities.serviceManagement.realize.input.lifecycle.type.kind == "nullable"; true
