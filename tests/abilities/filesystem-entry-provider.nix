##! Native filesystem entries retain typed paths and exact parent authority.
{
  lib,
  pkgs,
}: let
  payload = import ../effects/_fixture-payload.nix "filesystem";
  package = {
    _type = "aos-package-artifact";
    name = "aos-filesystem-provider";
    path = payload;
    outputs.out = payload;
    outPath = payload;
    meta.mainProgram = "aos-filesystem-provider";
  };
  evaluated = lib.evalModules {
    inherit lib;
    specialArgs = {inherit package;};
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
      ({config, ...}: {
        aos.directories.state = {
          enable = true;
          path = "/var/lib/example";
          persistent = true;
          mode = "0750";
        };
        aos.abilities.filesystem.operations.entry.effects.child.input = {
          kind = "directory";
          path = "/var/lib/example/child";
          parentResource = config.aos.abilities.filesystem.operations.persistentAllocate.effects.state.outputs.resource;
        };
        aos.abilities.filesystem.operations.entry.effects.log = {
          input = {
            kind = "empty-file";
            path = "/var/log/example.log";
            mode = "0660";
          };
          lifetime = "persistent";
        };
        aos.abilities.filesystem.operations.privilegedExecutable.effects.ping.input = {
          name = "ping";
          source = "${package.path}/bin/ping";
        };
        aos.abilities.filesystem.operations.symlinkTree.effects.configuration.input = {
          path = "/etc/example";
          sourcePath = "${package.path}/etc/example";
        };
      })
    ];
  };
  nodes = builtins.attrValues evaluated.config.aos.activation.graph.nodes;
  node = operation: builtins.head (builtins.filter (value: builtins.elem operation value.identity) nodes);
  parent = node "persistentAllocate";
  entry = name: builtins.head (builtins.filter (value: builtins.elem "entry" value.identity && lib.last value.identity == name) nodes);
  child = entry "child";
  log = entry "log";
  wrapper = node "privilegedExecutable";
  tree = node "symlinkTree";
in
  assert builtins.length nodes == 5;
  assert parent.lifetime == "persistent";
  assert parent.input.path == "/var/lib/example";
  assert parent.input.mode == "0750";
  assert child.dependencies == [(builtins.hashString "sha256" (builtins.toJSON parent.identity))];
  assert child.input.parentResource.identity == parent.identity;
  assert child.results.path.kind == "string";
  assert child.results.resource.kind == "string";
  assert log.input.kind == "empty-file";
  assert log.input.sourcePath == null;
  assert log.input.path == "/var/log/example.log";
  assert log.input.mode == "0660";
  assert log.lifetime == "persistent";
  assert wrapper.input.mode == "4755";
  assert wrapper.input.owner == "root";
  assert wrapper.input.group == "root";
  assert tree.input.sourcePath == "${package.path}/etc/example";
  assert tree.input.mode == "0777";
  assert tree.results.path.kind == "string";
  assert tree.results.resource.kind == "string";
  assert builtins.all (value: value.handler.executable == "${package.path}/bin/aos-filesystem-provider") nodes; true
