##! Compares complete installed dependency closures while retaining package identities.
{
  pkgs,
  pname,
  packages,
}: let
  closureInfo = pkgs.lib.build.closureInfo {inherit pkgs;};
  contracts = pkgs.lib.mapAttrs (name: variants:
    pkgs.lib.mapAttrs (role: package: let
      closure = closureInfo {
        pname = "${pname}-${name}-${role}";
        rootPaths = [package];
      };
    in {
      root = toString package;
      closure = "${closure}/store-paths";
    })
    variants)
  packages;
in
  assert packages != {};
  assert builtins.all (variants: builtins.attrNames variants == ["bazel" "cargo"]) (builtins.attrValues packages);
    pkgs.runCommand pname {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - "$out/parity.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      contracts = json.loads(${builtins.toJSON (builtins.toJSON contracts)})
      components = {}
      for name, variants in contracts.items():
          components[name] = {}
          for role, contract in variants.items():
              paths = set(Path(contract["closure"]).read_text().splitlines())
              if contract["root"] not in paths:
                  raise ValueError("installed package is absent from its closure: " + name)
              # Package identities may change during migration; every other
              # store path must remain identical, including non-ELF references.
              dependencies = sorted(paths - {contract["root"]})
              components[name][role] = {"root": contract["root"], "dependencies": dependencies}

          if components[name]["bazel"]["dependencies"] != components[name]["cargo"]["dependencies"]:
              raise ValueError("installed Bazel/Cargo runtime closures differ: " + name)

      Path(sys.argv[1]).write_text(json.dumps({
          "status": "PASS", "components": components,
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
    ''
