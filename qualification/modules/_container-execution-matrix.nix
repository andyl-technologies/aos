##! Validates the stage-specific lifecycle strategy qualification cells.
{
  lib,
  surface ? builtins.fromJSON (builtins.readFile ../container-execution-surface.json),
}: let
  expectedDigest = "756c1d1737ed27196a77a3997c357bb6a2eb34cf1d6ba29d0108912bdc7e7c5a";
  digest = builtins.hashString "sha256" (builtins.toJSON surface);
  expectedKeys = [
    "blockers"
    "evidence"
    "id"
    "interface_descriptor"
    "interface_name"
    "required_guarantees"
    "stage"
    "status"
    "strategy"
  ];
  token = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[a-z0-9.-]+" value != null;
  validCell = cell:
    builtins.attrNames cell
    == expectedKeys
    && builtins.match "[a-z0-9./-]+" cell.id != null
    && builtins.all token ([cell.interface_name cell.stage cell.status cell.strategy] ++ cell.required_guarantees ++ cell.blockers)
    && builtins.match "sha256:[0-9a-f]{64}" cell.interface_descriptor != null
    && builtins.all (value: builtins.isString value && builtins.stringLength value <= 256) cell.evidence
    && builtins.elem cell.status ["missing" "qualified"];
  byId = builtins.listToAttrs (map (cell: {
      name = cell.id;
      value = cell;
    })
    surface.cells);
  containerManager = byId."systemd-manager/system-container" or null;
  foreground = byId."foreground-process/application-container" or null;
  valid =
    builtins.attrNames surface
    == ["cells" "schema"]
    && surface.schema == "aos.qualification.container-execution-surface/v1"
    && digest == expectedDigest
    && builtins.length surface.cells == 3
    && builtins.length (lib.unique (map (cell: cell.id) surface.cells)) == 3
    && builtins.all validCell surface.cells
    && containerManager != null
    && containerManager.status == "missing"
    && containerManager.blockers
    == [
      "pr232-authenticated-backend-readiness"
      "pr232-broker-host-apply"
      "pr232-resource-view-lease-handoff"
      "pr232-shifted-payload-pid-namespace-proof"
      "pr232-scoped-local-manager-endpoint"
      "pr232-durable-lifecycle-observation-evidence"
    ]
    && foreground != null
    && foreground.status == "qualified"
    && foreground.blockers == []
    && foreground.evidence == ["checks.fleet.ability-native-foreground-container"];
in
  if !valid
  then throw "Container execution qualification surface is invalid."
  else {
    inherit (surface) cells;
    check = "stage-specific-manager-and-foreground-contracts-with-unqualified-container-cells";
    missing_container_cells = 1;
  }
