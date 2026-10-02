##! Creates receipt roots during an actual admitted preparation transaction.
{
  pkgs,
  lib,
  stateDirectory ? "/build/aos-boot-handoff-state",
}: let
  fixture = import ./boot-metadata-fixture.nix {
    inherit pkgs lib stateDirectory;
    preparationScript = ''
      export AOS_HANDOFF_NIX_STORE=${pkgs.nix}/bin/nix-store
      ${builtins.readFile ./boot-handoff-package/handler.sh}
    '';
  };
in
  fixture.overrideAttrs (previous: {
    phases =
      previous.phases
      ++ [
        {
          name = "handoff-sources";
          script = ''
            ${pkgs.jq}/bin/jq --arg authorization ${fixture.receipt} --arg plan ${fixture.plan} \
              '. + {sourceAuthorization:$authorization,sourcePlan:$plan}' \
              "$out/fixture.json" > "$out/fixture.json.new"
            mv "$out/fixture.json.new" "$out/fixture.json"
          '';
        }
      ];
  })
