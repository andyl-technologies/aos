##! Synthetic package fixtures used beside the production nginx provider stack.
{
  mkDerivation,
}: let
  mkFixture = {
    pname,
    abilities,
    src,
  }:
    mkDerivation {
      inherit pname abilities src;
      version = "1.0.0";
      runtimeDeps = [];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${pname}"
            printf '%s\n' 'synthetic nginx composition fixture' > "$out/share/${pname}/README"
          '';
        }
      ];

      meta = {
        description = "Synthetic nginx composition fixture";
        license = "Apache-2.0";
      };
    };
in {
  consumer = mkFixture {
    pname = "ability-reference-nginx-consumer";
    abilities = ./modules/consumer;
    src = ./modules/consumer;
  };

  backend-consumer = mkFixture {
    pname = "ability-reference-nginx-backend-consumer";
    abilities = ./modules/backend-consumer;
    src = ./modules/backend-consumer;
  };

  backend-registry = mkFixture {
    pname = "ability-reference-http-backend-registry";
    abilities = ./modules/backend-registry;
    src = ./modules/backend-registry;
  };
}
