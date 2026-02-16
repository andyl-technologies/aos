{
  description = "ANDYL OS — immutable, minimal Linux distribution built from source";

  inputs = { };

  outputs =
    { self }:
    let
      buildSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      devSystems = buildSystems ++ [
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      genAttrs =
        names: f:
        builtins.listToAttrs (
          map (n: {
            name = n;
            value = f n;
          }) names
        );

      aosFor =
        system:
        let
          lib = import ./lib { inherit system; };
          pkgs = import ./pkgs { inherit lib; };
        in
        {
          inherit lib pkgs;
        };
    in
    {
      packages = genAttrs buildSystems (
        system:
        let
          env = aosFor system;
        in
        {
          aos = env.pkgs.aos;
          default = env.pkgs.aos;
        }
      );

      devShells = genAttrs devSystems (
        system:
        let
          isLinux = builtins.elem system buildSystems;
          env = if isLinux then aosFor system else null;
        in
        {
          default = import ./dev/shell.nix {
            inherit system;
            aos = if isLinux then env.pkgs.aos else null;
            just = if isLinux then env.pkgs.just else null;
          };
        }
      );

      formatter = genAttrs buildSystems (system: (aosFor system).pkgs.alejandra);

      checks = genAttrs buildSystems (system: {
        aos = (aosFor system).pkgs.aos;
      });
    };
}
