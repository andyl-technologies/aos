##! Native Hub initialization job artifact.
##!
##! Shares the service's binary and layers, but defaults to the explicit init
##! transaction. Database authority and optional root credentials are supplied
##! at execution time; deploying this image does not execute the transaction.
{
  pkgs,
  aosSystem,
}: let
  service = import ./aos-hub.nix {inherit pkgs aosSystem;};
in {
  config =
    service.config
    // {
      name = "aos-hub-bootstrap";

      runtime =
        service.config.runtime
        // {
          command = ["init"];
          environment = builtins.removeAttrs service.config.runtime.environment [
            "HUB_LISTEN"
            "HUB_TOPOLOGY"
          ];
        };

      annotations =
        service.config.annotations
        // {
          "org.opencontainers.image.title" = "AOS Hub bootstrap";
          "org.opencontainers.image.description" = "Native AOS Hub explicit database initialization job";
          "dev.andyl.aos.container.definition" = "aos-hub-bootstrap";
        };

      publication =
        service.config.publication
        // {
          repository = "aos-hub-bootstrap";
        };
    };
}
