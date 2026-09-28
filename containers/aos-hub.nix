##! containers/aos-hub.nix -- Native Hub service artifact.
##!
##! The service image carries the same Native binary used by the systemd
##! deployment. Runtime configuration, credentials, and database authority are
##! supplied by the deployment; the image contains no initialized Hub state.
{
  pkgs,
  aosSystem,
}: let
  hostSystem = pkgs.stdenv.hostPlatform.system;
  validatedSystem =
    if aosSystem == hostSystem
    then hostSystem
    else throw "containers.aos-hub: target must match the package-set target";
  architecture =
    if validatedSystem == "x86_64-linux"
    then "amd64"
    else if validatedSystem == "aarch64-linux"
    then "arm64"
    else throw "containers.aos-hub: unsupported target '${validatedSystem}'";
  certificateRoots = [pkgs.ca-certificates];
  serviceRoots = [pkgs.aos-hub];
in {
  config = {
    name = "aos-hub";
    packageRoots = certificateRoots ++ serviceRoots;
    layers = [
      {
        name = "trust-roots";
        roots = certificateRoots;
      }
      {
        name = "hub-service";
        roots = serviceRoots;
        subtractRoots = certificateRoots;
      }
    ];

    filesystem = {
      facade = [
        {
          name = "aos-hub";
          target = "${pkgs.aos-hub}/bin/aos-hub";
        }
      ];
      directories = [
        {
          path = "/tmp";
          mode = "1777";
        }
      ];
    };

    runtime = {
      entrypoint = ["/usr/bin/aos-hub"];
      command = ["serve"];
      environment = {
        HUB_ROOT = "/tmp/aos-hub";
        HUB_LISTEN = "0.0.0.0:8080";
        HUB_TOPOLOGY = "hybrid";
        SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
      };
      user = "0:0";
      workingDirectory = "/tmp";
      stopSignal = "SIGTERM";
    };

    platform = {
      os = "linux";
      inherit architecture;
      aosSystem = validatedSystem;
    };
    budgets = {
      maxClosureMiB = 128;
      # Current library outputs retain 17.1 MiB of headers and static archives.
      maxDevelopmentPayloadMiB = 20;
      maxLayers = 4;
    };
    annotations = {
      "org.opencontainers.image.title" = "AOS Hub";
      "org.opencontainers.image.description" = "Native AOS Hub control service built from AOS packages";
      "org.opencontainers.image.vendor" = "Andyl, Inc.";
      "org.opencontainers.image.source" = "https://github.com/andyl-technologies/aos";
      "dev.andyl.aos.container.definition" = "aos-hub";
      "dev.andyl.aos.system" = validatedSystem;
    };
    publication = {
      repository = "aos-hub";
      releaseIdentity = pkgs.aos-hub.version;
    };
  };
}
