##! Exercises managed SDK write grants without widening repository authority.
{
  lib,
  evaluate,
  checksPass,
  localFixture,
}: let
  output = "/srv/terrane-sdk";
  exposure = {
    id = "snapshot";
    surface = "sdk";
    at = "${output}/first";
    view = "refs/heads/main";
    token = "file:/run/terrane/snapshot.cap";
  };
  fixture = lib.recursiveUpdate localFixture {
    aos.terrane = {
      sdkOutputRoots = [output];
      exposures = [exposure];
    };
  };
  configured = extra: evaluate (lib.recursiveUpdate fixture extra);
  accepted = extra: let
    cfg = configured extra;
    result = builtins.tryEval (builtins.deepSeq cfg.environment.etc."terrane/terrane.toml".text (checksPass cfg));
  in
    result.success && result.value;
  rejected = extra: !accepted extra;
  cfg = configured {};
  withOutput = root: {
    aos.terrane = {
      sdkOutputRoots = lib.mkForce [root];
      exposures = lib.mkForce [(exposure // {at = "${root}/snapshot";})];
    };
  };
in [
  {
    name = "sdk-output-explicit-serve-only-write-grant";
    pass =
      checksPass cfg
      && builtins.elem output cfg.systemd.services.terrane-serve.serviceConfig.ReadWritePaths
      && builtins.all (role: !(builtins.elem output cfg.systemd.services."terrane-${role}".serviceConfig.ReadWritePaths)) ["publish" "realize" "gc"]
      && cfg.systemd.services.terrane-serve.serviceConfig.ProtectSystem == "strict"
      && !(lib.hasInfix output cfg.environment.etc."tmpfiles.d/terrane.conf".text)
      && !(lib.hasInfix "sdkOutputRoots" cfg.environment.etc."terrane/terrane.toml".text);
  }
  {
    name = "sdk-output-nested-endpoints-and-disabled-serve-valid";
    pass =
      accepted {aos.terrane.exposures = lib.mkForce [(exposure // {at = "${output}/nested/first";})];}
      && accepted {aos.terrane.roles.serve.enable = false;};
  }
  {
    name = "sdk-output-required-container-and-strict-containment";
    pass = builtins.all rejected [
      {aos.terrane.sdkOutputRoots = lib.mkForce [];}
      {aos.terrane.exposures = lib.mkForce [(exposure // {at = output;})];}
      {aos.terrane.exposures = lib.mkForce [(exposure // {at = "${output}-other/first";})];}
      {aos.terrane.exposures = lib.mkForce [(exposure // {at = "${output}/../outside";})];}
      {aos.terrane.exposures = lib.mkForce [(exposure // {at = "relative";})];}
    ];
  }
  {
    name = "sdk-output-canonical-distinct-used-containers";
    pass = builtins.all rejected [
      {aos.terrane.sdkOutputRoots = lib.mkForce ["/"];}
      {aos.terrane.sdkOutputRoots = lib.mkForce ["${output}/../terrane-sdk"];}
      {aos.terrane.sdkOutputRoots = lib.mkForce ["${output}/"];}
      {aos.terrane.sdkOutputRoots = lib.mkForce [output output];}
      {aos.terrane.sdkOutputRoots = lib.mkForce [output "${output}/nested"];}
      {aos.terrane.sdkOutputRoots = lib.mkForce [output "/srv/unused"];}
    ];
  }
  {
    name = "sdk-output-storage-authority-and-controls-isolated";
    pass =
      accepted {
        aos.terrane.hostTier.domains.public = {
          path = "/srv/native";
          administrativeRoot = "/srv/admin";
        };
      }
      && builtins.all (root: rejected (withOutput root)) [
        "/var/lib/terrane"
        "/var/lib/terrane/chunks/export"
        "/var/lib/terrane-authority"
        "/var/lib/terrane-bucket"
        "/var/lib/terrane-host"
        "/run/terrane-maintenance"
        "/run/terrane-publish"
        "/run/aos-terrane-host"
        "/etc/export"
        "/nix/export"
        "/home/terrane/export"
        "/tmp/export"
      ]
      && rejected (lib.recursiveUpdate (withOutput "/srv/admin/export") {
        aos.terrane.hostTier.domains.public = {
          path = "/srv/native";
          administrativeRoot = "/srv/admin";
        };
      });
  }
  {
    name = "sdk-output-credential-and-quota-paths-isolated";
    pass = builtins.all rejected [
      {aos.terrane.tokens.hostToken = "file:${output}/host.cap";}
      {aos.terrane.tokens.issuerPublicKeys = ["file:${output}/issuer.pub"];}
      {aos.terrane.exposures = lib.mkForce [(exposure // {token = "file:${output}/snapshot.cap";})];}
      {aos.terrane.tokens.hostToken = "file:/srv/other/../terrane-sdk/host.cap";}
      {
        aos.terrane.hostTier.quota = {
          socketPath = "${output}/quota.sock";
          configurationEpoch = "00000000000000000000000000000001";
        };
      }
    ];
  }
  {
    name = "sdk-output-unrecognized-or-aliased-local-bucket-refused";
    pass = builtins.all (store: rejected {aos.terrane.store = lib.mkForce store;}) [
      "bucket(file:///srv/other/../terrane-sdk/bucket)"
      "bucket(file:///srv/%74errane-sdk/bucket)"
      "routed[bucket(file:///var/lib/terrane-bucket)]"
    ];
  }
]
