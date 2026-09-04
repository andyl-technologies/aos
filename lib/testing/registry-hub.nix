##! Focused evaluation contract for the system-owned native registry Hub.
{
  pkgs,
  lib,
  mkSystem,
  serverModule,
}: let
  evaluated = mkSystem {
    modules = [
      serverModule
      {
        aos.registry-hub = {
          enable = true;
          listen = "127.0.0.1:18420";
          externalUrl = "https://hub.example.test";
          reindexInterval = 15;
          deploymentId = "hub-production-v1";
          releaseReceiptKeyId = "hub-publication-v1";
          channelReceiptKeyId = "hub-channel-v1";
          credentials = {
            jwtSecret = "hub-jwt";
            domainProbeSignerManifest = "hub-probe-signers";
            routeReservationKeys = "hub-route-keys";
            cloudflareApiToken = "hub-cloudflare-token";
            releaseReceiptKey = "hub-release-receipt-key";
            channelReceiptKey = "hub-channel-receipt-key";
            releasePublicationKeys = "hub-publication-keys";
            qualificationKeys = "hub-qualification-keys";
          };
        };
      }
    ];
  };
  service = evaluated.config.systemd.services.aos-hub.serviceConfig;
  invalid = mkSystem {
    modules = [
      serverModule
      {aos.registry-hub.enable = true;}
    ];
  };
  invalidReleaseEvidence = mkSystem {
    modules = [
      serverModule
      {
        aos.registry-hub = {
          enable = true;
          deploymentId = "incomplete-release-authority";
          credentials = {
            domainProbeSignerManifest = "hub-probe-signers";
            routeReservationKeys = "hub-route-keys";
          };
        };
      }
    ];
  };
  contract = assert lib.hasInfix "127.0.0.1:18420" service.ExecStart;
  assert lib.hasInfix "--reindex-interval 15" service.ExecStart;
  assert lib.elem "jwt-secret:/run/credentials/@system/hub-jwt" service.LoadCredential;
  assert lib.elem "domain-probe-signers:/run/credentials/@system/hub-probe-signers" service.LoadCredential;
  assert lib.elem "route-reservation-keys:/run/credentials/@system/hub-route-keys" service.LoadCredential;
  assert lib.elem "cloudflare-api-token:/run/credentials/@system/hub-cloudflare-token" service.LoadCredential;
  assert lib.elem "release-receipt-key:/run/credentials/@system/hub-release-receipt-key" service.LoadCredential;
  assert lib.elem "channel-receipt-key:/run/credentials/@system/hub-channel-receipt-key" service.LoadCredential;
  assert lib.elem "release-publication-keys:/run/credentials/@system/hub-publication-keys" service.LoadCredential;
  assert lib.elem "qualification-keys:/run/credentials/@system/hub-qualification-keys" service.LoadCredential;
  assert lib.elem "HUB_CLOUDFLARE_API_TOKEN_FILE=/run/credentials/aos-hub.service/cloudflare-api-token" service.Environment;
  assert lib.elem "HUB_DEPLOYMENT_ID=hub-production-v1" service.Environment;
  assert lib.elem "HUB_RELEASE_RECEIPT_KEY_ID=hub-publication-v1" service.Environment;
  assert lib.elem "HUB_CHANNEL_RECEIPT_KEY_ID=hub-channel-v1" service.Environment;
  assert !(builtins.all (entry: builtins.getAttr "assertion" entry) (builtins.getAttr "assertions" invalid.config));
  assert !(builtins.all (entry: builtins.getAttr "assertion" entry) (builtins.getAttr "assertions" invalidReleaseEvidence.config)); true;
in
  pkgs.mkDerivation {
    pname = "registry-hub-module-check";
    version = "0";
    src = null;
    inherit contract;
    phases = [
      {
        name = "check";
        script = ''
          : "$contract"
          mkdir -p "$out"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];
  }
