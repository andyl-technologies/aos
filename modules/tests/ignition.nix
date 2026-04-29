##! modules/tests/ignition.nix — Ignition first-boot provisioning end-to-end
##!
##! Exercises the full metadata-delivery path:
##!   1. The harness packs `instanceMetadata.config` into an ISO9660 image
##!      (volume label `aos-metadata`) and attaches it as a SCSI CD-ROM.
##!   2. In the initrd, `aos-platform-detect.service` finds
##!      `/dev/disk/by-label/aos-metadata`, mounts it at `/run/aos-metadata`,
##!      and writes `IGNITION_CONFIG_FILE=/run/aos-metadata/config.json`
##!      to the platform env that every ignition stage inherits.
##!   3. The ignition-{disks,mount,files} stages read the file directly
##!      via ignition's `file` provider and apply the config.
##!   4. The check then asserts the guest-visible side-effect.
##!
##! Storage targets /var/etc/<path> because it is the top lower layer of
##! the production /etc overlay — entries there shadow the same path in
##! /etc.lower, so the test can override a file the image baked in.
{
  config,
  lib,
  ...
}: let
  hasIgnition = config.aos.services.ignition.enable or false;
in {
  config = lib.mkIf hasIgnition {
    system.checks.ignition-hostname = {
      description = "ignition first-boot provisioning via ISO9660 metadata channel";
      instanceMetadata = {
        format = "ignition";
        config = {
          ignition.version = "3.5.0";
          storage = {
            directories = [{path = "/var/etc";}];
            files = [
              {
                path = "/var/etc/hostname";
                mode = 420; # 0644
                overwrite = true;
                contents.source = "data:,ignition-test-host%0A";
              }
            ];
          };
        };
      };
      checks = [
        {
          name = "hostname-overridden";
          description = "/etc/hostname reads 'ignition-test-host' via the overlay";
          script = ''
            assert_output_contains "cat /etc/hostname" "ignition-test-host" \
              "ignition wrote /var/etc/hostname and the /etc overlay exposes it"
          '';
        }
      ];
    };
  };
}
