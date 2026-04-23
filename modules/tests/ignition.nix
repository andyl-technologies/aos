##! modules/tests/ignition.nix — Ignition first-boot provisioning end-to-end
##!
##! Exercises the full metadata-delivery path added by the checks-rehaul:
##!   1. The harness builds a metadata disk from `instanceMetadata.config`,
##!      attaches it as a second virtio-blk device, and appends
##!      `ignition.config.url=http://127.0.0.1:8080/config.json` to the
##!      kernel cmdline.
##!   2. In the initrd, `aos-test-metadata-mount.service` mounts the disk
##!      and brings up the loopback interface; `aos-test-metadata.socket`
##!      serves `config.json` via localhost HTTP.
##!   3. `ignition-fetch.service` reads the config URL from /proc/cmdline,
##!      fetches over the loopback, and the subsequent ignition-{disks,
##!      mount,files} stages apply the config.
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
      description = "ignition first-boot provisioning via virtio-blk + localhost HTTP";
      instanceMetadata = {
        format = "ignition";
        config = {
          ignition.version = "3.4.0";
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
