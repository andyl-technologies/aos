# AOS user documentation

- [Install and operate AOS](aos/)
  - Start here
    - [Overview and operating model](aos/README.md)
    - [Support status](aos/support-status.md)
    - [Install an image](aos/installation.md)
    - [Configure a host](aos/configuration.md)
    - [Understand and operate host.nix](aos/host-nix.md)
    - [Configure networking](aos/networking.md)
    - [Deploy in production](aos/deployment.md)
  - Packages
    - [Manage packages](aos/packages.md)
    - [Configure package registries](aos/registries.md)
    - [Understand native package runtime policy](aos/package-sandbox.md)
    - [Use packages in containers](aos/containers.md)
  - Day-to-day operation
    - [Operate a host](aos/operations.md)
    - [Upgrade and roll back a host](aos/upgrades.md)
    - [Run ZFS storage](aos/storage-zfs.md)
    - [Troubleshoot a host](aos/troubleshooting.md)
    - [Recover a host](aos/recovery.md)
  - Security
    - [Use Secure Boot and verify package trust](aos/secure-boot.md)
    - [Control access](aos/access-control.md)
    - [Harden a host](aos/security-hardening.md)
    - [Audit a host](aos/auditing.md)
    - [Manage certificates and CA trust](aos/certificates.md)
    - [Manage secrets](aos/secrets.md)
  - Packaging and reference
    - [Package an application](aos/package-authoring.md)
    - [Runtime abilities](aos/runtime-abilities.md)
    - [Inspect ability plans and retained execution](aos/ability-inspection.md)
    - [Use the AOS command-line tools](aos/cli.md)
    - [Build and boot from source](aos/quickstart.md), a pointer to the
      [maintainer tutorial](../maintainers/source-build-quickstart.md)
- [Operate AOS Hub](aos-hub/)
  - [Run a local Hub](aos-hub/quickstart.md)
  - [Deploy the native server](aos-hub/native.md)
  - [Deploy to Cloudflare](aos-hub/cloudflare.md)
  - [Use the web interface](aos-hub/web.md)
  - [Use the API](aos-hub/api.md)
  - [Choose the right CLI](aos-hub/cli.md)
  - [Trust an internal AOS Hub deployment](aos-hub/trust.md)
  - [Serve OCI containers](aos-hub/oci-containers.md)
  - [Collect OCI garbage](aos-hub/oci-gc.md)
- [Operate an AOS package registry](registry/)
  - [Publish a signed local registry](registry/quickstart.md)
  - [Publish packages and releases](registry/publishing.md)
  - [Host a registry](registry/hosting.md)
  - [Configure consumer registries](aos/registries.md)
  - [Stage and schedule updates](registry/rollouts.md)
  - [Manage trust and incidents](registry/trust.md)
- [Operate Crucible](crucible/)
  - [Run Nginx and Curl in Crucible](crucible/quickstart.md)

## Related documentation

Building images, publishing releases, and maintaining a fork are covered in the
[maintainer documentation](../maintainers/README.md). How each component is
implemented and why is covered in the
[engineering documentation](../engineering/README.md).
