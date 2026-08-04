# Boot AOS under QEMU and UEFI

The operator procedure for building, sizing, provisioning, and booting an AOS
image under the AOS-built QEMU and EDK2 firmware is maintained in the
[AOS first-boot tutorial](../users/aos/quickstart.md).

For deployment outside a local VM, use the [installation guide](../users/aos/installation.md).
The [`host.nix` guide](../users/aos/host-nix.md) documents metadata channels,
signed configuration, first-boot storage, drift, and diagnostics.

AOS images are self-booting UEFI disk images. Do not pass a separate kernel,
initrd, or kernel command line. The current provisioning interface consumes
literal `host.nix`; it does not use Ignition or the CoreOS `fw_cfg` key.
