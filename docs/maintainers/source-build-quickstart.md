# Tutorial: Build and boot AOS from source

This tutorial builds a custom server image, supplies first-boot storage policy,
and boots the result under the AOS-built QEMU and UEFI firmware. The guest uses
DHCP and exposes SSH through a host port forward.

Run the commands from the repository root on an `x86_64-linux` machine with
Nix, KVM, and at least 20 GiB of free disk space.

## 1. Define the system image

Create `systems/demo-server.nix`:

```nix
{...}: {
  imports = [./server.nix];

  aos.networking.hostName = "aos-demo";
  aos.services.ssh.enable = true;

  environment.etc."ssh/authorized_keys/root" = {
    text = ''
      ssh-ed25519 AAAA_REPLACE_WITH_YOUR_PUBLIC_KEY operator@example.com
    '';
    mode = "0600";
  };
}
```

Replace the example public key before building. This file is part of the image
definition: do not put private keys or other secrets in it.

Build the raw disk image and the host-side tools used below:

```sh
nix-build -A systems.demo-server.build.image.raw -o result-aos-image
nix-build -A pkgs.qemu -o result-aos-qemu
nix-build -A pkgs.edk2 -o result-aos-edk2
nix-build -A pkgs.gptfdisk -o result-aos-gptfdisk
nix-build -A pkgs.libisoburn -o result-aos-libisoburn
nix-build -A pkgs.zstd -o result-aos-zstd
```

The image is `result-aos-image/aos-aos.img.zst`. It contains a zstd-compressed UEFI system
partition and the immutable `root-a` filesystem. Swap and `/var` are created in
free space on first boot.

## 2. Define first-boot storage

Create `host.nix` in the repository root:

```nix
{
  aos.provisioning.storage.partitions = {
    swap = {
      sizeMin = "1G";
      sizeMax = "1G";
    };

    var.sizeMin = "8G";
  };
}
```

`host.nix` is literal Nix, not JSON or cloud-config. This example focuses on
first-boot storage; the same policy can manage runtime hostname, networking,
firewall, service, and package configuration as described in the
[`host.nix` guide](../users/aos/host-nix.md). The storage layout is committed
once; changing this file after the first successful boot does not resize or
repartition the machine.

Put the file on an AOS metadata ISO:

```sh
mkdir -p aos-demo-metadata
cp host.nix aos-demo-metadata/host.nix
./result-aos-libisoburn/bin/xorriso -as mkisofs \
  -V aos-metadata \
  -o aos-demo-metadata.iso \
  aos-demo-metadata
```

The volume label and file name are part of the interface. A detached
`host.nix.sig` and `facts.json` may be placed on the same ISO in deployments
that use them.

## 3. Prepare a writable VM disk

Copy the immutable build result, grow the copy to 16 GiB, and move the backup
GPT header to the new end of the disk:

```sh
./result-aos-zstd/bin/zstd -d result-aos-image/aos-aos.img.zst -o aos-demo.img
chmod u+w aos-demo.img
truncate -s 16G aos-demo.img
./result-aos-gptfdisk/sbin/sgdisk -e aos-demo.img

cp result-aos-edk2/FV/OVMF_VARS.fd aos-demo-OVMF_VARS.fd
chmod u+w aos-demo-OVMF_VARS.fd
```

The stock storage policy needs more than 6 GiB of free space after `root-a`: a
fixed 2 GiB swap partition, a `/var` partition with a 4 GiB minimum, the
provisioning marker, and alignment. This tutorial asks for 1 GiB of swap and at
least 8 GiB for `/var`, so 16 GiB leaves comfortable room for the image and its
state partitions.

## 4. Boot the guest

```sh
./result-aos-qemu/bin/qemu-system-x86_64 \
  -machine q35,smm=on,accel=kvm \
  -cpu host \
  -m 4096 \
  -smp 2 \
  -nographic \
  -global driver=cfi.pflash01,property=secure,value=on \
  -global ICH9-LPC.disable_s3=1 \
  -drive if=pflash,unit=0,format=raw,readonly=on,file=result-aos-edk2/FV/OVMF_CODE.fd \
  -drive if=pflash,unit=1,format=raw,file=aos-demo-OVMF_VARS.fd \
  -drive file=aos-demo.img,format=raw,if=virtio \
  -drive id=metadata,file=aos-demo-metadata.iso,if=none,format=raw,readonly=on \
  -device virtio-scsi-pci,id=scsi0 \
  -device scsi-cd,drive=metadata,bus=scsi0.0 \
  -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22
```

Leave QEMU running. From another terminal, connect with the public key baked
into the image:

```sh
ssh -p 2222 root@127.0.0.1
```

The first boot may take longer while AOS commits the storage layout and creates
`/var`. If SSH is not ready, inspect the serial console in the QEMU terminal.

## 5. Inspect the running host

Inside the guest:

```sh
cat /etc/os-release
systemctl is-system-running
systemctl --failed
findmnt /
findmnt /var
lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS
cat /var/lib/aos-provisioning/audit.json
```

The root filesystem should be EROFS and read-only. `/var` should be a separate
writable filesystem, and the provisioning audit should record the operator
input.

Use `systemctl poweroff` to stop the guest. QEMU exits after the virtual machine
powers off.

You now have a system variant you can extend with services, users, firewall
policy, or static networking. Continue with
[Build and customize release images](system-images.md), then read
[Install an image](../users/aos/installation.md) before deploying the disk
outside this disposable VM.

## Clean up

The system variant is source code; keep it if it represents a real deployment.
The VM artifacts are disposable:

```sh
rm -r aos-demo-metadata
rm aos-demo-metadata.iso aos-demo.img aos-demo-OVMF_VARS.fd
rm host.nix
```
