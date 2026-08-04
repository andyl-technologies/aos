# `AOS // ANDYL OS`

**EARLY PREVIEW**

AOS is a Linux distribution tailored for headless environments like servers and IoT devices.

## Purpose

A lightweight operating system that runs on any host with a single image. AOS brings together all the great features of NixOS under a familiar package management system that users of `apt` or `yum` would be delighted to use.

As a guiding principle, every AOS binary has a clear and reproducible provenance and is entirely bootstrapped from source.

## Components

- **Universal image** for cloud and metal
- **Host configuration** via `host.nix` delivered as cloud user-data
- Runtime managed by **systemd**
- Package management built with **Nix**

## Documentation

User guides, including the [Crucible operations guide](docs/users/crucible/),
live under [`docs/users/`](docs/users/).

## Install

<details>
<summary>Bare-metal</summary>

Requirements:

- x86-64 with UEFI enabled (CSM disabled);
- A boot drive with 50GB of capacity or more;
- A thumb drive or (virtual) CD to hold instance metadata/user-data;
  - The commands below assume a thumb drive adapt them to your situation.
- Your favorite Linux live CD with the following utilities installed:
  - any kind of HTTP client (`curl`, `wget`…);
  - `coreutils` (for `dd` & `base64`);
  - `xorriso` (might be packaged under `libisoburn`);
  - `sed`;

Boot your live CD then download the [AOS image] to flash it onto your boot drive:

```bash
printf "boot drive = %s\n" "${BOOT_DRIVE:?"Please set BOOT_DRIVE to the path of the block device for AOS"}"
printf "image path = %s\n" "${AOS_IMAGE:?"Please set AOS_IMAGE to the path where the AOS disk image was downloaded}"
dd if="$AOS_IMAGE" of="$BOOT_DRIVE" bs=128k conv=fsync status=progress
```

Next, write the host policy as literal Nix. Storage lives under the one-time
`aos.provisioning` lifecycle namespace; normal runtime policy uses its ordinary
module namespaces:

```bash
printf "host.nix path = %s\n" "${HOST_NIX:?"Please set HOST_NIX to your host.nix"}"
printf "aos-metadata iso path = %s\n" "${ISO_OUT:="./aos-metadata.iso"}"

(
    set -e

    staging="$(mktemp --tmpdir -d aos-metadata-staging.XXXXXXXXXX)"
    trap "rm -rf $staging" EXIT

    cp "$HOST_NIX" "$staging/host.nix"

    xorriso \
        -as mkisofs \
        -volid aos-metadata \
        -output "$ISO_OUT" \
        -r $staging/
)
```

You may be able to use the ISO directly or you can write it to a thumb drive:

```bash
printf "metadata drive = %s\n" "${METADATA_DRIVE:?"Please set METADATA_DRIVE to the path of the block device for aos-metadata"}"

dd \
    if="${ISO_OUT:?"Please set ISO_OUT with the file produced at the previous step"}" \
    of="$METADATA_DRIVE" \
    bs=128k \
    conv=fsync
```

Once your drives are ready, reboot the machine from the boot drive and into AOS.

</details>

<details>
<summary>Vultr (Cloud/VPS)</summary>

Pre-requisites:

Create a `host.nix` containing the machine's storage and runtime policy, for
example:

```nix
{
  aos.provisioning.storage.partitions.var.sizeMin = "8G";
}
```

Installation:

- Login to console.vultr.com;
- Expand *Storage* on the left and select *Snapshots*:
- Click on *Create Snapshot* and select:
  - [ ] *Remote Snapshot*;
  - [ ] *Remote URL*: copy/paste the link to the [AOS image];
  - [ ] *Mark this snapshot as UEFI*;
  - [ ] Hit *Upload Snapshot*.
- Back to the left hand side menu expand *Compute* and select *Instances*:
- Click *Deploy Server* or *Create Instance* and select:
  - [ ] Figure out an instance type with 50GB of storage or more;
    - Shared CPU instances are gonna be the cheapest.
  - [ ] Click *Configure Software* at the bottom once your form is ready;
    - [ ] Select *Snapshot* as your image and use the uploaded snapshot;
    - [ ] Enable *Cloud-Init User Data* and paste the literal contents of `host.nix`;
    - [ ] Hit *Deploy*;
      - This should redirect you to the *Instance* page/table.
- You can access the server's console or lookup its IP from its detail page.

</details>

<!-- vim: set spell spelllang=en wrap: -->
