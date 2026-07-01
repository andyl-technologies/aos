# AOS — Andyl OS

AOS is a Linux distribution tailored for headless environments like servers and IoT devices. AOS has a clear and reproducible [provenance] thanks to its build process conducted with [Nix] and bootstrapped entirely from source.

## Purpose

We wanted a lightweight operating system that runs on any host with a single image that brings together all the great features of NixOS under a familiar package management system that users of `apt` or `yum` would be delighted to use.

## Components

- Universal image for cloud and metal
- [Host provisionning] via cloud-init (Ignition)
- Runtime managed by systemd
- [Package management] built with Nix

## Install

<details>
<summary>Bare-metal</summary>

Requirements:

- x86-64 with UEFI enabled (CSM disabled);
- A boot drive with 50GB of capacity or more;
- A thumb drive or (virtual) CD to hold the "cloud-init" instance metadata/userdata;
  - The commands below assume a thumb drive adapt them to your situation.
- Your favorite Linux live CD with the following utilities installed:
  - any kind of HTTP client (`curl`, `wget`…);
  - `coreutils` (for `dd` & `base64`);
  - `xorriso` (might be packaged under `libisoburn`);
  - `sed`;
- Your SSH public key.

Boot your live CD then download the [AOS image] to flash it onto your boot drive:

```bash
printf "boot drive = %s\n" "${BOOT_DRIVE:?"Please set BOOT_DRIVE to the path of the block device for AOS"}"
printf "image path = %s\n" "${AOS_IMAGE:?"Please set AOS_IMAGE to the path where the AOS disk image was downloaded}"
dd if="$AOS_IMAGE" of="$BOOT_DRIVE" bs=128k conv=fsync status=progress
```

Next, build `aos-metadata.iso` with a [minimal `config.json`] for Ignition set with your SSH public key and the expected path of your boot drive block device:

```bash
printf "boot drive = %s\n" "${BOOT_DRIVE:?"Please set BOOT_DRIVE to the path of the block device for AOS"}"
printf "ignition config path = %s\n" "${CONFIG_PATH:?"Please set CONFIG_PATH to the path of the ignition config.json"}"
printf "ssh public key = %s\n" "${SSH_PUBLIC_KEY:?"Please set SSH_PUBLIC_KEY (e.g. \`from ssh-add -L | cut -d' ' -f2)'"}"
printf "aos-metadata iso path = %s\n" "${ISO_OUT:="./aos-metadata.iso"}"

(
    set -e

    staging="$(mktemp --tmpdir -d aos-metadata-staging.XXXXXXXXXX)"
    trap "rm -rf $staging" EXIT

    sed \
        -e "s/REPLACE_ME_RUN_ssh-add_-L_pipe_base64_-w0/$SSH_PUBLIC_KEY/" \
        -e "s#/dev/vda#$BOOT_DRIVE#" \
        <"$CONFIG_PATH" \
        >"$staging/config.json"

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

Download the [minimal `config.json`] for Ignition and set your SSH public key in it, for example:

```bash
printf "ignition config path = %s\n" "${CONFIG_PATH:?"Please set CONFIG_PATH to the path of the ignition config.json"}"
printf "ssh public key = %s\n" "${SSH_PUBLIC_KEY:?"Please set SSH_PUBLIC_KEY (e.g. \`from ssh-add -L | cut -d' ' -f2)'"}"
perl -i -pe "s/REPLACE_ME_RUN_ssh-add_-L_pipe_base64_-w0/$SSH_PUBLIC_KEY/" "$CONFIG_PATH"
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
    - [ ] Enable *Cloud-Init User Data* and paste the content from `$CONFIG_PATH`;
    - [ ] Hit *Deploy*;
      - This should redirect you to the *Instance* page/table.
- You can access the server's console or lookup its IP from its detail page.

</details>


## Packages

## Develop



[AOS image]: 
[minimal `config.json`]: ./docs/users/install/minimal-config.json

[provenance]: ./docs/users/build_assurance.md

<!-- vim: set spell spelllang=en wrap: -->
