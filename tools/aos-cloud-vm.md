# AOS cloud VM helper

Run `bash tools/aos-cloud-vm --help` for all options. The helper imports a
verified immutable Hub raw image and launches one Spot VM on GCP or AWS.

Prerequisites: an `aos` binary supporting `image download --metadata-only`,
Bash, Python 3, jq, coreutils, GNU tar, gzip, zstd, gptfdisk (`sgdisk`), and the
provider CLI. Supply existing cloud scope, bucket, network, and credentials;
AWS also needs a VM Import/Export role. The helper grants no IAM permissions.
The image must advertise EFI and the required VirtIO or NVMe/ENA drivers.

Replace every placeholder and restrict the SSH source CIDR:

```bash
bash tools/aos-cloud-vm up \
  --provider gcp --project example-project \
  --region us-central1 --zone us-central1-a \
  --network example-network --subnet example-subnet --bucket example-bucket \
  --name example-vm --state-dir ./cloud-state/example-vm \
  --hub https://hub.example --registry example --package server --release 1.2.3 \
  --machine-type e2-standard-2 --disk-size 32 \
  --ssh-key ./operator.pub --ssh-cidr 192.0.2.10/32 \
  --set aos.networking.hostName=example-vm
```

`plan` verifies inputs without provider operations; `image-create` and
`vm-create` split the two stages of `up`. SSH uses root public-key login on
port 22; initial configuration can take several minutes. Private access needs
an existing route and firewall policy; AWS also requires `--security-group`.

The first `--config` retains direct operator priority (75); later files are
ordinary imports. `--set` parses JSON literals, otherwise strings, at priority
60; explicit `mkForce` (50) still wins. `--set-string` and `--set-file` provide
literal strings and public file contents. Nix remains the evaluator.

Self-contained configurations work on existing images. Relative imports and
JSON/TOML data trees use `--config-root`, requiring authenticated image
capability `aos.config-bundle/v1`; GCP signed or large inputs also need it.
The bounded bundle retains its complete
source and authorization for evaluation and recovery. Include only public
configuration. Signed object URLs expire; keep local state private and choose
`--config-url-ttl` for initial boot. GCP pointer delivery needs `--url-signer`.

Reuse an imported image with a new state directory and `--image-state-dir`.
`delete --provider gcp --name example-vm --state-dir ./cloud-state/example-vm`
removes the recorded VM, ingress, and configuration objects; `--delete-image`
also removes owned import artifacts once no consumers need them.

GCP uses UEFI with Secure Boot disabled and explicit VirtIO networking. AWS
uses raw snapshot import and AMI registration; its boot path still needs live
qualification. Run the offline check with
`bash ./aos-dev build check build.aos-cloud-vm --no-out-link`.
