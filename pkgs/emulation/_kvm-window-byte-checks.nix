# Mandatory source/caller checks for the opt-in KVM window/byte components.
# These compile actual source functions with explicitly modeled native plumbing;
# they do not install a kernel, enter a guest, or qualify a KVM node.
{
  python3,
  patch,
  linuxSource,
}: let
  fixtures = ./qemu-patches/_fixtures/kvm-window-bytes;
  legacyFixtures = ./qemu-patches/_fixtures;
  kernelPatches = ../kernel;
  stage5 = kernelPatches + "/crucible-controller-completion-stage5-7.2.3.patch";
  sourceArchive =
    if linuxSource != null && linuxSource.version == "7.2.3"
    then linuxSource.src
    else throw "KVM component proofs require the pinned Linux 7.2.3 source";
in ''
  ${python3}/bin/python3 ${fixtures}/materialize-kernel.py \
    ${sourceArchive} "$PWD/kvm-component-kernel" ${patch}/bin/patch \
    ${kernelPatches}/crucible-controller-clock-7.2.3.patch \
    ${kernelPatches}/crucible-controller-clock-stage2-7.2.3.patch \
    ${kernelPatches}/crucible-controller-clock-stage3-7.2.3.patch \
    ${kernelPatches}/crucible-controller-clock-stage4-7.2.3.patch \
    ${stage5} \
    ${kernelPatches}/crucible-controller-run-return-stage6-7.2.3.patch \
    ${kernelPatches}/crucible-controller-response-bytes-stage7-7.2.3.patch

  ${python3}/bin/python3 ${fixtures}/window/model.py \
    "$PWD" "$PWD/kvm-component-kernel/stage6" "$CC" "$PWD/kvm-window-proof"
  ${python3}/bin/python3 ${fixtures}/window/mutations.py \
    "$PWD" "$PWD/kvm-component-kernel/stage6" "$CC" "$PWD/kvm-window-mutants"
  ${python3}/bin/python3 ${fixtures}/window/window-producer.py \
    "$PWD" "$CC" "$PWD/kvm-window-producer-proof"
  ${python3}/bin/python3 ${fixtures}/window/producer-mutations.py \
    "$PWD" "$CC" "$PWD/kvm-window-producer-mutants"
  ${python3}/bin/python3 ${fixtures}/window/refusal.py \
    build/qemu-system-x86_64 build/qemu-system-aarch64 \
    ${legacyFixtures}/kvm-component-refusal.py

  ${python3}/bin/python3 ${fixtures}/initial/model.py \
    "$PWD" "$CC" "$PWD/kvm-initial-response-proof" ${stage5}
  ${python3}/bin/python3 ${fixtures}/initial/mutations.py \
    "$PWD" "$CC" "$PWD/kvm-initial-response-mutants" ${stage5}
  ${python3}/bin/python3 ${fixtures}/initial/refusal.py \
    build/qemu-system-x86_64 build/qemu-system-aarch64 \
    ${legacyFixtures}/kvm-component-refusal.py

  ${python3}/bin/python3 ${fixtures}/lifetime/model.py \
    "$PWD" "$CC" "$PWD/kvm-original-resource-proof"
  ${python3}/bin/python3 ${fixtures}/lifetime/mutations.py \
    "$PWD" "$CC" "$PWD/kvm-original-resource-mutants"

  ${python3}/bin/python3 ${fixtures}/bytes/guards.py \
    "$PWD" ${fixtures}/bytes/compatibility.json
  ${python3}/bin/python3 ${fixtures}/bytes/model.py \
    "$PWD" "$PWD/kvm-component-kernel" "$CC" "$PWD/kvm-response-byte-proof"
  ${python3}/bin/python3 ${fixtures}/bytes/mutations.py \
    "$PWD" "$PWD/kvm-component-kernel" "$CC" "$PWD/kvm-response-byte-mutants"
  ${python3}/bin/python3 ${fixtures}/bytes/refusal.py \
    build/qemu-system-x86_64 build/qemu-system-aarch64 \
    ${legacyFixtures}/kvm-component-refusal.py
''
