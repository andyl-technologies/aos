##! Pure architecture and dependency-role checks for the policy readback fixture.
##!
##! Inert package inputs expose the generated phase without realizing tools,
##! compiling init, or booting either guest architecture.
{lib}: let
  buildPackages = builtins.listToAttrs (builtins.map (name: {
    inherit name;
    value = "/fixture/build-${name}";
  }) ["coreutils" "cpio" "diffutils" "findutils" "grep" "qemu" "socat"]);
  fixture = architecture:
    import ../../pkgs/security/aos-selinux-kernel-policy-readback.nix {
      mkDerivation = args: args;
      stdenv.hostPlatform.constraints.cpu = architecture;
      inherit buildPackages;
      linux = "/fixture/target-kernel";
      aos-selinux-production-policy = "/fixture/target-policy";
    };
  native = fixture "x86_64";
  arm = fixture "aarch64";
  script = package: (builtins.head package.phases).script;
  commonContract = package: let
    phase = script package;
  in
    package.buildDeps
    == builtins.attrValues buildPackages
    && lib.hasInfix "/fixture/target-kernel/boot/vmlinuz-*" phase
    && lib.hasInfix "$CC -std=c17" phase
    && lib.hasInfix "-static" phase
    && lib.hasInfix "run_readback first\nrun_readback second" phase
    && lib.hasInfix "cmp readback-first.bin readback-second.bin" phase
    && lib.hasInfix ''"$elapsed" -ge 90'' phase
    && lib.hasInfix "sha256sum ${package.passthru.qemuBinary}" phase;
  unsupported = builtins.tryEval (fixture "riscv64").passthru.qemuPlatform;
in
  assert commonContract native;
  assert commonContract arm;
  assert native.passthru.qemuPlatform
  == {
    binary = "qemu-system-x86_64";
    machine = "q35,accel=tcg";
    cpu = "max";
    console = "ttyS0";
    serialDevice = "virtio-serial";
    kernelParameters = "noapic ";
  };
  assert arm.passthru.qemuPlatform
  == {
    binary = "qemu-system-aarch64";
    machine = "virt,accel=tcg";
    cpu = "cortex-a57";
    console = "ttyAMA0";
    serialDevice = "virtio-serial-pci";
    kernelParameters = "";
  };
  assert lib.hasInfix "-machine q35,accel=tcg -cpu max" (script native);
  assert lib.hasInfix "console=ttyS0,115200 noapic selinux=1" (script native);
  assert lib.hasInfix "-machine virt,accel=tcg -cpu cortex-a57" (script arm);
  assert lib.hasInfix "console=ttyAMA0,115200 selinux=1" (script arm);
  assert lib.hasInfix "-device virtio-serial-pci" (script arm);
  assert !(lib.hasInfix "qemu-system-x86_64" (script arm));
  assert !unsupported.success; "native tools, target kernel/init, and architecture-matched two-boot readback"
