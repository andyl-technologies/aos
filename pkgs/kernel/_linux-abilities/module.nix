##! Linux kernel artifact implementation selected through the ability graph.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  packageName,
  packageVersion,
  ...
}: let
  kernelInterface = lib.abilities.interfaces.kernelPlatform.interfaces.kernel;
  kernelArtifactSelector = lib.abilities.packageOutput {};
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "kernel";
  selected =
    builtins.length selectedBindings == 1
    && (builtins.head selectedBindings).binding.request == "system:kernel";
  selectedBinding =
    if selected
    then builtins.head selectedBindings
    else if selectedBindings != []
    then throw "the Linux kernel implementation requires exactly one system:kernel binding"
    else null;
  selectedKernelOutput =
    config.aos.abilities.compositionOutputs."system:kernel"."selected-kernel".value or null;
  kernelArtifact = packageArtifactFor kernelArtifactSelector;
  authoredKernel = {
    _type = "aos-selected-kernel";
    artifact = selectedKernelOutput;
    name = "linux";
    package = kernelArtifact;
    targetPlatform = config.aos.kernel.targetPlatform;
    identity = {
      binding = selectedBinding.navigationKey;
      implementation = selectedBinding.binding.implementation;
      package = {
        name = packageName;
        version = packageVersion;
      };
      providerInstance = selectedBinding.providerInstance.identity;
    };
    configuration = {
      bootImage = "${kernelArtifact}/boot/vmlinuz-${packageVersion}";
      moduleTree = "${kernelArtifact}/lib/modules/${packageVersion}";
      release = packageVersion;
    };
  };
  kernel =
    if
      selectedKernelOutput != null
      && selectedKernelOutput._type == "aos-artifact-reference"
      && selectedKernelOutput.store_path == builtins.toString kernelArtifact
    then authoredKernel
    else throw "selected kernel projection differs from its checked planning output";
in {
  config = {
    aos.abilities = {
      implementations.kernel = {
        description = "Supplies the selected Linux kernel artifact and module ABI.";
        interface = kernelInterface.alias;
        artifact = kernelArtifactSelector;
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = kernelArtifactSelector;
          path = "share/aos/providers/linux.nix";
        };
      };
    };

    aos.kernel.selected = lib.mkIf selected kernel;
  };
}
