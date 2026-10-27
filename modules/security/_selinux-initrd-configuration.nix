# Retains the selected SELinux labeling inputs for native initrd replay.
{
  lib,
  policy,
  protectedRootPreparation ? null,
  protectMeasuredVar ? false,
}: let
  selection = import ./_selinux-initrd-policy.nix;

  # PID 1 opens a userspace labeling handle as soon as SELinux is detected.
  # Native configuration also starts D-Bus before switch-root, where it reads
  # the selected bus contexts. Retain each consumer's canonical policy input
  # without reading derivation outputs during evaluation.
  contextFiles = [
    {
      name = "file-contexts";
      path = "files/file_contexts";
    }
    {
      name = "file-context-substitutions";
      path = "files/file_contexts.subs_dist";
    }
    {
      name = "dbus-contexts";
      path = "dbus_contexts";
    }
  ];
  contextEffects = lib.listToAttrs (map (file: {
      name = "selinux-initrd-${file.name}";
      value.input = {
        path = "/etc/selinux/aos/contexts/${file.path}";
        mode = "0444";
        fragments = [
          {
            storePath = "${policy}/etc/selinux/aos/contexts/${file.path}";
            maximumBytes = 1048576;
          }
        ];
      };
    })
    contextFiles);
  # Package-only initrd replay cannot inspect host Sandbox selections. Carry
  # the exact image-selected preparation as data admitted with its executable.
  configurationData =
    lib.recursiveUpdate
    (lib.recursiveUpdate selection {
      aos.abilities.configuration.operations.file.effects = contextEffects;
    })
    (lib.optionalAttrs (protectedRootPreparation != null) {
      aos.boot.substrateServices.protectedRootPreparation = protectedRootPreparation;
      # The format owner must establish this label before mount-var verifies it.
      # Retaining only the mount recipe would reject a fresh state filesystem.
      aos.storageProvisioning.protectedVarContext = protectedRootPreparation.varRootContext;
      aos.security = lib.optionalAttrs protectMeasuredVar {
        measuredVar.protectedVarContext = protectedRootPreparation.varRootContext;
      };
    });
  # Runtime evaluation admits this module by its own fixed NAR. Embed the
  # static selection so replay never imports an unadmitted absolute store path.
  configuration = builtins.toFile "aos-selinux-initrd-policy.nix" ''
    builtins.fromJSON ${builtins.toJSON (builtins.unsafeDiscardStringContext (builtins.toJSON configurationData))}
  '';
in {
  configuration = [configuration];
  # The retained module carries public path data. This separate admitted
  # input preserves the actual producer dependency without an IFD.
  supplementalInputs =
    ["${policy}"]
    ++ lib.optional (protectedRootPreparation != null)
    (builtins.dirOf (builtins.dirOf protectedRootPreparation.executable));
}
