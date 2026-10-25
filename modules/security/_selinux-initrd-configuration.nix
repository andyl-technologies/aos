# Retains the selected SELinux labeling inputs for native initrd replay.
{
  lib,
  policy,
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
  configurationData = lib.recursiveUpdate selection {
    aos.abilities.configuration.operations.file.effects = contextEffects;
  };
  # Runtime evaluation admits this module by its own fixed NAR. Embed the
  # static selection so replay never imports an unadmitted absolute store path.
  configuration = builtins.toFile "aos-selinux-initrd-policy.nix" ''
    builtins.fromJSON ${builtins.toJSON (builtins.unsafeDiscardStringContext (builtins.toJSON configurationData))}
  '';
in {
  configuration = [configuration];
  # The retained module carries public path data. This separate admitted
  # input preserves the actual producer dependency without an IFD.
  supplementalInputs = ["${policy}"];
}
