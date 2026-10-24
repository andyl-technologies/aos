# Retains the selected SELinux labeling inputs for native initrd replay.
{
  lib,
  policy,
}: let
  selection = builtins.path {
    path = ./_selinux-initrd-policy.nix;
    name = "aos-selinux-initrd-policy.nix";
  };

  # PID 1 opens a userspace labeling handle as soon as SELinux is detected.
  # Copy the exact selected text and substitutions without evaluation-time
  # reads of derivation outputs or large text in provider invocations.
  contextFiles = [
    {
      name = "file-contexts";
      path = "files/file_contexts";
    }
    {
      name = "file-context-substitutions";
      path = "files/file_contexts.subs_dist";
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
  configuration = builtins.toFile "aos-selinux-initrd-policy.nix" ''
    {
      imports = [${selection}];
      aos.abilities.configuration.operations.file.effects =
        builtins.fromJSON ${builtins.toJSON (builtins.unsafeDiscardStringContext (builtins.toJSON contextEffects))};
    }
  '';
in {
  configuration = [configuration];
  # The retained module carries public path data. This separate admitted
  # input preserves the actual producer dependency without an IFD.
  supplementalInputs = ["${policy}"];
}
