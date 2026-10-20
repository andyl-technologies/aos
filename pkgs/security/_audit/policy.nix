##! Canonical Linux audit policy and optional finite input/retention bounds.
{lib, ...}: {
  options.aos.security.audit = {
    enable = lib.mkOption {
      extensible = true;
      type = lib.types.bool;
      default = true;
      description = "Enable the Linux audit framework and its rule loader.";
    };
    rules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "-a always,exit -F arch=b64 -S execve -k exec"
        "-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules"
        "-a always,exit -F arch=b64 -S mount -S umount2 -k mounts"
        "-w /etc/passwd -p wa -k user_modification"
        "-w /etc/group -p wa -k group_modification"
        "-w /etc/shadow -p wa -k shadow_modification"
        "-w /etc/gshadow -p wa -k gshadow_modification"
        "-w /etc/selinux/ -p wa -k selinux_policy"
        "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config"
        "-w /etc/hostname -p wa -k network_config"
        "-w /etc/ssh/sshd_config -p wa -k sshd_config"
        "-w /var/log/audit/ -p wa -k audit_log"
        "-w /etc/sudoers -p wa -k sudoers"
        "-w /etc/sudoers.d/ -p wa -k sudoers"
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change"
        "-w /etc/localtime -p wa -k time_change"
      ];
      description = "Audit rules in auditctl(8) format.";
    };
    backlogLimit = lib.mkOption {
      type = lib.types.ints.between 1 9007199254740991;
      default = 8192;
      description = "Kernel audit backlog buffer size.";
    };
    failureMode = lib.mkOption {
      type = lib.types.ints.between 0 2;
      default = 1;
      description = "Kernel audit failure action: silent, printk, or panic.";
    };
    bounds = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          maxLogFileMiB = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Finite audit rotation target in MiB, not a hard filesystem quota.";
          };
          numLogs = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value >= 2 && value <= 99);
            description = "Finite rotated audit file count; the active file and rotation overshoot remain separately charged.";
          };
          maximumRules = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Maximum configured audit rule count before the rule loader runs.";
          };
          maximumRuleBytes = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Maximum byte length of each configured audit rule.";
          };
          maximumBacklog = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Maximum configured kernel audit queue entry count; kernel memory ownership is separate from auditd's cgroup.";
          };
        };
      });
      default = null;
      description = "Optional image-selected audit input and retention bounds; absence preserves the ordinary audit configuration.";
    };
  };
}
