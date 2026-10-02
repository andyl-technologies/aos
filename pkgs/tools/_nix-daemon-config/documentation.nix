##! Package-owned Nix daemon operation and lifecycle documentation.
{lib}: let
  inherit (lib.aosDoc) code inlineCode list paragraph section text;
in {
  summary = "Package-owned multi-user Nix daemon";
  sections = {
    overview = section "Multi-user Nix builds" [
      (paragraph [
        (inlineCode "nix")
        (text " provides the executable payload. Select the separate ")
        (inlineCode "nix-daemon")
        (text " APM package and enable its package-owned interface to run a multi-user daemon:")
      ])

      (code "nix" ''
        {
          aos.apm.desiredPackages = [ "nix-daemon" ];
          nix-daemon = {
            enable = true;
            buildUsers.count = 8;
            buildDirectory = "/var/cache/nix-build";
            settings = {
              max-jobs = 2;
              cores = 1;
              sandbox = true;
              sandbox-fallback = false;
              allowed-users = [ "*" ];
              trusted-users = [ "root" ];
              experimental-features = [ "nix-command" "flakes" ];
            };
            resources = {
              cpuQuotaCores = 2;
              memoryHigh = "50%";
              memoryMax = "70%";
              memorySwapMax = "0";
            };
            scheduling = {
              cpuPolicy = "batch";
              ioClass = "best-effort";
              ioPriority = 5;
              oomScoreAdjust = 500;
            };
            clients.enable = true;
          };
        }
      '')

      (paragraph [
        (text "These values are the defaults except ")
        (inlineCode "enable")
        (text ", which defaults to ")
        (inlineCode "false")
        (text ". Package admission requires host policy allowing privileged services. The root daemon intentionally has an unconfined APM classification: Nix itself creates the build sandboxes and switches to locked non-root build accounts. The service requires an AOS image providing immutable ")
        (inlineCode "packageServicePolicyAbi >= 2")
        (text "; older images fail evaluation with an upgrade diagnostic.")
      ])
    ];

    configuration = section "Configuration and clients" [
      (paragraph [
        (text "The canonical store is ")
        (inlineCode "/nix/store")
        (text "; clients connect through ")
        (inlineCode "/nix/var/nix/daemon-socket/socket")
        (text ". The service waits for AOS Nix database initialization and does not replace the store or recursively change ownership. Native configuration lives in ")
        (inlineCode "/etc/aos/packages/nix-daemon/nix.conf")
        (text ", separately from the image-owned ")
        (inlineCode "/etc/nix/nix.conf")
        (text ".")
      ])

      (paragraph [
        (text "With ")
        (inlineCode "clients.enable")
        (text ", new login shells export ")
        (inlineCode "NIX_REMOTE=daemon")
        (text " and ")
        (inlineCode "NIX_CONF_DIR=/etc/aos/packages/nix-daemon")
        (text ". Existing shells retain their environment. APM's privileged store management explicitly selects the local store and baseline configuration, so configuration activation and garbage collection do not depend on the daemon being available.")
      ])

      (paragraph [
        (inlineCode "settings")
        (text " includes typed common options and accepts ordinary upstream settings as booleans, integers, single-line strings, or lists of tokens. Names must be lowercase kebab-case; values cannot inject comments or configuration directives. Nix validates the upstream meaning of additional settings. The package derives ")
        (inlineCode "build-users-group")
        (text ", ")
        (inlineCode "build-dir")
        (text ", and the mandatory ")
        (inlineCode "/bin/sh")
        (text " sandbox mapping to its signed AOS Bash dependency; those settings cannot be overridden. Explicit ")
        (inlineCode "extra-sandbox-paths")
        (text " are supported but cannot replace that mapping or its ancestors. No development cache mounts, emulation platforms, or KVM capabilities are advertised by default. Configure those only when the host provides them.")
      ])

      (paragraph [
        (text "Local ")
        (inlineCode "max-jobs")
        (text " must be between zero and ")
        (inlineCode "buildUsers.count")
        (text "; zero is available for remote-only builds. Remote builder specifications and experimental features remain available. Automatic store garbage collection is off by default (")
        (inlineCode "min-free = 0")
        (text ", ")
        (inlineCode "max-free = 0")
        (text "); explicit valid thresholds can enable it.")
      ])

      (paragraph [
        (text "The build directory must have trusted root-owned ancestry without symlinks or group/other writes. The daemon prepares the final directory as root with mode 0755. Its signed unit has a narrowly validated ")
        (inlineCode "RequiresMountsFor")
        (text " projection. Declare a mount unit for any intended separate backing filesystem: systemd cannot infer an undeclared disk from the directory name.")
      ])
    ];

    resources = section "Resource policy and restarts" [
      (paragraph [
        (text "The package-owned ")
        (inlineCode "aos-pkg-nix-daemon-builds.slice")
        (text " imposes aggregate CPU, memory, and swap limits on the daemon and its build workers. The policy service runs in the enclosing package slice, outside those limits, so configuration can recover from an insufficient build memory limit. CPU quota is a positive number of cores. Memory limits accept positive byte counts, ")
        (inlineCode "K")
        (text "/")
        (inlineCode "M")
        (text "/")
        (inlineCode "G")
        (text "/")
        (inlineCode "T")
        (text ", percentages from 1% through 100%, ")
        (inlineCode "0")
        (text ", or ")
        (inlineCode "infinity")
        (text ". Scheduling supports CPU ")
        (inlineCode "other")
        (text ", ")
        (inlineCode "batch")
        (text ", or ")
        (inlineCode "idle")
        (text ", I/O ")
        (inlineCode "best-effort")
        (text " or ")
        (inlineCode "idle")
        (text ", priorities 0 through 7, and OOM scores 0 through 1000.")
      ])

      (paragraph "Signed runtime metadata binds native configuration and projected policy bytes to transactional restarts. A policy service reconciles every resource property on every change, including disabled generations and rollback. This resets old runtime overrides rather than allowing them to outrank the selected policy. The validator covers the package's authenticated direct unit drop-ins; it is not an effective-systemd audit of root-authored overlays or inherited drop-ins.")

      (paragraph "Daemon restart stops the listener process while allowing existing Nix workers to finish in the same resource slice. Scheduling changes affect newly started processes. Memory policy can terminate workers under pressure; preserving workers across a restart is not a guarantee that every build will succeed.")
    ];

    lifecycle = section "Disable, drain, and remove" [
      (paragraph [
        (text "The signed package authorizes a fixed pool of ")
        (inlineCode "nixbld1")
        (text " through ")
        (inlineCode "nixbld64")
        (text ", with UIDs 30001 through 30064 and GID 30000 for ")
        (inlineCode "nixbld")
        (text ". The image permanently reserves these names and numeric identities and rejects collisions or remapping. The selected package always retains all 64 locked accounts. ")
        (inlineCode "buildUsers.count")
        (text " (1 through 64) controls explicit eligible group membership; reducing it does not remove or reuse accounts while older builds continue.")
      ])

      (list {
        ordered = true;
        items = [
          [
            (paragraph [
              (text "Set ")
              (inlineCode "nix-daemon.enable = false")
              (text " and activate the configuration. The socket closes and cannot activate the disabled daemon. Accounts, store contents, and existing workers remain.")
            ])
          ]
          [(paragraph "Wait for builds to finish. Disable does not implement a drain request or cancel workers.")]
          [
            (paragraph [
              (text "Remove ")
              (inlineCode "nix-daemon")
              (text " from desired packages and remove its interface settings. Activation refuses account removal while a reserved identity is running, the listener/socket is active, or the worker cgroup cannot be verified. An empty retired inactive slice is accepted.")
            ])
          ]
        ];
      })

      (paragraph "After successful removal, generated account entries disappear. Their numeric identities remain reserved by the image and must not be assigned to other accounts. Store contents and completed outputs remain; ordinary AOS store management decides their later retention.")
    ];
  };
}
