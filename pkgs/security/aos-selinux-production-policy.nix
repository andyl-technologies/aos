##! Offline final SELinux policy for the production Linux kernel.
{
  mkDerivation,
  linux,
  refpolicy-production,
  checkpolicy,
  semodule-utils,
  libselinux,
  secilc,
  setools,
  python3,
  aos-netd,
  aos-filesystem-fuse-worker,
  aos-sandbox-zfs-worker,
  aos-sandboxd,
  aos-storaged,
  aos-sandbox-mountd,
  aos-source-providerd,
  systemd,
  aos-method46-tpm-helper,
  aos-sandbox-view-preparer-tools,
  viewPreparers ? [],
  homeContextAliases ? "",
  gitReadDelegation ? false,
  sourceProviderMount ? false,
  onlineNix ? false,
  runtimeDeploymentPublisher ? false,
  resourceBankEnrollment ? false,
  hostComponentControl ? false,
  aos-nix-runtime-tpm-helpers ? null,
  aos-nix-online-store-reader ? null,
}: let
  policyVersion = "33";
  policySupport = ./_aos-selinux-production-policy;
  gitReadCheckerArgument = if gitReadDelegation then "--git-read-delegation" else "";
  homeAliases = builtins.toFile "aos-selinux-home-context-aliases" homeContextAliases;
  closedOnlineSource = source: let
    parts = builtins.split "\n# AOS_ONLINE_NIX_BEGIN\n" source;
    ending =
      if builtins.length parts == 3
      then builtins.split "# AOS_ONLINE_NIX_END\n" (builtins.elemAt parts 2)
      else [];
  in
    if builtins.length parts != 3 || builtins.length ending != 3
    then throw "online Nix policy requires exactly one closed block"
    else if onlineNix
    then source
    else builtins.elemAt parts 0 + "\n" + builtins.elemAt ending 2;
  # Host055 is independent of both Online Nix and the strict Mount suffix.
  # Accepted Host57 native state/namespace/pidfs cells remain in the base.
  closedRuntimeSource = source: let
    parts = builtins.split "\n# AOS_HOST_RUNTIME_BEGIN\n" source;
    ending =
      if builtins.length parts == 3
      then builtins.split "# AOS_HOST_RUNTIME_END\n" (builtins.elemAt parts 2)
      else [];
  in
    if builtins.length parts != 3 || builtins.length ending != 3
      || builtins.length (builtins.split "# AOS_HOST_RUNTIME_END\n" source) != 3
    then throw "Host runtime policy requires exactly one closed block"
    else if runtimeDeploymentPublisher
    then source
    else builtins.elemAt parts 0 + "\n" + builtins.elemAt ending 2;
  closedResourceBankSource = source: let
    parts = builtins.split "\n# AOS_RESOURCE_BANK_ENROLLMENT_BEGIN\n" source;
    ending =
      if builtins.length parts == 3
      then builtins.split "# AOS_RESOURCE_BANK_ENROLLMENT_END\n" (builtins.elemAt parts 2)
      else [];
  in
    if builtins.length parts != 3 || builtins.length ending != 3
      || builtins.length (builtins.split "# AOS_RESOURCE_BANK_ENROLLMENT_BEGIN\n" source) != 3
      || builtins.length (builtins.split "# AOS_RESOURCE_BANK_ENROLLMENT_END\n" source) != 3
    then throw "resource bank policy requires exactly one closed block"
    else if resourceBankEnrollment
    then source
    else builtins.elemAt parts 0 + "\n" + builtins.elemAt ending 2;
  closedHostComponentSource = source: let
    parts = builtins.split "\n# AOS_HOST_COMPONENT_CONTROL_BEGIN\n" source;
    ending =
      if builtins.length parts == 3
      then builtins.split "# AOS_HOST_COMPONENT_CONTROL_END\n" (builtins.elemAt parts 2)
      else [];
  in
    if builtins.length parts != 3 || builtins.length ending != 3
      || builtins.length (builtins.split "# AOS_HOST_COMPONENT_CONTROL_BEGIN\n" source) != 3
      || builtins.length (builtins.split "# AOS_HOST_COMPONENT_CONTROL_END\n" source) != 3
    then throw "Host component policy requires exactly one closed block"
    else if hostComponentControl
    then source
    else builtins.elemAt parts 0 + "\n" + builtins.elemAt ending 2;
  # The suffix has one fixed beginning and ending, and no trailing source.
  # The false branch restores the exact original newline, not a blank block.
  closedSelectedSource = path: let
    source = closedRuntimeSource (
      if path == policySupport + "/owner_confinement.te"
      then closedHostComponentSource (closedResourceBankSource (closedOnlineSource (builtins.readFile path)))
      else builtins.readFile path
    );
    parts = builtins.split "\n# AOS_SELECTED_MOUNT_SOURCE_BEGIN\n" source;
    ending =
      if builtins.length parts == 3
      then builtins.split "# AOS_SELECTED_MOUNT_SOURCE_END\n" (builtins.elemAt parts 2)
      else [];
  in
    if builtins.length parts != 3 || builtins.length ending != 3 || builtins.elemAt ending 2 != ""
    then throw "selected Mount/Source policy requires exactly one closed suffix"
    else if sourceProviderMount
    then source
    else builtins.elemAt parts 0 + "\n";
  replaceSelectedInitializer = pattern: literal: replacement: source:
    if builtins.length (builtins.split pattern source) != 3
    then throw "selected owner DATA requires exactly one fixed initializer"
    else builtins.replaceStrings [literal] [replacement] source;
  resourceBankOwnerData =
    if resourceBankEnrollment
    then replaceSelectedInitializer
      "RESOURCE_BANK_RECIPIENTS = \\(\\)"
      "RESOURCE_BANK_RECIPIENTS = ()"
      "RESOURCE_BANK_RECIPIENTS = RESOURCE_BANK_KNOWN_RECIPIENTS"
      (builtins.readFile (policySupport + "/owner_policy.py"))
    else builtins.readFile (policySupport + "/owner_policy.py");
  runtimeOwnerData =
    if runtimeDeploymentPublisher
    then replaceSelectedInitializer
      "RUNTIME_DOMAINS = \\(\\)"
      "RUNTIME_DOMAINS = ()"
      "RUNTIME_DOMAINS = RUNTIME_KNOWN_DOMAINS"
      resourceBankOwnerData
    else resourceBankOwnerData;
  mountSourceOwnerData =
    if !sourceProviderMount
    then runtimeOwnerData
    else (
      replaceSelectedInitializer
      "SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS = frozenset\\(\\)"
      "SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS = frozenset()"
      "SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS = frozenset({0x6686})"
      (
        replaceSelectedInitializer
        "SELECTED_MOUNT_SOURCE_DOMAINS = \\(\\)"
        "SELECTED_MOUNT_SOURCE_DOMAINS = ()"
        "SELECTED_MOUNT_SOURCE_DOMAINS = (\"aos_sandbox_mount_t\", \"aos_source_provider_t\")"
        runtimeOwnerData
      )
    );
  selectedOwnerData = builtins.toFile "aos-selected-owner-policy.py" (
    if onlineNix
    then replaceSelectedInitializer
      "ONLINE_NIX_DOMAINS = \\(\\)"
      "ONLINE_NIX_DOMAINS = ()"
      "ONLINE_NIX_DOMAINS = ONLINE_NIX_KNOWN_DOMAINS"
      mountSourceOwnerData
    else mountSourceOwnerData
  );
  selectedEffectiveData = builtins.toFile "aos-selected-effective-policy.py" (
    if hostComponentControl
    then replaceSelectedInitializer
      "HOST_COMPONENT_CONTROL = False"
      "HOST_COMPONENT_CONTROL = False"
      "HOST_COMPONENT_CONTROL = True"
      (builtins.readFile (policySupport + "/effective_policy.py"))
    else builtins.readFile (policySupport + "/effective_policy.py")
  );
  # Selected checks import the rendered immutable DATA beside the same checker.
  # No policy observation or runtime option chooses its expected permissions.
  checkerScript =
    if sourceProviderMount || onlineNix || runtimeDeploymentPublisher || resourceBankEnrollment || hostComponentControl
    then "selected-policy-checker/effective_policy.py"
    else "${policySupport}/effective_policy.py";
  # toFile cannot carry an output reference, and the policy must not build
  # the executable it labels. The system module co-installs this exact output.
  netdBasename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString aos-netd));
  netdBasenameRegex = builtins.replaceStrings ["."] ["\\."] netdBasename;
  publisherBasename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString aos-sandbox-zfs-worker));
  publisherBasenameRegex = builtins.replaceStrings ["."] ["\\."] publisherBasename;
  exactPublisherLabel =
    builtins.match "[a-z0-9]{32}-aos-sandbox-zfs-worker-[0-9]+\\.[0-9]+\\.[0-9]+" publisherBasename
    != null;
  exactPackageBasename = name: package: let
    basename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString package));
  in
    if builtins.match "[a-z0-9]{32}-${name}-[0-9]+\\.[0-9]+\\.[0-9]+" basename != null
    then builtins.replaceStrings ["."] ["\\."] basename
    else throw "${name} SELinux label requires its exact evaluated package root";
  onlinePackageBasename = name: package: let
    basename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString package));
  in
    if builtins.match "[a-z0-9]{32}-${name}-1" basename != null
    then builtins.replaceStrings ["."] ["\\."] basename
    else throw "online Nix SELinux label requires its exact evaluated package root";
  onlineFileContexts =
    if !onlineNix
    then ""
    else let
      domain = aos-nix-online-store-reader.domainIdHex;
      helperBasename = onlinePackageBasename "aos-nix-runtime-tpm-helpers" aos-nix-runtime-tpm-helpers;
      readerBasename = onlinePackageBasename "aos-nix-online-store-reader-${domain}" aos-nix-online-store-reader;
      sandboxBasename = exactPackageBasename "aos-sandboxd" aos-sandboxd;
    in
      if builtins.match "[0-9a-f]{32}" domain == null || domain == "00000000000000000000000000000000"
      then throw "online Nix file contexts require the selected nonzero domain"
      else ''
        /(nix|nix\.lower)/store/${sandboxBasename}/bin/aos-sandbox-nixd -- system_u:object_r:aos_sandbox_nix_exec_t
        /(nix|nix\.lower)/store/${helperBasename}/libexec/aos-nix-controller-tpm-helper -- system_u:object_r:aos_nix_controller_floor_helper_exec_t
        /(nix|nix\.lower)/store/${helperBasename}/libexec/aos-nix-owner-tpm-helper -- system_u:object_r:aos_nix_owner_floor_helper_exec_t
        /(nix|nix\.lower)/store/${readerBasename}/libexec/aos-nix-online-store-reader -- system_u:object_r:aos_nix_online_store_reader_exec_t
        /(nix|nix\.lower)/store/[a-z0-9]{32}-aos-nix-startup-profile-2(/.*)? system_u:object_r:aos_nix_startup_profile_t
        /var/lib/aos/sandbox-nix/domains/${domain}/root(/.*)? system_u:object_r:aos_nix_online_store_t
        /var/lib/aos/sandbox-nix/domains/${domain}/root/nix/var/nix/gcroots/(aos-online|auto)(/.*)? system_u:object_r:aos_nix_online_gcroots_t
        /var/lib/aos/sandbox-nix/broker-session/controller(/.*)? system_u:object_r:aos_nix_online_owner_state_t
        /var/lib/aos/sandboxd/broker-session/nix(/.*)? system_u:object_r:aos_nix_online_controller_state_t
        /var/lib/aos/sandbox-nix/broker-session/controller/(session\.journal|tpm-floor\.journal)\.lock -- system_u:object_r:aos_nix_online_owner_lock_t
        /var/lib/aos/sandboxd/broker-session/nix/(session\.journal|tpm-floor\.journal)\.lock -- system_u:object_r:aos_nix_online_controller_lock_t
        /run/aos/sandbox-nix(/.*)? system_u:object_r:aos_nix_online_runtime_t
        /run/credentials/aos-sandbox-nixd\.service(/.*)? system_u:object_r:aos_nix_online_owner_credential_t
      '';
  # PID1's public comparison pin uses this same evaluated package as Storage.
  # Its two-component version must not widen the existing owner-label helper.
  systemdBasename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString systemd));
  systemdBasenameRegex = builtins.replaceStrings ["."] ["\\."] systemdBasename;
  systemdPinPathRegex = "/(nix|nix\\.lower)/store/${systemdBasenameRegex}/share/aos/backend-policy-artifact-v2";
  systemdPinPath = root: basename: "/${root}/store/${basename}/share/aos/backend-policy-artifact-v2";
  systemdSiblingBasename =
    (
      if builtins.substring 0 1 systemdBasename == "0"
      then "1"
      else "0"
    )
    + builtins.substring 1 (builtins.stringLength systemdBasename - 1) systemdBasename;
  systemdVersionSibling = builtins.replaceStrings ["-systemd-261.2"] ["-systemd-261.3"] systemdBasename;
  exactSystemdPinLabel =
    systemd.name == "systemd-261.2"
    && systemd.version == "261.2"
    && builtins.match "[a-z0-9]{32}-systemd-261\\.2" systemdBasename != null
    && builtins.match systemdPinPathRegex (systemdPinPath "nix" systemdBasename) != null
    && builtins.match systemdPinPathRegex (systemdPinPath "nix.lower" systemdBasename) != null
    && builtins.match systemdPinPathRegex (systemdPinPath "nix" systemdSiblingBasename) == null
    && systemdVersionSibling != systemdBasename
    && builtins.match systemdPinPathRegex (systemdPinPath "nix" systemdVersionSibling) == null
    && builtins.match systemdPinPathRegex (systemdPinPath "nix" (systemdBasename + "-alias")) == null
    && builtins.match systemdPinPathRegex ((systemdPinPath "nix" systemdBasename) + "0") == null
    && builtins.match systemdPinPathRegex ((systemdPinPath "nix" systemdBasename) + "/extra") == null;
  ownerModule = builtins.toFile "aos_sandbox.te" (
    builtins.readFile (policySupport + "/aos_sandbox.te")
    + "\n"
    + closedSelectedSource (policySupport + "/owner_confinement.te")
    + "\n"
    + builtins.readFile (policySupport + "/view_confinement.te")
    + (if gitReadDelegation then "\n" + builtins.readFile (policySupport + "/git_read_delegation.te") else "")
  );
  viewEntrypointContext = entry: let
    basename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString entry.package));
    allowedPrograms =
      if entry.role == "source"
      then ["aos-sandbox-source-signer-view"]
      else if entry.role == "cache"
      then ["aos-sandbox-cache-journal-view" "aos-sandbox-cache-signer-views" "aos-sandbox-cache-signer-views-stop"]
      else [];
  in
    if builtins.elem entry.program allowedPrograms && builtins.match "[a-z0-9]{32}-${entry.program}" basename != null
    then "/(nix|nix\\.lower)/store/${basename}/bin/${entry.program} -- system_u:object_r:aos_sandbox_${entry.role}_view_preparer_exec_t\n"
    else throw "view preparation requires an exact evaluated fixed Source/Cache script entrypoint";
  inspectorPathRegex = "/(nix|nix\\.lower)/store/${netdBasenameRegex}/bin/aos-sandbox-network-namespace-inspector";
  inspectorPath = basename: "/nix/store/${basename}/bin/aos-sandbox-network-namespace-inspector";
  siblingBasename =
    (
      if builtins.substring 0 1 netdBasename == "0"
      then "1"
      else "0"
    )
    + builtins.substring 1 (builtins.stringLength netdBasename - 1) netdBasename;
  siblingVersion =
    if aos-netd.version == "0.0.0"
    then "0.0.1"
    else "0.0.0";
  siblingVersionBasename = builtins.replaceStrings [aos-netd.version] [siblingVersion] netdBasename;
  # Under this basename alphabet, only '.' needs regex escaping. Reject a
  # different derivation or version before emitting the installed context map.
  exactNetdLabel =
    builtins.match "[a-z0-9]{32}-aos-netd-[0-9]+\\.[0-9]+\\.[0-9]+" netdBasename
    != null
    && builtins.match inspectorPathRegex (inspectorPath netdBasename) != null
    && builtins.match inspectorPathRegex (inspectorPath siblingBasename) == null
    && siblingVersionBasename != netdBasename
    && builtins.match inspectorPathRegex (inspectorPath siblingVersionBasename) == null;
  workerBasename = builtins.unsafeDiscardStringContext (builtins.baseNameOf (toString aos-filesystem-fuse-worker));
  workerBasenameRegex = builtins.replaceStrings ["."] ["\\."] workerBasename;
  workerPathRegex = "/(nix|nix\\.lower)/store/${workerBasenameRegex}/bin/aos-filesystem-fuse-worker";
  workerPath = basename: "/nix/store/${basename}/bin/aos-filesystem-fuse-worker";
  workerSibling =
    (
      if builtins.substring 0 1 workerBasename == "0"
      then "1"
      else "0"
    )
    + builtins.substring 1 (builtins.stringLength workerBasename - 1) workerBasename;
  exactWorkerLabel =
    builtins.match "[a-z0-9]{32}-aos-filesystem-fuse-worker-[0-9]+\\.[0-9]+\\.[0-9]+" workerBasename
    != null
    && builtins.match workerPathRegex (workerPath workerBasename) != null
    && builtins.match workerPathRegex (workerPath workerSibling) == null
    && builtins.match workerPathRegex (workerPath (workerBasename + "-alias")) == null;
  fileContexts =
    if exactNetdLabel && exactWorkerLabel && exactPublisherLabel && exactSystemdPinLabel
    then
      builtins.toFile "aos_sandbox.fc" (
        builtins.replaceStrings
        (["@AOS_NETD_BASENAME_REGEX@" "@AOS_FUSE_WORKER_BASENAME_REGEX@" "@AOS_ZFS_WORKER_BASENAME_REGEX@" "@AOS_CONTROLLER_BASENAME_REGEX@" "@AOS_STORAGE_BASENAME_REGEX@" "@AOS_TPM_HELPER_BASENAME_REGEX@" "@AOS_VIEW_TOOLS_BASENAME_REGEX@" "@AOS_SYSTEMD_BASENAME_REGEX@"]
          ++ (if sourceProviderMount then ["@AOS_MOUNT_BASENAME_REGEX@" "@AOS_SOURCE_PROVIDER_BASENAME_REGEX@"] else []))
        ([netdBasenameRegex workerBasenameRegex publisherBasenameRegex (exactPackageBasename "aos-sandboxd" aos-sandboxd) (exactPackageBasename "aos-storaged" aos-storaged) (exactPackageBasename "aos-method46-tpm-helper" aos-method46-tpm-helper) (exactPackageBasename "aos-sandbox-view-preparer-tools" aos-sandbox-view-preparer-tools) systemdBasenameRegex]
          ++ (if sourceProviderMount then [(exactPackageBasename "aos-sandbox-mountd" aos-sandbox-mountd) (exactPackageBasename "aos-source-providerd" aos-source-providerd)] else []))
        (closedSelectedSource (policySupport + "/aos_sandbox.fc"))
        + builtins.concatStringsSep "" (map viewEntrypointContext viewPreparers)
        + (if gitReadDelegation then builtins.readFile (policySupport + "/git_read_delegation.fc") else "")
        + onlineFileContexts
      )
    else throw "fixed service SELinux labels must match only their evaluated package roots";
in
  mkDerivation {
    pname = "aos-selinux-production-policy";
    version = "1";

    buildDeps = [
      checkpolicy
      semodule-utils
      libselinux
      secilc
      setools
      python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          module_dir=${refpolicy-production}/usr/share/selinux/refpolicy
          base_package="$module_dir/base.pp"
          aos_module=aos_sandbox
          attribute_negative_module=aos_sandbox_attribute_negative
          export PYTHONPATH=${setools}/lib/python3/site-packages

          ${if sourceProviderMount || onlineNix || runtimeDeploymentPublisher || resourceBankEnrollment || hostComponentControl then ''
            mkdir selected-policy-checker
            cp -R ${policySupport}/. selected-policy-checker/
            chmod u+w selected-policy-checker
            chmod u+w selected-policy-checker/owner_policy.py
            install -m 0444 ${selectedOwnerData} selected-policy-checker/owner_policy.py
            ${if hostComponentControl then ''
              chmod u+w selected-policy-checker/effective_policy.py
              install -m 0444 ${selectedEffectiveData} selected-policy-checker/effective_policy.py
            '' else ""}
          '' else ""}

          AOS_SELINUX_PRODUCTION_RECIPE=${./aos-selinux-production-policy.nix} \
            ${python3}/bin/python3 ${policySupport}/effective_policy_test.py
          # Compare the real indexed and stock matchers on bounded native data,
          # not mock policy rules or another full production-policy scan.
          ${checkpolicy}/bin/checkpolicy -c ${policyVersion} -U reject \
            -o query-fixture.policy.${policyVersion} \
            ${policySupport}/rule_query_fixture.conf
          ${python3}/bin/python3 ${policySupport}/rule_query_test.py \
            query-fixture.policy.${policyVersion} \
            > query-index-differential-report 2>&1
          cat query-index-differential-report
          ${checkpolicy}/bin/checkmodule -m \
            -o "$aos_module.mod" ${ownerModule}
          ${semodule-utils}/bin/semodule_package \
            -o "$aos_module.pp" \
            -m "$aos_module.mod" \
            -f ${fileContexts}
          test -s "$aos_module.pp"
          ${checkpolicy}/bin/checkmodule -m \
            -o "$attribute_negative_module.mod" \
            ${policySupport}/aos_sandbox_attribute_negative.te
          ${semodule-utils}/bin/semodule_package \
            -o "$attribute_negative_module.pp" \
            -m "$attribute_negative_module.mod"
          test -s "$attribute_negative_module.pp"
          for narrow_negative_module in aos_sandbox_loader_negative aos_sandbox_context_negative aos_sandbox_guest_file_negative aos_sandbox_guest_ancestor_negative aos_sandbox_root_custody_negative aos_sandbox_helper_socket_negative aos_sandbox_signer_socket_negative; do
            ${checkpolicy}/bin/checkmodule -m \
              -o "$narrow_negative_module.mod" \
              ${policySupport}/"$narrow_negative_module.te"
            ${semodule-utils}/bin/semodule_package \
              -o "$narrow_negative_module.pp" \
              -m "$narrow_negative_module.mod"
            test -s "$narrow_negative_module.pp"
          done

          test -f "$base_package"
          set -- "$base_package"
          for module_package in "$module_dir"/*.pp; do
            if [ "$module_package" != "$base_package" ]; then
              set -- "$@" "$module_package"
            fi
          done
          set -- "$@" "$aos_module.pp"

          # The production variant's base package carries reject-unknown and
          # its Linux 6.18 class map. The focused AOS sandbox module is linked
          # here; legacy mutable-store compatibility modules are not inputs.
          ${semodule-utils}/bin/semodule_link -o linked-policy.mod "$@"
          ${semodule-utils}/bin/semodule_expand \
            -c ${policyVersion} \
            linked-policy.mod final-policy.${policyVersion}

          ${checkpolicy}/bin/checkpolicy -b -C \
            -o final-policy.cil final-policy.${policyVersion}
          grep -Fx '(policycap nnp_nosuid_transition)' final-policy.cil
          ${python3}/bin/python3 ${checkerScript} \
            ${gitReadCheckerArgument} final-policy.${policyVersion} > effective-policy.tsv
          test -s effective-policy.tsv

          # Separate mutants restore textrel, translation, Guest host-file
          # access/relabeling, foreign Root custody or fixed-role connections.
          # Normal base assertions remain enabled; each fails the same checker.
          for narrow_negative_module in aos_sandbox_loader_negative aos_sandbox_context_negative aos_sandbox_guest_file_negative aos_sandbox_guest_ancestor_negative aos_sandbox_root_custody_negative aos_sandbox_helper_socket_negative aos_sandbox_signer_socket_negative; do
            ${semodule-utils}/bin/semodule_link \
              -o "$narrow_negative_module-linked.mod" \
              "$@" "$narrow_negative_module.pp"
            ${semodule-utils}/bin/semodule_expand \
              -c ${policyVersion} \
              "$narrow_negative_module-linked.mod" \
              "$narrow_negative_module-policy.${policyVersion}"
            if ${python3}/bin/python3 ${checkerScript} \
              ${gitReadCheckerArgument} "$narrow_negative_module-policy.${policyVersion}" \
              > "$narrow_negative_module-effective.tsv" \
              2> "$narrow_negative_module-diagnostic"
            then
              echo "attribute-expanded grant unexpectedly passed: $narrow_negative_module" >&2
              exit 1
            fi
            if test "$narrow_negative_module" = aos_sandbox_root_custody_negative; then
              grep -F "foreign normal Root custody grant exists" "$narrow_negative_module-diagnostic"
            else
              grep -F "forbidden allow exists" "$narrow_negative_module-diagnostic"
            fi
            case "$narrow_negative_module" in
              aos_sandbox_loader_negative)
                grep -F "aos_filesystem_fuse_worker_t" "$narrow_negative_module-diagnostic"
                grep -F "execmod" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_context_negative)
                grep -F "aos_filesystem_fuse_worker_t" "$narrow_negative_module-diagnostic"
                grep -F "sock_file" "$narrow_negative_module-diagnostic"
                grep -F "permission='open'" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_guest_file_negative)
                grep -F "outside Guest file_type cohort" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_guest_owner_t" "$narrow_negative_module-diagnostic"
                grep -F "var_t" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_guest_ancestor_negative)
                grep -F "aos_sandbox_guest_owner_t" "$narrow_negative_module-diagnostic"
                # Both expanded targets are forbidden; query order is not evidence.
                grep -E "target='(var_t|var_lib_t)'" "$narrow_negative_module-diagnostic"
                grep -F "object_class='dir'" "$narrow_negative_module-diagnostic"
                grep -F "permission='relabelfrom'" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_root_custody_negative)
                grep -F "aos_sandbox_negative_root_sources" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_negative_root_targets:fd use" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_helper_socket_negative)
                grep -F "aos_method46_controller_helper_t" "$narrow_negative_module-diagnostic"
                grep -F "object_class='unix_stream_socket'" "$narrow_negative_module-diagnostic"
                grep -F "permission='connect'" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_negative_helper_socket_sources" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_negative_helper_socket_targets" "$narrow_negative_module-diagnostic"
                ;;
              aos_sandbox_signer_socket_negative)
                grep -F "aos_sandbox_cache_signer_t" "$narrow_negative_module-diagnostic"
                grep -F "object_class='unix_stream_socket'" "$narrow_negative_module-diagnostic"
                grep -F "permission='connect'" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_negative_signer_socket_sources" "$narrow_negative_module-diagnostic"
                grep -F "aos_sandbox_negative_signer_socket_targets" "$narrow_negative_module-diagnostic"
                ;;
              *)
                echo "unknown negative module: $narrow_negative_module" >&2
                exit 1
                ;;
            esac
          done

          # Link a deliberately forbidden attribute-based process:ptrace rule
          # into a second loadable binary. This proves the production checker
          # uses SETools' indirect source expansion and unbounded target scan.
          ${semodule-utils}/bin/semodule_link \
            -o attribute-negative-linked-policy.mod \
            "$@" "$attribute_negative_module.pp"
          # Production expansion above keeps neverallow checking enabled. Only
          # this deliberately forbidden, never-installed fixture bypasses the
          # base policy assertions so the SETools gate can reject it itself.
          ${semodule-utils}/bin/semodule_expand \
            -a \
            -c ${policyVersion} \
            attribute-negative-linked-policy.mod \
            attribute-negative-policy.${policyVersion}
          if ${python3}/bin/python3 ${checkerScript} \
            ${gitReadCheckerArgument} attribute-negative-policy.${policyVersion} \
            > attribute-negative-effective-policy.tsv \
            2> attribute-negative-diagnostic
          then
            echo "attribute-expanded forbidden rule unexpectedly passed" >&2
            exit 1
          fi
          grep -F "forbidden allow exists" attribute-negative-diagnostic
          grep -F "process" attribute-negative-diagnostic
          grep -F "ptrace" attribute-negative-diagnostic

          mkdir kernel-source
          tar xf ${linux.src} -C kernel-source --strip-components=1
          $CC \
            -std=c17 \
            -Wall \
            -Wextra \
            -Werror \
            -I kernel-source/security/selinux/include \
            ${policySupport}/kernel-classmap.c \
            -o emit-kernel-classmap
          ./emit-kernel-classmap > kernel-classmap.tsv

          ${python3}/bin/python3 ${policySupport}/coverage_test.py
          ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv final-policy.cil observed-policy-classmap.tsv

          # The source-level negative catches comparator regressions directly.
          ${python3}/bin/python3 ${policySupport}/coverage.py remove \
            final-policy.cil deficient-policy.cil io_uring allowed
          if ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv deficient-policy.cil deficient-source-classmap.tsv \
            2> deficient-source-diagnostic
          then
            echo "deficient source unexpectedly passed policy coverage" >&2
            exit 1
          fi
          grep -F "ordered permissions differ for io_uring" \
            deficient-source-diagnostic

          # The artifact negative must first compile, then fail the same gate
          # only after checkpolicy decodes the resulting loadable binary.
          ${secilc}/bin/secilc \
            -c ${policyVersion} \
            -f /dev/null \
            -o deficient-policy.${policyVersion} \
            deficient-policy.cil
          test -s deficient-policy.${policyVersion}
          ${checkpolicy}/bin/checkpolicy -b -C \
            -o deficient-policy-decoded.cil deficient-policy.${policyVersion}
          if ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv \
            deficient-policy-decoded.cil \
            deficient-binary-classmap.tsv \
            2> deficient-binary-diagnostic
          then
            echo "deficient binary unexpectedly passed policy coverage" >&2
            exit 1
          fi
          grep -F "ordered permissions differ for io_uring" \
            deficient-binary-diagnostic

          mkdir unpacked-modules
          : > file_contexts
          module_index=0
          for module_package in "$module_dir"/*.pp; do
            module_index=$((module_index + 1))
            module_prefix="unpacked-modules/module-$module_index"
            ${semodule-utils}/bin/semodule_unpackage \
              "$module_package" "$module_prefix.mod" "$module_prefix.fc"

            if [ -s "$module_prefix.fc" ]; then
              cat "$module_prefix.fc" >> file_contexts
              printf '\n' >> file_contexts
            fi
          done

          cat ${fileContexts} >> file_contexts
          printf '\n' >> file_contexts

          test -s file_contexts
          ${libselinux}/sbin/sefcontext_compile \
            -p final-policy.${policyVersion} \
            -o file_contexts.bin \
            file_contexts
          test -s file_contexts.bin
        '';
      }
      {
        name = "install";
        script = ''
          policy_root=$out/etc/selinux/aos
          evidence_root=$out/share/aos-selinux-production-policy

          mkdir -p "$policy_root" "$evidence_root"
          cp -R ${refpolicy-production}/etc/selinux/refpolicy/. "$policy_root/"
          chmod -R u+w "$policy_root"
          mkdir -p "$policy_root/policy" "$policy_root/contexts/files"
          install -m 0644 final-policy.${policyVersion} \
            "$policy_root/policy/policy.${policyVersion}"
          install -m 0644 file_contexts file_contexts.bin \
            "$policy_root/contexts/files/"
          # Backing-home aliases use this policy's own contexts, never the
          # legacy refpolicy context image or a different loaded policy.
          test -f "$policy_root/contexts/files/file_contexts.subs_dist"
          cat ${homeAliases} >> "$policy_root/contexts/files/file_contexts.subs_dist"
          install -m 0644 \
            kernel-classmap.tsv \
            observed-policy-classmap.tsv \
            final-policy.cil \
            effective-policy.tsv \
            query-index-differential-report \
            "$aos_module.mod" \
            "$aos_module.pp" \
            ${policySupport}/aos_sandbox.te \
            ${policySupport}/aos_sandbox_attribute_negative.te \
            ${policySupport}/aos_sandbox_loader_negative.te \
            ${policySupport}/aos_sandbox_context_negative.te \
            ${policySupport}/aos_sandbox_guest_ancestor_negative.te \
            ${policySupport}/aos_sandbox_root_custody_negative.te \
            ${policySupport}/aos_sandbox_helper_socket_negative.te \
            ${policySupport}/aos_sandbox_signer_socket_negative.te \
            ${policySupport}/view_confinement.te \
            ${policySupport}/view_policy.py \
            attribute-negative-diagnostic \
            aos_sandbox_loader_negative-diagnostic \
            aos_sandbox_context_negative-diagnostic \
            aos_sandbox_guest_ancestor_negative-diagnostic \
            aos_sandbox_root_custody_negative-diagnostic \
            aos_sandbox_helper_socket_negative-diagnostic \
            aos_sandbox_signer_socket_negative-diagnostic \
            deficient-source-diagnostic \
            deficient-binary-diagnostic \
            "$evidence_root/"
          install -m 0644 ${fileContexts} "$evidence_root/aos_sandbox.fc"
          ${if onlineNix || runtimeDeploymentPublisher || resourceBankEnrollment || hostComponentControl then ''
            # Adjacent modules and rendered expectation DATA are the same
            # inputs used above; the relative passthru has no output cycle.
            mkdir -p "$out/share/aos/selected-policy-checker"
            install -m 0444 selected-policy-checker/*.py \
              "$out/share/aos/selected-policy-checker/"
          '' else ""}

          cat > "$evidence_root/gate-result" <<'EOF'
          kernel_classmap_ordered_prefix=pass
          final_binary_handleunknown_reject=pass
          deficient_source_pair=io_uring.allowed
          deficient_source_coverage=rejected
          deficient_binary_compilation=pass
          deficient_binary_decoded_coverage=rejected
          aos_sandbox_module_linked=pass
          aos_sandbox_effective_policy=pass
          aos_sandbox_attribute_expansion_negative=rejected
          EOF
        '';
      }
    ];

    passthru = {
      evidenceSources = [
        policySupport
        refpolicy-production.src
        linux.src
      ];
    } // (if onlineNix || runtimeDeploymentPublisher || resourceBankEnrollment || hostComponentControl then {
      effectivePolicyCheckerRelative = "share/aos/selected-policy-checker/effective_policy.py";
    } else {});

    meta = {
      description = "Offline SELinux policy matched to the production Linux class map";
      license = "GPL-2.0-or-later";
    };
  }
