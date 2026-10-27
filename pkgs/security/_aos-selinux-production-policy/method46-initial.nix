##! Closed manual initializer policy inputs; importing this file enables no role.
{
  purposes ? [],
  initialPackage ? null,
  helperPackage ? null,
}: let
  knownPurposes = ["controller" "storage"];
  selected = builtins.filter (role: builtins.elem role purposes) knownPurposes;
  validSelection = builtins.isList purposes && purposes == selected;
  storeHash = "[0-9abcdfghijklmnpqrsvwxyz]{32}";
  storeRoots = "/(nix|nix\\.lower|usr/lib/aos/nix)/store";
  credentials = builtins.fromJSON (builtins.readFile ./method46_initial_credentials.json);
  join = builtins.concatStringsSep "\n";

  # Discard references only after validating an actual store root. Policy must
  # not depend on the executable or on its policy-dependent startup profile.
  packageRoot = suffix: package: let
    path = builtins.unsafeDiscardStringContext (toString package);
    basename = builtins.baseNameOf path;
    escaped = builtins.replaceStrings ["."] ["\\."] suffix;
  in
    if builtins.match "/nix/store/${storeHash}-${escaped}" path == null
    then throw "method46 initial policy requires the exact ${suffix} store output"
    else builtins.replaceStrings ["."] ["\\."] basename;
  initialRoot = packageRoot "aos-method46-floor-initializers-0.1.0" initialPackage;
  helperRoot = packageRoot "aos-method46-initial-tpm-helpers-1" helperPackage;

  roleInputs = role: let
    service = "aos-sandbox-${role}-floor-initialize";
    domain = "aos_method46_${role}_initial_t";
    helper = "aos_method46_initial_${role}_helper_t";
    credential = "aos_method46_${role}_initial_credential_t";
    credentialDirectory = "/run/credentials/${service}\\.service";
    credentialTransitions = join (map
      (name: ''type_transition init_t ${credential}:file ${credential} "${name}";'')
      credentials);
  in {
    inherit role service domain helper credential;
    moduleText =
      builtins.replaceStrings
      ["@ROLE@" "@CREDENTIAL_TRANSITIONS@"]
      [role credentialTransitions]
      (builtins.readFile ./method46_initial_role.te);
    fileContexts = join ([
        "${storeRoots}/${initialRoot}/bin/${service} -- system_u:object_r:aos_method46_${role}_initial_exec_t"
        "${storeRoots}/${helperRoot}/libexec/aos-method46-initial-${role}-tpm-helper -- system_u:object_r:aos_method46_initial_${role}_helper_exec_t"
        "${credentialDirectory} -d system_u:object_r:${credential}"
        "/run/aos/sandbox/method46-${role}-initial\\.sock -s system_u:object_r:aos_method46_${role}_initial_approval_t"
      ]
      ++ map (name: "${credentialDirectory}/${name} -- system_u:object_r:${credential}") credentials);
  };
  roles = map roleInputs selected;

  # The profile embeds the resulting policy, so pinning its store hash here
  # would introduce a cycle. Restrict the label to the versioned package and
  # its three delivered files; Source independently authenticates their bytes.
  profileContexts = join (map
    (name: "${storeRoots}/${storeHash}-aos-method46-initial-startup-profile-3/${name} -- system_u:object_r:aos_method46_initial_profile_t")
    ["profile\\.json" "source-policy\\.33" "effective-policy\\.tsv"]);
in
  if !validSelection
  then throw "method46 initial purposes must be a canonical subset of controller, storage"
  else {
    inherit credentials purposes roles;
    moduleText =
      if selected == []
      then ""
      else "type aos_method46_initial_profile_t;\n" + join (map (role: role.moduleText) roles) + "\n";
    fileContexts =
      if selected == []
      then ""
      else join (map (role: role.fileContexts) roles ++ [profileContexts]) + "\n";
  }
