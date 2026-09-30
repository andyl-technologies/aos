##! Authors native domain response barriers before qualification binding.
{...}: {
  aos.nativeHandlerInterception.native-handler-interception-aos-filesystem-provider.operations = map (name: {
    ability = "filesystem";
    inherit name;
  }) ["directory" "allocate" "persistentAllocate" "entry"];
  aos.nativeHandlerInterception.native-handler-interception-systemd.operations = [
    {
      ability = "configuration";
      name = "file";
    }
  ];
  aos.nativeHandlerInterception.native-handler-interception-aos-network-ruleset-provider.operations = [
    {
      ability = "networkPolicy";
      name = "ruleset";
    }
  ];
}
