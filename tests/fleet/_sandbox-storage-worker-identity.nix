# Retain the fixture worker identity for native host-stage activation.
{...}: {
  aos.users.groups.aos-sandbox-zfs-worker = {
    gid = 992;
    members = [];
  };
  aos.users.users.aos-sandbox-zfs-worker = {
    uid = 992;
    group = "aos-sandbox-zfs-worker";
    home = "/";
    shell = "/sbin/nologin";
    description = "AOS serialized OpenZFS transaction worker";
    extraGroups = [];
  };
}
