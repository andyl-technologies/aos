# Retain the fixture Controller identity for native host-stage activation.
{...}: {
  aos.users.groups.aos-sandboxd = {
    gid = 811;
    members = [];
  };
  aos.users.users.aos-sandboxd = {
    uid = 811;
    group = "aos-sandboxd";
    home = "/var/lib/aos/sandboxd";
    shell = "/sbin/nologin";
    description = "AOS sandbox node controller";
    extraGroups = [];
  };
}
