##! Keeps reviewed upstream policies through real package aliases and module dependencies.
{pkgs}: let
  dependencies = import ../../lib/packages/module-dependencies.nix;
  requirementsFor = consumer: name:
    builtins.filter (requirement: requirement != null && requirement.package == name)
    (map (dependencies.requirement (package: package.catalogName or package.pname or package.name)) consumer.moduleDeps);

  bind = pkgs.bind;
  dnsutils = pkgs.dnsutils;
  findutils = pkgs.findutils;
  lua = pkgs.lua;
  pyrefly = pkgs.pyrefly;
in {
  stableSeriesPolicies = assert bind.versionRequirement == "~${bind.version}";
  assert lua.versionRequirement == "~${lua.version}";
  assert pyrefly.versionRequirement == "=${pyrefly.version}"; true;

  selectedOutputRetainsPolicy = assert bind.dnsutils.version == bind.version;
  assert bind.dnsutils.versionRequirement == bind.versionRequirement;
  assert dnsutils.version == bind.version;
  assert dnsutils.versionRequirement == bind.versionRequirement;
  assert dnsutils.outputName == "dnsutils";
  assert dnsutils.drvPath == bind.drvPath; true;

  qualificationUsesExactRelease = assert dnsutils.qualificationDocument.package.version == bind.version;
  assert pyrefly.qualificationDocument.package.version == pyrefly.version;
  assert builtins.all (package:
    package.deployment.package.version
    == package.version
    && package.deployment.versionRequirement == package.versionRequirement)
  [pkgs.glibc pkgs.binutils]; true;

  bootstrapPublicationRetainsRecipePolicy =
    if pkgs.stdenv.isCross
    then true
    else
      assert findutils.versionRequirement == "=${findutils.version}";
      assert findutils.drvPath == pkgs.stdenv.findutils.drvPath;
      assert findutils.qualificationDocument.package.version == findutils.version;
      assert findutils.deployment.package.version == findutils.version;
      assert findutils.deployment.versionRequirement == findutils.versionRequirement; true;

  sourceCoordinatesUseExactRelease = assert bind.src.urls
  == ["https://downloads.isc.org/isc/bind9/${bind.version}/bind-${bind.version}.tar.xz"];
  assert lua.src.urls == ["https://www.lua.org/ftp/lua-${lua.version}.tar.gz"];
  assert pyrefly.src.urls == ["https://github.com/facebook/pyrefly/archive/refs/tags/${pyrefly.version}.tar.gz"];
  assert builtins.all (package: builtins.match "[~^=].*" package.version == null) [bind lua pyrefly findutils]; true;

  moduleDependenciesUseReviewedPolicies = assert requirementsFor pkgs.openssh "linux-pam"
  == [
    {
      package = "linux-pam";
      packageVersion = "=${pkgs.linux-pam.version}";
    }
  ];
  assert requirementsFor pkgs.openssh "nftables"
  == [
    {
      package = "nftables";
      packageVersion = "=${pkgs.nftables.version}";
    }
  ];
  assert requirementsFor pkgs.polkit "dbus"
  == [
    {
      package = "dbus";
      packageVersion = "^${pkgs.dbus.version}";
    }
  ]; true;
}
