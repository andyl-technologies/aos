##! JaCoCo 0.8.11 source for Bazel's code coverage dependencies.
{
  fetchgit,
  buildPackages,
}:
fetchgit {
  url = "https://github.com/jacoco/jacoco.git";
  ref = "v0.8.11";
  rev = "f33756c37f1e41041d84018047b14cb394742761";
  name = "jacoco-0.8.11-source-only";
  hash = "sha256-3+nfmr1km4A+wJVBV69ID9nGDdYL4y8YZm/Lad9EdOs=";

  git = buildPackages.git-minimal;
  caCertificates = buildPackages.ca-certificates;
  coreutils = buildPackages.coreutils;

  sparsePatterns = [
    "/org.jacoco.core/src/"
    "/org.jacoco.report/src/"
    "/org.jacoco.agent.rt/src/"
    "/org.jacoco.agent/src/"
    "/LICENSE*"
    "/NOTICE*"
  ];
}
