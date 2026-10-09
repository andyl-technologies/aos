##! Keeps the future image operation inactive while its baseline image boots.
{lib, ...}: {
  aos.tests.imageScenario.enable = lib.mkDefault false;
}
