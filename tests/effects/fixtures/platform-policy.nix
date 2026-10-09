##! Authored operator policy used by the native image replay fixture.
{
  aos.kernel.modules = ["overlay"];
  aos.networking.hostName = "fixture";
  aos.networking.tuning."net.core.wmem_max" = "9000000";
}
