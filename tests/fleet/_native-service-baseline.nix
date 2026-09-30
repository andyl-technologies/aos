##! Keeps authored deadline services inactive in the boot baseline.
{...}: {
  aos.nativeServiceQualification.enabled = {
    deadline = false;
    deadlineRemove = false;
  };
}
