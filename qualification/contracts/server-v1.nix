##! One server contract; release class changes obligations, not requirement IDs.
{
  id = "aos-server-v1";
  promises = [
    "Install authenticated public artifacts and provision a persistent headless server."
    "Configure users, SSH, DNS, time, DHCP, and single-address static networking."
    "Install, change versions, remove, and recover machine-wide package generations."
    "Activate and roll back host configuration with transaction-bound evidence."
    "Update the preceding accepted image, recover or roll back, and update again."
    "Preserve committed workload data within the declared storage and migration contract."
    "Keep update storage bounded and fail safely when resources are exhausted."
    "Run nginx HTTP/TLS and a persistent container workload on the reference targets."
  ];
  exclusions = [
    "No implicit qualification of other hardware, hypervisors, clouds, or container runtimes."
    "No SELinux enforcement claim until labeled-root and enforcing-policy gates pass."
    "No automatic reversal of application data migrations through image rollback."
    "No stock unprivileged per-user package mutation contract."
    "No uptime SLA or failure-rate inference from a finite qualification campaign."
  ];
  thresholds = {
    edge = {
      soak_seconds = 86400;
      exercise_max_age_seconds = 2592000;
      require_independent_review = false;
      require_complete_matrix = false;
    };
    candidate = {
      soak_seconds = 604800;
      exercise_max_age_seconds = 2592000;
      require_independent_review = true;
      require_complete_matrix = false;
    };
    stable = {
      soak_seconds = 1209600;
      exercise_max_age_seconds = 2592000;
      require_independent_review = true;
      require_complete_matrix = true;
    };
    emergency = {
      # Urgency never silently removes production obligations. A separately
      # reviewed future policy can define a bounded expedited observation rule.
      soak_seconds = 1209600;
      exercise_max_age_seconds = 2592000;
      require_independent_review = true;
      require_complete_matrix = true;
    };
  };
}
