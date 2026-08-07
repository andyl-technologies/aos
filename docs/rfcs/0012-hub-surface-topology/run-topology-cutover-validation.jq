include "validate-topology-cutover";

{plan: $plan[0], report: $report[0], verification: $verification[0]}
| .verification.verifier_identity.current_exe_sha256 =
    .verification.verifier_identity.bundle_entry_sha256
| validate(.plan; .report; .verification)
