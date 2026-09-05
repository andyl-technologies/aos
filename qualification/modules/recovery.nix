##! Owns recovery qualification requirements and their regression coverage.
{...}: {
  config.qualification.requirements = {
    operator-recovery = {
      checks = ["key-custody" "independent-encrypted-backup" "restore-to-clean-environment" "registry-key-rotation" "alert-delivery" "abandoned-and-fix-forward-release"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "operator";
      phase = "staging";
      production_only = false;
      regressions = [];
      scope = "release";
    };
    production-recovery = {
      checks = ["portable-hub-database-export-import" "isolated-hub-restore" "independent-authority-control" "compatibility-and-support-window"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "operator";
      phase = "staging";
      production_only = true;
      regressions = [];
      scope = "release";
    };
  };
}
