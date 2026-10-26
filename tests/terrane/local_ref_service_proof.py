"""Binds native repository-backed Ref service cases to the actual retained ELF."""

import hashlib
import json
import os
from pathlib import Path
import shutil

from sdk_contract_proof import require, run_sdk_contract


CASES = [
    "stream_checks::changed_publications_refuse_prepared_reflog_rows_and_listing_completion",
    "stream_checks::identity_expiry_refuses_prepared_empty_listing_completion",
    "guarded_point_reads_preserve_whole_records_and_observe_actual_publication",
    "genuine_signatures_and_broad_grants_do_not_override_repository_acl",
    "finite_listing_and_reflog_match_the_actual_committed_whole_records",
    "malformed_requests_refuse_and_home_reads_satisfy_all_freshness_modes",
    "response_budgets_refuse_whole_results_at_exact_boundaries",
    "missing_authentication_and_unavailable_mutations_preserve_the_head",
    "identity_expiring_after_middleware_dispatch_cannot_reach_repository_data",
]


if __name__ == "__main__":
    run_sdk_contract(
        "local_ref_service", CASES,
        "Actual local repository reads through authenticated native sockets, "
        "current signed ACLs and canonical ref records; "
        "no CAS, resumable watch, remote/cache freshness or deployment claim",
    )
    output = Path(os.environ["out"])
    review_path = output / "source-review.json"
    review = json.loads(review_path.read_text())
    executable = Path(review["artifact"]["executable"])
    retained = output / "local-ref-service-test"
    shutil.copyfile(executable, retained)
    retained.chmod(0o755)
    require(hashlib.sha256(retained.read_bytes()).hexdigest() == review["executable_sha256"],
            "retained local Ref service integration artifact changed")
    review["retained_executable"] = str(retained)
    review_path.write_text(json.dumps(review, indent=2) + "\n")
