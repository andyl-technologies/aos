"""Project actual conformance and current List export into initial Copy inputs.

The source-built tool validates the complete original provider journal. These
records establish neither physical authority nor current credential admission;
the separate current SQL export and independent selection remain required.
"""

import copy
import hashlib
import json
import re
import shlex


def observe_external_copy_contract(worker, tools, *, observation_root, report_sha256, label):
    """Read the ordinary run's exact report and execute its read-only projection."""
    if (observation_root != "/var/lib/hybrid-worker/provider-observation" and re.fullmatch(
            r"/var/lib/hybrid-worker/external-oci/[0-9a-f]{32}/(?:destination-)?provider-observation", observation_root) is None
            or re.fullmatch(r"[0-9a-f]{64}", report_sha256) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None):
        raise ValueError("Copy report selection differs")
    report = read_direct_guest_file(worker, tools["python"], observation_root + "/observations.json", 1024 * 1024)
    if hashlib.sha256(report).hexdigest() != report_sha256:
        raise ValueError("Copy projection selects another actual provider original")
    observed = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root'])
        executable=Path(selected['executable'])
        with executable.open('rb') as source:
            executable_sha=hashlib.file_digest(source,'sha256').hexdigest()
        arguments=[str(executable),'copy-contract','--report-file',str(root/'observations.json'),
            '--journal-directory',str(root/'journal'),'--output',str(root/'copy-contract.json')]
        with (root/'copy-contract.stdout').open('xb') as stdout, (root/'copy-contract.stderr').open('xb') as stderr:
            result=subprocess.run(arguments,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=60,check=False)
            stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
        if result.returncode:
            raise ValueError('Current source Copy contract projection refused; preserve original journal')
        path=root/'copy-contract.json'; body=path.read_bytes()
        if not 0<len(body)<=65536:raise ValueError('Copy contract exceeded its bound')
        value=json.loads(body)
        if value['executable_sha256']!=executable_sha or value['report_sha256']!=selected['reportSha256']:
            raise ValueError('Copy projection executable or original report changed')
        print(json.dumps({'value':value,'receipt':{'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),
            'byteSize':str(len(body)),'executableSha256':executable_sha}}))
    """, {"root": observation_root, "reportSha256": report_sha256,
        "executable": tools["providerConformance"]}, timeout=75))
    raw_report = json.loads(report)["original"]
    value = observed["value"]
    for name in ("endpoint", "bucket", "private_staging_prefix", "policy_review_sha256"):
        if value[name] != raw_report[name]:
            raise ValueError("Copy projection changed a retained provider coordinate or private policy")
    if value["private_policy"] != raw_report["policy"]:
        raise ValueError("Copy projection changed the real original private policy")
    if value["provider_contract"]["evidence_digest"] != report_sha256:
        raise ValueError("Copy requirement evidence differs from the actual report")
    retain_direct_flow(label + "-copy-contract.json", observed)
    return observed


def export_current_external_list(worker, tools, bootstrap, *, sql_url_file,
                                 issuer_configuration_file, output, label):
    """Export only the genuine current List member of the unchanged publication."""
    if (not output.startswith("/var/lib/hybrid-worker/")
            or any(part in {"", ".", ".."} for part in output.split("/")[1:])
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None):
        raise ValueError("List export custody path differs")
    write = bootstrap["write_cohort"]
    arguments = [tools["authorityBootstrap"], "--database-url-file", sql_url_file,
        "export-list-cohort", "--authority-id", write["authority"]["authority_id"],
        "--issuer-configuration", issuer_configuration_file,
        "--association-id", write["association"]["association_id"],
        "--admitted-prefix", write["admitted_prefix"], "--output", output]
    private_guest_command(worker, shlex.join(arguments), timeout=120)
    body = read_direct_guest_file(worker, tools["python"], output + "/list-cohort.json", 1024 * 1024)
    listing = json.loads(body)
    if (set(listing) != {"version", "publication", "issuer_installation", "list_cohort"}
            or listing["version"] != 1 or listing["publication"] != bootstrap["publication"]
            or listing["issuer_installation"] != bootstrap["issuer_installation"]):
        raise ValueError("Actual List export changed the current selected authority head")
    reference = {"file": output + "/list-cohort.json", "sha256": hashlib.sha256(body).hexdigest(),
        "byteSize": str(len(body))}
    retain_direct_flow(label + "-list-export.json", {"value": listing, "receipt": reference})
    return {"value": listing, "receipt": reference}


def project_current_external_copy(consumers, bootstrap, listing, copy_observation, producer_digest, *,
                                  provider_concurrency=3):
    """Bind separately observed requirements and the exact current purpose cohorts."""
    if (re.fullmatch(r"[0-9a-f]{64}", producer_digest) is None
            or listing["publication"] != bootstrap["publication"]
            or listing["issuer_installation"] != bootstrap["issuer_installation"]):
        raise ValueError("Copy projection changed its producer or authority identity")
    if type(provider_concurrency) is not int or not 3 <= provider_concurrency <= 32:
        raise ValueError("Copy domain provider capacity differs from its actual isolate runtime")
    listing = listing["list_cohort"]
    if listing["credential"]["purpose"] != "list" or listing["allowed_effects"] != ["list"]:
        raise ValueError("Copy List cohort does not represent the separately exported purpose")
    result = copy.deepcopy(consumers)
    object_consumer = result["HUB_EXTERNAL_OBJECT_CONSUMER"]
    if (object_consumer["publications"] != [bootstrap["publication"]]
            or set(json.dumps(row, sort_keys=True) for row in object_consumer["cohorts"]) !=
            set(json.dumps(bootstrap[name], sort_keys=True) for name in ("read_cohort", "write_cohort"))):
        raise ValueError("Copy projection cannot replace independently installed object authority")
    object_consumer["cohorts"].append(copy.deepcopy(listing))
    result["HUB_EXTERNAL_COPY_CONSUMER"] = {"version": 1, "domains": [{
        "issuer_installation": bootstrap["issuer_installation"], "producer_profile_digest": producer_digest,
        "provider_contract": copy_observation["value"]["provider_contract"],
        "read_cohort": bootstrap["read_cohort"], "list_cohort": listing, "write_cohort": bootstrap["write_cohort"],
        "part_bytes": "8388608", "provider_concurrency": provider_concurrency,
        "maximum_list_page_objects": 128, "maximum_list_pages": 128}]}
    if len(json.dumps(object_consumer, separators=(",", ":")).encode()) > 128 * 1024:
        raise ValueError("Full current object authority exceeds its existing bound")
    return result
