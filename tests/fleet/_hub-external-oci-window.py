"""Run a separate, normally initialized External OCI and Copy business lane.

The stock Native performs normal authority and registry setup. A separately
identified test process then serves the confined OCI candidate using the same
database, fixed origins and current authority. Direct sidecar transfer keeps
its independent final runtime acceptance; Copy uses the observed provider
contract and current Read/List/Write cohorts. Raw failures remain private.
"""

import hashlib
import json
import secrets
import shlex
import time
from types import SimpleNamespace


def run_external_oci_pair_window(client, native, worker, s3, database_machine, tools,
                                 database_host, original_configuration, artifacts,
                                 reviewer_public_key, *, copy_isolation="same_worker", planned_run):
    """Call ordinary bootstrap, publication, graph readback and reviewed copying."""
    run = planned_run
    coordinates = external_oci_pair_coordinates(run)
    if copy_isolation not in {"same_worker", "source_worker"}:
        raise ValueError("External Copy isolation case differs")
    tools = {**tools, "copyIsolationCase": copy_isolation}
    addresses = json.loads(direct_guest_python(native, tools["python"], """
        import socket
        print(json.dumps({role:socket.gethostbyname(role) for role in ('native','worker')}))
    """, {}))
    prepared = provision_external_oci_pair(native, worker, client, database_machine, tools,
        original_configuration, run, database_host, addresses["native"], addresses["worker"], reviewer_public_key)
    pair_tools = {**tools, "deploymentId": "fleet-external-oci-" + run,
        "workerUrl": coordinates["publicOrigin"], "nativeOriginUrl": coordinates["controlOrigin"],
        "storageWorkKeyFile": coordinates["workerRoot"] + "/materials/HUB_STORAGE_WORK_KEY",
        "nativeStorageWorkKeyFile": prepared["nativeFiles"]["HUB_STORAGE_WORK_KEY"],
        "nativeDatabaseUrlFile": prepared["nativeFiles"]["database"]}
    boundaries = prepare_external_oci_boundaries(native, worker, pair_tools, prepared,
        addresses["native"], addresses["worker"])
    ownership = {"prepared": prepared, "processes": {}, "forwards": []}
    workflow, producer_error, result = None, None, None
    try:
        processes = start_external_oci_pair(native, worker, client, pair_tools, prepared, boundaries,
            ownership=ownership)
        ownership["processes"] = processes
        stock_codec = select_external_storage_codec(pair_tools, artifacts, processes["native"], run,
            "ordinary_native")
        workflow = ExternalOciWorkflowCapture(native, worker, s3, pair_tools, prepared, processes,
            {**boundaries, **stock_codec})
        result = run_external_oci_business_lane(client, native, worker, s3, database_machine,
            pair_tools, prepared, processes, boundaries, artifacts, reviewer_public_key,
            ownership, workflow, database_host)
        return result
    except Exception as error:
        producer_error = error
        raise
    finally:
        capture_error = None
        if workflow is not None:
            try:
                complete = workflow.complete(ownership["processes"])
                ownership["completeCapture"] = complete
                if result is not None:
                    result["completeCapture"] = complete
                accounting = managed_fixture_module(pair_tools["externalWorkflowAccounting"],
                    "external_authority_accounting_" + run)
                read_sql = lambda query, label: read_external_oci_sql(native, pair_tools,
                    ownership["prepared"], ownership["processes"]["native"], query, label)
                assessment = accounting.consume_external_workflow_evidence(native, worker, pair_tools,
                    ownership["prepared"], ownership["processes"], complete,
                    ownership.get("business"), read_sql,
                    read_private=lambda machine, path, maximum: read_direct_guest_file(
                        machine, pair_tools["python"], path, maximum))
                retain_direct_flow("external-oci-" + run + "-whole-workflow-assessment.json", assessment)
                if result is not None:
                    result["wholeWorkflowAssessment"] = assessment
                # This gate covers the selected canonical boundary bodies.
                # Whole-machine consumption and authority joins stay separate.
                if (assessment.get("complete") is not True
                        or type(assessment.get("capturedObjectByteUpperBound")) is not int
                        or assessment.get("capturedObjectByteUpperBound") != 0):
                    capture_error = RuntimeError("External selected-boundary body budget is unresolved or exceeded")
            except Exception as error:
                capture_error = error
                retain_direct_flow("external-oci-" + run + "-capture-failure.json", {
                    "version": 1, "failureClass": type(error).__name__, "nativeBulkBytes": None})
        exits = teardown_external_oci_pair(client, native, worker, pair_tools, ownership,
            producer_error or capture_error)
        if result is not None:
            result["ownedExits"] = exits
        if producer_error is None and capture_error is not None:
            raise capture_error


def run_external_oci_business_lane(client, native, worker, s3, database_machine, pair_tools,
                                    prepared, processes, boundaries, artifacts, reviewer_public_key,
                                    ownership, workflow, database_host):
    """Execute the genuine business sequence inside the outer capture lifetime."""
    tools = pair_tools
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    observed = observe_external_oci_pair(worker, pair_tools, prepared, processes, "bootstrap")
    label = "external-oci-" + run
    observation_sha = retain_direct_flow(label + "-bootstrap-observations.json", observed)
    reviewed = await_direct_review(label + "-provider-inputs", {
        "actualPair": retain_direct_flow(label + "-actual-pair.json", {
            "prepared": prepared, "boundaries": boundaries, "processes": processes}),
        "sourceClockNamespace": observation_sha,
    }, {"privateStagePolicy", "providerReviewFile"})
    selected = {**reviewed["selection"], "providerPrefix":
        coordinates["placementPrefix"].rsplit("/", 1)[0] + "/.aos-direct-upload"}
    provider_body, provider_sha, material = direct_provider_observations(worker, s3, pair_tools, selected,
        observation_root=coordinates["workerRoot"] + "/provider-observation",
        artifact_label="external-oci-" + run + "-provider")
    copy_contract = observe_external_copy_contract(worker, pair_tools,
        observation_root=coordinates["workerRoot"] + "/provider-observation",
        report_sha256=provider_sha, label=label)
    controls, refresh = external_oci_controls(client, pair_tools, prepared)
    reader = provision_operator_reader(database_machine, worker, pair_tools["python"], pair_tools["postgres"],
        database_host, selected_tables=CREDENTIAL_CUSTODY_METADATA_TABLES,
        operator_root=coordinates["workerRoot"] + "/operator",
        database_name=coordinates["databaseName"], operator_role=coordinates["operatorRole"])
    setup = managed_fixture_module(pair_tools["externalOciSetup"], "external_oci_setup_" + run)
    operator = SimpleNamespace(install_operator_provider_versions=install_operator_provider_versions,
        stage_queued_provider_credential=stage_queued_provider_credential,
        read_operator_binding_pins=read_operator_binding_pins)
    credentials = setup.bootstrap_external_oci_binding(controls, worker, pair_tools, coordinates, {
        "organizationSlug": "external-" + run, "organizationName": "External OCI fleet",
        "bindingStableId": "external-binding-" + run, "bindingName": "objects",
        "providerCoordinates": {"bucket": "fleet-s3", "prefix": coordinates["placementPrefix"].rsplit("/", 1)[0],
            "endpoint": {"scheme": "https", "dnsName": "s3.fleet.test", "port": 443},
            "signingRegion": "garage", "accessMode": "private"},
        "versionReferences": {purpose: "secret://fleet/external-oci/" + run + "/" + purpose + "/v1"
            for purpose in ("presign", "read", "list", "write")}, "providerMaterial": material,
    }, operator, database_host)
    fresh = observe_external_oci_pair(worker, pair_tools, prepared, processes, "installed")
    physical = await_direct_review(label + "-physical-authority", {
        "actualProviderReport": provider_sha,
        "currentCredentialSql": retain_direct_flow(label + "-credential-bootstrap.json", credentials),
        "actualNamespaceClock": retain_direct_flow(label + "-before-authority.json", fresh),
        "actualCopyContract": copy_contract["receipt"]["sha256"],
    }, {"authority", "issuerInstallation", "timingProfile", "clockUncertaintySeconds",
        "clockCommitLatencySeconds", "issuerSigningKeyId", "providerContract",
        "privateStagePolicy", "checksumAlgorithm", "maximumGrantLifetimeSeconds"})
    selection = physical["selection"]
    if selection["privateStagePolicy"] != selected["privateStagePolicy"]:
        raise ValueError("External authority changed its observed private policy")
    renewal = read_direct_guest_file(worker, pair_tools["python"],
        coordinates["workerRoot"] + "/materials/HUB_AUTHORITY_RENEWAL_KEY", 65536)
    issuer = provision_external_issuer(native, worker, pair_tools["python"], pair_tools["openssl"],
        selection["issuerInstallation"], selection["timingProfile"], selection["clockUncertaintySeconds"],
        selection["clockCommitLatencySeconds"], selection["issuerSigningKeyId"], renewal,
        pair_tools["issuerCertificate"], pair_tools["issuerPrivateKey"], pair_tools["issuerCertificateHost"],
        issuer_root=coordinates["nativeRoot"] + "/issuer",
        worker_operator_root=coordinates["workerRoot"] + "/operator", listen="127.0.0.1:4680",
        hub_root=coordinates["nativeRoot"] + "/hub")
    files = {"restrictedSqlUrlFile": coordinates["workerRoot"] + "/operator/sql.url",
        "issuerConfigurationFile": coordinates["workerRoot"] + "/operator/issuer/issuer.json",
        "issuerPublicKeyFile": coordinates["workerRoot"] + "/operator/issuer/issuer-public-key.hex",
        "storageWorkKeyFile": pair_tools["storageWorkKeyFile"],
        "secretVersionManifestFile": credentials["operatorVersions"]["manifestFile"],
        "nativeDatabaseUrlFile": prepared["nativeFiles"]["database"]}
    actual_time = int(private_guest_command(native, shlex.join([pair_tools["python"], "-c",
        "import time; print(int(time.time()))"])).strip())
    exports = setup.export_external_oci_setup(native, worker, pair_tools, coordinates, files,
        selection["authority"], credentials, controls,
        SimpleNamespace(admit_external_fixture_authority=admit_external_fixture_authority),
        private_guest_command, actual_time)
    if copy_contract["value"]["private_staging_prefix"] != exports["bootstrap"]["staging_prefix"]:
        raise ValueError("Provider conformance measured another actual Direct staging prefix")
    setup_input = prepare_external_oci_profile_input(native, worker, pair_tools, prepared,
        credentials, exports, copy_contract, files, fresh)
    profile = setup.invoke_external_oci_preparation(native, pair_tools, coordinates,
        setup_input["file"], "profile", private_guest_command)
    consumers = setup.project_external_oci_consumers(exports, profile["profile"], profile["receipt"], {
        "providerReportSha256": provider_sha, "providerContract": copy_contract["value"]["provider_contract"],
        "maximumListPageObjects": 128, "maximumListPages": 128, "providerConcurrency": 3})
    staging = external_consumer_configuration(exports["bootstrap"], selection["providerContract"], provider_body,
        selection["privateStagePolicy"], selection["checksumAlgorithm"], selection["maximumGrantLifetimeSeconds"])
    consumers["HUB_EXTERNAL_STAGING_CONSUMER"] = staging["HUB_EXTERNAL_STAGING_CONSUMER"]
    install_direct_guest_file(native, pair_tools["python"], coordinates["nativeRoot"] + "/issuer/publication.json",
        read_direct_guest_file(worker, pair_tools["python"],
            coordinates["workerRoot"] + "/operator/authority-export/publication.json", 1048576))
    private_guest_command(native, shlex.join(exports["initializeArguments"]), timeout=120)
    issuer_process = launch_managed_process(native, pair_tools, coordinates["nativeRoot"], "issuer",
        exports["serveArguments"], {})
    ownership["issuer"] = issuer_process
    issuer_binding = issuer_service_binding(boundaries["nativeAddress"], 4677, pair_tools["fleetCaPem"],
        pair_tools["issuerCertificateHost"])
    prepared = install_external_oci_consumers(worker, pair_tools, prepared, consumers, issuer_binding, "oci")
    workflow.close(processes)
    processes = restart_external_oci_worker(worker, pair_tools, prepared, processes, "external-oci-installed")
    ownership.update(prepared=prepared, processes=processes)
    workflow.resume(prepared, processes, "ordinary_native")
    hydrated = setup.hydrate_external_oci_setup(native, worker, pair_tools, coordinates, files, exports, private_guest_command)
    source_coordinates = {**coordinates, "workerOrigin": coordinates["publicOrigin"],
        "registryOrganizationSlug": "external-" + run, "clientRoot": coordinates["clientRoot"] + "/producer"}
    producer = managed_fixture_module(pair_tools["managedContainerProducer"], "external_oci_producer_" + run)
    source = producer.prepare_managed_container_source(client, pair_tools, source_coordinates)
    registry = setup.scan_external_oci_registry(controls, coordinates, credentials, [source["trustKey"]], consumers)
    direct = qualify_external_oci_direct(native, worker, pair_tools, prepared, processes,
        exports, artifacts, reviewer_public_key,
        lambda: prepare_external_oci_candidate(native, pair_tools, prepared, setup_input,
            profile, registry, setup, processes["native"]), workflow=workflow, ownership=ownership)
    prepared, processes = direct["prepared"], direct["processes"]
    final_candidate = direct["candidate"]
    workflow.close(processes)
    helper = switch_external_oci_native(native, pair_tools, prepared, processes, registry,
        final_candidate, direct["acceptance"], ownership=ownership)
    processes = {**processes, "native": helper["process"]}
    ownership.update(prepared=prepared, processes=processes, helper=helper)
    helper_codec = select_external_storage_codec(pair_tools, artifacts, processes["native"], run,
        "controlled_external_oci_native")
    workflow.boundaries = {**boundaries, **helper_codec}
    workflow.resume(prepared, processes, "controlled_external_oci_native")
    route_prepared = {**prepared, "coordinates": {**coordinates, "workerOrigin": coordinates["publicOrigin"],
        "workerName": "fleet-external-oci-" + run, "endpointId": "external-endpoint-" + run,
        "probeSecretRef": "external-probe-" + run}}
    route = configure_managed_distribution(client, worker, pair_tools, route_prepared, processes, controls,
        registry, organization_slug="external-" + run,
        listener_observer=lambda: await_external_oci_tls(worker, pair_tools, coordinates["publicOrigin"]))
    policy_tools = prepare_direct_client_provider_policy(client, pair_tools, credentials,
        policy_root=coordinates["clientRoot"] + "/provider-policy",
        artifact_label=label + "-client-policy")
    publication = producer.publish_managed_container(client, policy_tools, controls, source_coordinates,
        registry["registry"], source, refresh)
    readback = read_external_oci_signed_graph(client, policy_tools, source_coordinates, source,
        publication, refresh)
    # Ordinary signed upload invokes the genuine reindexer. Retain its exact
    # current source head rather than inventing a separate reindex RPC.
    reindex = wait_external_oci_signed_index(controls, registry, publication["signedSource"]["sourceCommit"], label)
    read_sql = lambda query, label: read_external_oci_sql(native, pair_tools, prepared, processes["native"], query, label)
    catalogue = observe_external_copy_catalog(read_sql, registry,
        publication["signedSource"]["sourceCommit"], "external-oci-copy-catalogue")
    copied = run_external_placement_copy(controls, registry, credentials["binding"], catalogue,
        run_id=run, retain=retain_direct_flow, read_sql=read_sql)
    cancelled = run_external_copy_cancel_window(native, worker, s3, pair_tools, prepared,
        processes, workflow, controls, registry, credentials["binding"], ownership=ownership)
    lost = run_external_copy_loss_window(native, worker, pair_tools, prepared, processes,
        workflow, controls, registry, credentials["binding"], catalogue, ownership=ownership, read_sql=read_sql)
    report = {"version": 1, "coordinates": coordinates, "processes": processes,
        "copyIsolationCase": pair_tools["copyIsolationCase"],
        "issuerProcess": issuer_process, "operatorReader": reader, "issuer": issuer,
        "providerContract": copy_contract, "exports": exports, "hydration": hydrated,
        "profile": profile, "candidate": final_candidate, "direct": direct["evidence"],
        "helper": helper, "route": route, "publication": publication, "readback": readback,
        "reindex": reindex, "copy": copied, "copyCancellation": cancelled, "copyClosedLoss": lost,
        "nativeBulkBytes": None,
        "scope": "connected emulated External OCI/Copy lane; independent full byte and provider joins required"}
    retain_direct_flow(label + "-business-window.json", report)
    ownership["business"] = report
    return report
