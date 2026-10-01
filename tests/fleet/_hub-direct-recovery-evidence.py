"""Assess recovery coverage without reconstructing killed client counters.

A terminal invocation describes only its fresh attempts. Complete recovered
publication coverage comes from exact retained originals, provider byte receipts
and final verified inventory; these never become synthetic client counters.
"""


def assert_direct_recovered_activity(known, corpus, recovery, mapping, provider, native_requests):
    """Require complete real provider coverage and explicitly partial client data."""
    if (not recovery["terminalCountersUnavailable"] or recovery["interruption"] is None
            or recovery["continuity"] is None or recovery["changedSource"] is None
            or recovery["interruption"]["result"]["exitCode"] != -9
            or recovery["interruption"]["result"]["timedOut"]
            or not recovery["continuity"]["preservedPositiveParts"]
            or not recovery["changedSource"]["journalsUnchanged"]):
        raise ValueError("recovery lacks its exact interrupted original and preserved positive receipts")
    if (provider["unresolvedReceiptIndexes"] or provider["unknownCallers"]
            or provider["nativeProviderCalls"] or not mapping["originals"]):
        raise ValueError("recovered provider corpus or caller coverage remains incomplete")
    uploads = {}
    for receipt in provider["classified"]:
        if (receipt["caller"] == "client" and receipt["method"] == "PUT"
                and receipt["location"] == "stage" and 200 <= receipt["status"] < 300):
            key = (receipt["sessionDigest"], receipt["originalDigest"], receipt["placementDigest"])
            uploads[key] = uploads.get(key, 0) + receipt["objectTransferBytes"]
    coverage = []
    for original in mapping["originals"]:
        key = (original["sessionDigest"], original["originalDigest"], original["placementDigest"])
        received = uploads.get(key, 0)
        if received < int(original["byteSize"]):
            raise ValueError("one verified recovered original lacks actual positive client provider byte coverage")
        coverage.append({"sessionDigest": key[0], "originalDigest": key[1],
            "placementDigest": key[2], "verifiedOriginalBytes": int(original["byteSize"]),
            "positiveClientProviderBodyBytes": received})
    # A is interrupted during Content. Its later Visibility transfer and B's
    # distinct large original still have actual terminal counters. Earlier A
    # transfers remain unavailable here even if their provider receipts exist.
    minimum_known_bytes = DIRECT_LARGE_OBJECT_BYTES + corpus["metadata_source_bytes"]
    if (known["acknowledged_bytes"] < minimum_known_bytes
            or known["provider_successes"] < DIRECT_METADATA_OBJECT_COUNT + 1
            or known["max_provider_active"] < 2
            or known["caps"] < 1 or known["identity"] < 1 or known["commit"] < 1):
        raise ValueError("completed recovery invocations lack actual remaining client activity")
    for phase in ("begin", "grant", "report", "complete"):
        if not 0 < known[phase] < DIRECT_METADATA_OBJECT_COUNT + DIRECT_LARGE_OBJECT_COUNT:
            raise ValueError("completed recovery controls lack actual bounded batching")
    manifest_routes = {
        "begin": "BeginRegistryPublicationManifest", "append": "AppendRegistryPublicationManifest",
        "seal": "SealRegistryPublicationManifest", "commit": "CommitRegistryPublication",
    }
    manifest_calls = {name: sum(request["procedure"] == "/aos.hub.v1.PublishService/" + method
        and request["method"] == "POST" and request["status"] == 200
        for request in native_requests) for name, method in manifest_routes.items()}
    if (manifest_calls["begin"] < 1 or manifest_calls["append"] < 2
            or manifest_calls["seal"] < 1 or manifest_calls["commit"] < 1):
        raise ValueError("actual Native boundary lacks successful original manifest control coverage")
    result = {"version": 1, "clientTerminalCountersComplete": False,
        "unavailableInvocations": recovery["terminalCountersUnavailable"],
        "knownTerminalAcknowledgedBytes": known["acknowledged_bytes"],
        "positiveClientProviderBodyBytes": sum(row["positiveClientProviderBodyBytes"] for row in coverage),
        "providerCoverage": coverage, "nativeManifestCalls": manifest_calls,
        "scope": "actual interruption-inclusive traffic and preserved final originals; provider bytes include retries, no unique-range or reconstructed client-counter inference"}
    retain_direct_flow("actual-recovered-publication-activity.json", result)
    return result
