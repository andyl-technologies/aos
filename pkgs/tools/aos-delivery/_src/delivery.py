"""Submits and observes the exact AOS hybrid staging application boundary.

No command provisions cloud resources, accesses provider credentials or signs
release evidence. Infrastructure owns those operations through its registered
delivery graph and qualified engine generation.
"""

import argparse
import base64
import json
import os
import re
import sys

import artifact
from transport import ARTIFACT_MEDIA_TYPE, Client, DeliveryError, OPERATION_NAME, encoded


COORDINATE_VERSION = "delivery.andyl.com/artifact-coordinate/v1"
ARTIFACT_NAME = re.compile(r"artifacts/[a-z0-9][a-z0-9-]{0,126}\Z")


def source_for(args):
    """Builds protobuf JSON source fields from proved workflow coordinates."""
    artifact.prove_source(args.source_sha)
    declaration = artifact.declaration_content(args.declaration)
    return {
        "repository": artifact.REPOSITORY,
        "repositoryOwnerId": "159484437",
        "repositoryId": "1156711779",
        "commitSha": args.source_sha,
        "ref": artifact.REF,
        "workflowRef": artifact.WORKFLOW,
        "workflowRunId": os.environ["GITHUB_RUN_ID"],
        "declarationDigest": artifact.digest(declaration),
        "declaration": base64.b64encode(declaration).decode(),
    }


def target_for(phase):
    """Selects one of the two fixed registered staging targets."""
    if phase not in ("application", "release-graph"):
        raise DeliveryError("staging phase is outside the registered client contract")
    return {
        "application": artifact.APPLICATION,
        "environment": "staging",
        "phase": phase,
        "surface": "all" if phase == "application" else "native",
    }


def coordinate_for(target, source):
    """Binds finalized intake to the same source, workflow, run and release target."""
    return {
        "apiVersion": COORDINATE_VERSION,
        **target,
        "repository": source["repository"],
        "repositoryOwnerId": source["repositoryOwnerId"],
        "repositoryId": source["repositoryId"],
        "sourceCommit": source["commitSha"],
        "sourceRef": source["ref"],
        "workflowRef": source["workflowRef"],
        "workflowRunId": source["workflowRunId"],
        "declarationDigest": source["declarationDigest"],
    }


def checked_coordinate(path, target, source):
    """Rejects a coordinate from another job run, source, component or target."""
    coordinate = artifact.read_json(path)
    expected = coordinate_for(target, source)
    expected.update({"name": coordinate.get("name"), "digest": coordinate.get("digest")})
    if (
        coordinate != expected
        or not ARTIFACT_NAME.fullmatch(coordinate.get("name", ""))
        or not artifact.DIGEST.fullmatch(coordinate.get("digest", ""))
    ):
        raise DeliveryError("artifact coordinate crosses its workflow or source boundary")
    return coordinate


def request_id(command, target):
    """Derives stable idempotency from the current run, attempt and typed target."""
    value = encoded({
        "run": os.environ["GITHUB_RUN_ID"],
        "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "command": command,
        "target": target,
    })
    return "gh-hub-" + artifact.digest(value).removeprefix("sha256:")


def checked_operation(operation, target, source, anchor="", artifact_name=""):
    """Fences a returned operation to its submitted source and registered target."""
    if (
        not OPERATION_NAME.fullmatch(operation.get("name", ""))
        or operation.get("target") != target
    ):
        raise DeliveryError("operation does not match the submitted target")
    returned = operation.get("source", {})
    public_source_fields = (
        "repository", "repositoryOwnerId", "repositoryId", "commitSha", "ref",
        "workflowRef", "workflowRunId", "declarationDigest", "artifactDigest",
    )
    # Operation APIs omit declaration bytes; their digest binds the full input.
    for field in public_source_fields:
        if returned.get(field, "") != source.get(field, ""):
            raise DeliveryError("operation does not match the submitted source")
    if (
        operation.get("generationAnchor", "") != anchor
        or operation.get("artifact", "") != artifact_name
    ):
        raise DeliveryError("operation does not retain the selected artifact or engine anchor")
    return operation


def watch(args, client, source):
    """Observes an operation fenced to the explicitly selected registered target."""
    if not OPERATION_NAME.fullmatch(args.operation):
        raise DeliveryError("operation name is invalid")
    target = target_for(args.phase)
    anchor = ""
    artifact_name = ""
    if args.phase == "release-graph":
        if (
            not args.artifact_coordinate
            or not OPERATION_NAME.fullmatch(args.generation_anchor or "")
        ):
            raise DeliveryError("release observation requires its artifact coordinate and engine anchor")
        coordinate = checked_coordinate(args.artifact_coordinate, target, source)
        source = {**source, "artifactDigest": coordinate["digest"]}
        artifact_name = coordinate["name"]
        anchor = args.generation_anchor
    elif args.artifact_coordinate or args.generation_anchor:
        raise DeliveryError("base observation cannot select an artifact or engine anchor")

    operation = client.rpc(
        "GetOperation", {"name": args.operation}, operations=True,
    ).get("operation", {})
    if operation.get("name") != args.operation:
        raise DeliveryError("operation observation crossed its requested name")
    checked_operation(operation, target, source, anchor, artifact_name)
    print(encoded(client.wait(operation, args.timeout)).decode())


def upload(args, client, target, source):
    """Reserves, uploads and finalizes actual bytes through the API-only lane."""
    digest, size = artifact.file_digest(args.artifact)
    if not 0 < size <= 2 << 30:
        raise DeliveryError("bundle exceeds the immutable artifact size boundary")
    source = {**source, "artifactDigest": digest}
    identity = request_id("upload-artifact", target)
    reservation = client.rpc("BeginArtifactUpload", {
        "requestId": identity,
        "target": target,
        "source": source,
        "sizeBytes": str(size),
        "digest": digest,
        "mediaType": ARTIFACT_MEDIA_TYPE,
    }).get("upload", {})
    name = reservation.get("name", "")
    if not ARTIFACT_NAME.fullmatch(name):
        raise DeliveryError("artifact reservation name is invalid")
    with open(args.artifact, "rb") as content:
        client.upload(reservation, content, size, digest)
    finalized = client.rpc("FinalizeArtifactUpload", {
        "requestId": identity,
        "upload": name,
    }).get("artifact", {})
    if (
        finalized.get("digest") != digest
        or str(finalized.get("sizeBytes")) != str(size)
        or finalized.get("sourceCommit") != source["commitSha"]
        or finalized.get("declarationDigest") != source["declarationDigest"]
        or not re.fullmatch(r"[1-9][0-9]{0,19}", str(finalized.get("objectGeneration", "")))
        or finalized.get("mediaType") != ARTIFACT_MEDIA_TYPE
        or not ARTIFACT_NAME.fullmatch(finalized.get("name", ""))
    ):
        raise DeliveryError("finalized artifact differs from the actual bundle and source")
    return {
        **coordinate_for(target, source),
        "name": finalized["name"],
        "digest": digest,
    }


def reconcile(args, client, target, source):
    """Submits the registered base or anchored release graph once."""
    body = {"requestId": request_id(args.command, target), "target": target, "source": source}
    anchor = ""
    artifact_name = ""
    method = "ReconcileApplication"
    if args.command == "reconcile-artifact":
        if not OPERATION_NAME.fullmatch(args.generation_anchor or ""):
            raise DeliveryError("release requires a completed base engine anchor")
        coordinate = checked_coordinate(args.artifact_coordinate, target, source)
        artifact_name, anchor = coordinate["name"], args.generation_anchor
        source["artifactDigest"] = coordinate["digest"]
        body.update({"artifact": artifact_name, "generationAnchor": anchor})
        body = {"reconciliation": body}
        method = "ReconcileAnchoredApplication"
    operation = checked_operation(
        client.rpc(method, body).get("operation", {}),
        target, source, anchor, artifact_name,
    )
    # Persist the typed coordinate immediately, so observation can be resumed
    # even when a later network request or credential refresh fails.
    if args.github_output:
        with open(args.github_output, "a") as output:
            output.write("operation=" + operation["name"] + "\n")
    print(encoded(operation).decode(), flush=True)
    if args.wait:
        client.wait(operation, args.timeout)


def main(argv=None):
    """Parses explicit typed commands; no arbitrary graph or provider inputs exist."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prove = commands.add_parser("prove-source")
    prove.add_argument("--source-sha", required=True)
    database = commands.add_parser("validate-database")
    database.add_argument("--status", required=True)
    bundle = commands.add_parser("bundle")
    bundle_inputs = (
        "source-sha", "declaration", "image", "evidence",
        "cataloger", "scanner", "database-status", "output",
    )
    for name in bundle_inputs:
        bundle.add_argument("--" + name, required=True)
    for command in ("upload-artifact", "reconcile", "reconcile-artifact", "watch"):
        sub = commands.add_parser(command)
        for name in ("endpoint", "source-sha", "declaration"):
            sub.add_argument("--" + name, required=True)
        if command == "upload-artifact":
            sub.add_argument("--artifact", required=True)
        if command == "reconcile-artifact":
            sub.add_argument("--artifact-coordinate", required=True)
            sub.add_argument("--generation-anchor", required=True)
        if command in ("reconcile", "reconcile-artifact"):
            sub.add_argument("--github-output")
            sub.add_argument("--wait", action=argparse.BooleanOptionalAction, default=True)
        if command == "watch":
            sub.add_argument("--operation", required=True)
            sub.add_argument("--phase", choices=("application", "release-graph"), required=True)
            sub.add_argument("--generation-anchor")
            sub.add_argument("--artifact-coordinate")
        sub.add_argument("--timeout", type=int, default=3000)
    args = parser.parse_args(argv)
    if args.command == "validate-database":
        validate_database(artifact.read_json(args.status))
        return
    if args.command == "prove-source":
        artifact.prove_source(args.source_sha)
        return
    if args.command == "bundle":
        artifact.build_bundle(args)
        return
    source = source_for(args)
    client = Client(args.endpoint)
    if not 0 < args.timeout <= 3000:
        raise DeliveryError("observation timeout must be between 1 and 3000 seconds")
    target = target_for("application" if args.command == "reconcile" else "release-graph")
    if args.command == "upload-artifact":
        print(encoded(upload(args, client, target, source)).decode())
    elif args.command == "watch":
        watch(args, client, source)
    else:
        reconcile(args, client, target, source)


def validate_database(status):
    """Checks actual Grype status against the admitted schema and age bounds."""
    artifact.validate_database(status)


if __name__ == "__main__":
    try:
        main()
    except (DeliveryError, OSError, ValueError) as error:
        print("aos-delivery: " + str(error), file=sys.stderr)
        sys.exit(1)
