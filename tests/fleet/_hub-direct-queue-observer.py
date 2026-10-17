"""Bind real emulator startup queue readback to the observed installation.

The runner captures supported queue options after Miniflare becomes ready.
This observer checks the same live runner and exact configuration commitment.
Delivery, restarts and provider pool measurements remain separate evidence.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def read_regular_file(path, limit):
    """Read a bounded stable regular file, refusing blocking special files."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("queue observation input is not a bounded regular file")
        body = source.read(limit + 1)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("queue observation input changed during capture")
    if len(body) != before.st_size:
        raise ValueError("queue observation input length changed during capture")
    return body


def closed_document(path, fields):
    """Read a bounded closed JSON observation without echoing its contents."""
    body = read_regular_file(path, 256 * 1024)
    value = json.loads(body)
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("queue observation fields differ from the contract")
    return value


def observe_queue(options):
    """Validate live startup facts and return a closed per-queue readback."""
    startup = closed_document(options.startup_file, {
        "version", "runnerPid", "runnerStartTicks", "configurationSha256",
        "invocationBoundSupport", "queueOptions",
    })
    installation = json.loads(read_regular_file(options.installation_file, 256 * 1024))
    if startup["version"] != 1 or startup["invocationBoundSupport"] != "unsupported":
        raise ValueError("emulator invocation support was not explicitly observed")
    if installation["version"] != 1 or installation["executionKind"] != "emulated_external":
        raise ValueError("queue readback requires an observed External emulator installation")
    configuration_sha256 = hashlib.sha256(
        read_regular_file(options.configuration_file, 16 * 1024 * 1024)
    ).hexdigest()
    if configuration_sha256 != startup["configurationSha256"]:
        raise ValueError("configuration changed since the actual runtime startup")
    if configuration_sha256 != installation["runtimeBindingsSha256"]:
        raise ValueError("startup configuration differs from the observed installation")

    pid = startup["runnerPid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("actual runner PID is invalid")
    process = Path("/proc") / str(pid)
    start_ticks = (process / "stat").read_text().rpartition(") ")[2].split()[19]
    if start_ticks != startup["runnerStartTicks"]:
        raise ValueError("observed queue runner lifetime differs from startup")
    command = (process / "cmdline").read_bytes().split(b"\0")
    expected_runner = os.fsencode(options.runner_file.resolve(strict=True))
    expected_configuration = os.fsencode(options.configuration_file.resolve(strict=True))
    if len(command) != 5 or command[1] != expected_runner or command[3] != expected_configuration:
        raise ValueError("observed queue runner has different installed arguments")
    if hashlib.sha256(read_regular_file(options.runner_file, 1024 * 1024)).hexdigest() != installation["runnerSha256"]:
        raise ValueError("queue runner differs from the observed installation")

    queues = startup["queueOptions"]
    if not isinstance(queues, dict) or set(queues) != {"queueConsumers", "queueProducers"}:
        raise ValueError("actual queue options are incomplete")
    consumers = queues["queueConsumers"]
    producers = queues["queueProducers"]
    if not isinstance(consumers, dict) or not isinstance(producers, dict):
        raise ValueError("queue mappings must use explicit named settings")
    consumer = consumers.get(options.queue_name)
    if not isinstance(consumer, dict) or "maxConcurrentInvocations" in consumer:
        raise ValueError("emulator consumer settings differ from supported readback")
    batch = consumer.get("maxBatchSize")
    if isinstance(batch, bool) or not isinstance(batch, int) or not 1 <= batch <= 100:
        raise ValueError("actual explicit maximum batch size is unavailable")
    binding = "HUB_DIRECT_VERIFY_BULK" if options.queue_class == "bulk" else "HUB_DIRECT_VERIFY_METADATA"
    producer = producers.get(binding)
    queue_name = producer.get("queueName") if isinstance(producer, dict) else producer
    if queue_name != options.queue_name:
        raise ValueError("actual verification producer has a different queue consumer")

    report = {
        "version": 1,
        "executionKind": installation["executionKind"],
        "deploymentId": installation["deploymentId"],
        "publicOrigin": installation["publicOrigin"],
        "sourceDigest": installation["sourceDigest"],
        "scriptVersion": installation["scriptVersion"],
        "queueName": options.queue_name,
        "maximumBatchSize": str(batch),
        "maximumConcurrentInvocations": None,
        "invocationBoundSupport": "unsupported",
        "runtimeBindingsSha256": configuration_sha256,
        "distributionNarSha256": installation["distributionNarSha256"],
    }
    if (process / "stat").read_text().rpartition(") ")[2].split()[19] != start_ticks:
        raise ValueError("observed queue runner changed during capture")
    return report


def main():
    """Write an independently selected, create-new private queue observation."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("startup-file", "installation-file", "configuration-file", "runner-file", "output-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--queue-name", required=True)
    parser.add_argument("--queue-class", choices=("bulk", "metadata"), required=True)
    options = parser.parse_args()
    report = observe_queue(options)
    descriptor = os.open(options.output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(report, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    main()
