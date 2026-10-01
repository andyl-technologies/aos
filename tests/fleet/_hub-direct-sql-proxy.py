"""Count the Worker operator's PostgreSQL wire bytes independently of Native API.

The listener accepts only local operator connections. The database still owns
authentication and table privileges. Only numeric per-connection observations
are retained; SQL, credentials and provider material are never logged.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import signal


async def serve(options):
    """Forward actual SQL connections and retain offered/completed byte counts."""
    descriptor = os.open(options.output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    output = os.fdopen(descriptor, "w")
    active = set()
    sequence = 0

    async def connection(reader, writer):
        nonlocal sequence
        task = asyncio.current_task()
        active.add(task)
        sequence += 1
        observation = {
            "version": 1,
            "traffic_class": "operator_postgresql_metadata_wire",
            "connection": sequence,
            "client_read_bytes": 0,
            "database_read_bytes": 0,
            "client_to_database_forwarded_bytes": 0,
            "database_to_client_forwarded_bytes": 0,
            "outcome": "pending",
        }
        remote = None

        async def relay(source, destination, read_field, forwarded_field):
            while block := await source.read(64 * 1024):
                observation[read_field] += len(block)
                destination.write(block)
                await destination.drain()
                observation[forwarded_field] += len(block)

        try:
            remote_reader, remote = await asyncio.open_connection(
                options.upstream_host, options.upstream_port,
            )
            pipes = [
                asyncio.create_task(relay(reader, remote, "client_read_bytes", "client_to_database_forwarded_bytes")),
                asyncio.create_task(relay(remote_reader, writer, "database_read_bytes", "database_to_client_forwarded_bytes")),
            ]
            try:
                done, pending = await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
                for completed in done:
                    completed.result()
                observation["outcome"] = "peer_eof"
            finally:
                for pipe in pipes:
                    if not pipe.done():
                        pipe.cancel()
                await asyncio.gather(*pipes, return_exceptions=True)
        except asyncio.CancelledError:
            observation["outcome"] = "cancelled"
        except OSError:
            observation["outcome"] = "transport_error"
        finally:
            writer.close()
            if remote is not None:
                remote.close()
            output.write(json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())
            active.discard(task)

    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stopping.set)
    try:
        server = await asyncio.start_server(connection, "127.0.0.1", options.listen_port)
        async with server:
            await stopping.wait()
        for task in tuple(active):
            task.cancel()
        await asyncio.gather(*tuple(active), return_exceptions=True)
    finally:
        output.close()


def main():
    """Run the local numeric observer with explicit isolated SQL coordinates."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, default=5432)
    parser.add_argument("--output-file", type=Path, required=True)
    options = parser.parse_args()
    if not 1 <= options.listen_port <= 65535 or not 1 <= options.upstream_port <= 65535:
        raise ValueError("operator SQL observer port is invalid")
    asyncio.run(serve(options))


if __name__ == "__main__":
    main()
