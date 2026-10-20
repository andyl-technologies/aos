# Detect discarded sandbox paths while accounting for known protocol names.
{
    text = $0

    if (file ~ /-cmake-[^/]+\/bin\/(cmake|ctest|cpack)$/) {
        # CMake's RPC methods occupy complete string literals. Accept only
        # those literals, retaining paths appended to the same line.
        gsub(/^\/build\/(targets|commands)\/?$/, "", text)
    }

    if (file ~ /-docker-buildx-[^/]+\/bin\/docker-buildx$/) {
        # Go pools these Moby endpoint strings with adjacent endpoints.
        # Match their observed neighbours rather than arbitrary descendants
        # of a sandbox directory named cancel or prune.
        gsub(/\/build\/prune\/containers\/\/checkpoints/, "/containers//checkpoints", text)
        gsub(/\/build\/cancel\/checkpoints\/\/attestations/, "/checkpoints//attestations", text)
    }

    if (text ~ /(^|[[:space:]"=:(;,])\/build\//) {
        found = 1
    }
}

END {
    exit(found ? 0 : 1)
}
