The six Java files in this directory are adapted source from
`JetBrains/intellij-community` commit
`5be8cb0a3dd4b8aa202c535649bf000591441c70` (21 August 2013).
They supply headless PSI and utility APIs required by the November 2013 Kotlin
compiler while the existing AOS IntelliJ bootstrap remains at its pinned
2012 source stages. Each file retains its upstream Apache 2.0 header.

The release derivation compiles these files from source. It rejects compiled
payloads in both the fetched Kotlin tree and this directory before building.
