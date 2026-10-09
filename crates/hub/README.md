# AOS Hub crates

Hub package names carry project ownership independently of their directory.
The workspace keeps one lockfile; these directories group source for readers.
Installed executable and protocol names remain stable.

| Package | Responsibility | Dependency boundary |
| --- | --- | --- |
| `aos-hub-model` | Tenancy/IAM values, credential primitives, endpoint and delivery policy, webhook event taxonomy, cache metadata | Portable domain library; no persistence, HTTP server, or application dependencies |
| `aos-hub-db` | Schema migrations, typed capability queries, SQL translation and values, backend abstraction | Depends on domain/shared formats; SQLx drivers compile only on native targets |
| `aos-hub-service` | Authorization and application orchestration, indexing/storage controllers, OAuth/WebAuthn flows, Connect handlers and rendered pages | Consumes model and persistence through runtime ports; no client implementation dependency |
| `aos-hub-api` | Generated Hub messages, ProtoJSON codecs and Connect descriptors | Generates from canonical `api/proto` source; browser/API inventory parity is tested separately |
| `aos-hub-client` | Hub Connect-JSON requests and OAuth login/device/refresh flows | Native client without build-server client or Hub service implementation dependencies |
| `aos-hub-ui` | Portable navigation, route advertisement and presentation values | Shared console presentation vocabulary |
| `aos-hub-native` | Native runtime adapters and the installed `aos-hub` executable | Native database, network and filesystem deployment |
| `aos-hub-worker` | Cloudflare Worker adapters and colocated Durable Object SQL bridge | WebAssembly deployment of the shared application |
| `aos-hub-console` | Browser console | WebAssembly UI consuming API/UI values |

Persistence never imports application orchestration. Native and Worker adapters
import the model and database packages directly where they use their APIs;
`aos-hub-service` is not a compatibility facade for those libraries.

Service operations and persistence queries are grouped by capability. Their
regression suites share focused fixtures, while orchestration tests stay with
the service. Raw SQL fault injection is available only under `test-fixtures`;
production callers use typed database mutations.
