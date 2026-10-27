// SPDX-License-Identifier: Apache-2.0
// Reads one compiled private store through the selected Nix library engine.
// Requests nominate only bounded historical path/size DATA. The parent owns
// snapshot authenticity, immutable backing, current Session and original cut.

#include "config.hh"
#include "config-global.hh"
#include "globals.hh"
#include "hash.hh"
#include "local-store.hh"
#include "shared.hh"
#include "store-api.hh"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#ifndef AOS_NIX_ONLINE_DOMAIN_ROOT
#error "The selected package must compile the fixed domain root"
#endif

namespace {

using Json = nlohmann::ordered_json;

constexpr std::string_view domainRoot = AOS_NIX_ONLINE_DOMAIN_ROOT;
constexpr std::string_view logicalStore = "/nix/store";
constexpr std::size_t maximumRequestBytes = 262144;
constexpr std::size_t maximumResponseBytes = 4194304;
constexpr std::size_t maximumObjects = 4096;
constexpr std::uint64_t maximumNarBytes = 1073741824;

[[noreturn]] void refuse()
{
    throw std::runtime_error("fixed private-store readback refused");
}

void require(bool condition)
{
    if (!condition) {
        refuse();
    }
}

void requireExactStorePath(nix::Store & store, const std::string & path)
{
    // The upstream logical-store parser owns path syntax. The authenticated
    // recipe's narrower path set remains a separate parent comparison.
    require(store.printStorePath(store.parseStorePath(path)) == path);
}

std::string readRequest()
{
    std::string request;
    std::array<char, 16384> scratch{};
    while (std::cin) {
        std::cin.read(scratch.data(), scratch.size());
        const auto count = std::cin.gcount();
        require(count >= 0);
        const auto bytes = static_cast<std::size_t>(count);
        require(bytes <= maximumRequestBytes - request.size());
        request.append(scratch.data(), bytes);
    }
    require(std::cin.eof() && !request.empty());
    return request;
}

void setFixedSetting(const std::string & name, const std::string & value)
{
    require(nix::globalConfig.set(name, value));
}

// Checks the byte ceiling before forwarding to the sole upstream hash sink.
// This does not serialize or parse NAR, or introduce a second hash engine.
class CheckedNarSink final : public nix::Sink {
    nix::HashSink & sink;
    std::uint64_t limit;
    std::uint64_t bytes = 0;

public:
    CheckedNarSink(nix::HashSink & sink, std::uint64_t limit)
        : sink(sink), limit(limit)
    {
    }

    void operator()(std::string_view data) override
    {
        require(data.size() <= limit - bytes);
        bytes += static_cast<std::uint64_t>(data.size());
        sink(data);
    }

    void requireComplete(std::uint64_t upstreamBytes) const
    {
        require(bytes == limit && upstreamBytes == bytes);
    }
};

Json readObject(nix::Store & store, const Json & requested)
{
    require(requested.is_object() && requested.size() == 2
        && requested.contains("path") && requested.contains("narSize")
        && requested["path"].is_string() && requested["narSize"].is_number_unsigned());
    const auto path = requested["path"].get<std::string>();
    const auto ceiling = requested["narSize"].get<std::uint64_t>();
    require(ceiling != 0 && ceiling <= maximumNarBytes);
    requireExactStorePath(store, path);
    const auto storePath = store.parseStorePath(path);
    require(store.printStorePath(storePath) == path);

    const auto info = store.queryPathInfo(storePath);
    require(info->path == storePath && info->narHash.algo == nix::HashAlgorithm::SHA256
        && info->narSize == ceiling && info->references.size() <= maximumObjects);
    nix::HashSink hash(nix::HashAlgorithm::SHA256);
    CheckedNarSink checked(hash, ceiling);
    store.narFromPath(storePath, checked);
    const auto [actualHash, actualBytes] = hash.finish();
    checked.requireComplete(actualBytes);
    require(actualHash == info->narHash);

    Json references = Json::array();
    std::size_t referenceBytes = 0;
    for (const auto & reference : info->references) {
        const auto printed = store.printStorePath(reference);
        requireExactStorePath(store, printed);
        require(printed.size() + 3 <= maximumResponseBytes - referenceBytes);
        referenceBytes += printed.size() + 3;
        references.push_back(printed);
    }
    // StorePath ordering is hash-part ordering, not a promised string order.
    // The wire contract's complete path set is sorted after exact validation.
    std::sort(references.begin(), references.end());

    Json deriver = nullptr;
    if (info->deriver) {
        const auto printed = store.printStorePath(*info->deriver);
        requireExactStorePath(store, printed);
        deriver = printed;
    }
    return Json{
        {"path", path},
        {"dbNarHash", info->narHash.to_string(nix::HashFormat::SRI, true)},
        {"dbNarSize", info->narSize},
        {"actualNarHash", actualHash.to_string(nix::HashFormat::SRI, true)},
        {"actualNarSize", actualBytes},
        {"references", std::move(references)},
        {"deriver", std::move(deriver)},
    };
}

std::string readRoots(nix::LocalStore & store, const Json & request)
{
    const auto operation = request["operation"].get<std::string>();
    require(operation == "plan-roots" || operation == "register-roots"
        || operation == "inspect-roots");
    require(request["names"].is_array() && request["names"].size() == request["paths"].size()
        && request["names"].size() <= 256);

    const auto directDirectory = std::string(domainRoot) + "/nix/var/nix/gcroots/aos-online";
    const auto indirectDirectory = std::string(domainRoot) + "/nix/var/nix/gcroots/auto";
    require(std::filesystem::is_directory(std::filesystem::symlink_status(directDirectory))
        && std::filesystem::is_directory(std::filesystem::symlink_status(indirectDirectory)));

    Json response{{"version", 2}, {"roots", Json::array()}};
    std::string previous;
    for (std::size_t index = 0; index < request["paths"].size(); ++index) {
        const auto & requested = request["paths"][index];
        const auto path = requested["path"].get<std::string>();
        require(previous.empty() || previous < path);
        // Complete the ordinary DB/NAR readback for every output before the
        // first possible write. Its hash/parser engine is not duplicated.
        static_cast<void>(readObject(store, requested));

        const auto name = request["names"][index].get<std::string>();
        require(name.size() == 64 && std::all_of(name.begin(), name.end(), [](char value) {
            return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
        }));
        const auto direct = directDirectory + "/" + name;
        // Exactly LocalStore::addIndirectRoot's selected upstream engine and
        // physical path argument. Rust does not recreate its SHA1/Nix32 codec.
        const auto indirect = indirectDirectory + "/"
            + nix::hashString(nix::HashAlgorithm::SHA1, direct)
                .to_string(nix::HashFormat::Nix32, false);
        for (const auto & old : response["roots"]) {
            require(old["direct"] != direct && old["indirect"] != indirect);
        }
        response["roots"].push_back(Json{
            {"path", path}, {"direct", direct}, {"indirect", indirect}, {"target", path},
        });
        previous = path;
    }

    if (operation == "register-roots") {
        // The parent has retained and checked both complete original directory
        // inventories. Do not let upstream's replace-capable recipe adopt an
        // already-present link, including a dangling symlink.
        for (const auto & root : response["roots"]) {
            require(std::filesystem::symlink_status(root["direct"].get<std::string>()).type()
                    == std::filesystem::file_type::not_found
                && std::filesystem::symlink_status(root["indirect"].get<std::string>()).type()
                    == std::filesystem::file_type::not_found);
        }
        for (const auto & root : response["roots"]) {
            const auto path = root["path"].get<std::string>();
            const auto direct = root["direct"].get<std::string>();
            require(store.addPermRoot(store.parseStorePath(path), direct) == direct);
        }
        // addPermRoot may have created a temp link or replaced a named link
        // before failing. No retry, deletion, healing or durable receipt is
        // emitted here; the parent's original directories/attempt survive.
    }
    if (operation != "plan-roots") {
        for (const auto & root : response["roots"]) {
            const auto direct = root["direct"].get<std::string>();
            const auto indirect = root["indirect"].get<std::string>();
            require(std::filesystem::is_symlink(std::filesystem::symlink_status(direct))
                && std::filesystem::is_symlink(std::filesystem::symlink_status(indirect))
                && std::filesystem::read_symlink(direct).string() == root["target"].get<std::string>()
                && std::filesystem::read_symlink(indirect).string() == direct);
        }
    }
    const auto encoded = response.dump();
    require(encoded.size() <= maximumResponseBytes);
    return encoded;
}

std::string readStore(const std::string & rawRequest)
{
    const auto request = Json::parse(rawRequest);
    const bool roots = request.is_object() && request.contains("version")
        && request["version"].is_number_unsigned() && request["version"] == 2;
    if (roots) {
        require(request.dump() == rawRequest && request.size() == 4
            && request.contains("operation") && request["operation"].is_string()
            && request.contains("paths") && request["paths"].is_array()
            && !request["paths"].empty() && request["paths"].size() <= 256
            && request.contains("names"));
    } else {
        require(request.dump() == rawRequest && request.is_object() && request.size() == 2
        && request.contains("version") && request.contains("paths")
        && request["version"].is_number_unsigned() && request["version"] == 1
        && request["paths"].is_array() && !request["paths"].empty()
        && request["paths"].size() <= maximumObjects);
    }

    // Configuration files, plugins, substituters and build engines are not
    // inputs. initNix still starts its real upstream signal-handler thread.
    nix::initNix(false);
    setFixedSetting("experimental-features", "read-only-local-store");
    setFixedSetting("gc-reserved-space", "0");
    setFixedSetting("use-sqlite-wal", "false");
    setFixedSetting("substitute", "false");
    setFixedSetting("substituters", "");
    setFixedSetting("trusted-substituters", "");
    setFixedSetting("build-users-group", "");
    setFixedSetting("build-hook", "");
    setFixedSetting("pre-build-hook", "");
    setFixedSetting("post-build-hook", "");

    const std::string root(domainRoot);
    const auto store = nix::openStore("local", {
        {"root", root}, {"store", std::string(logicalStore)},
        {"state", root + "/nix/var/nix"}, {"real", root + "/nix/store"},
        {"read-only", "true"},
    });
    const auto local = store.dynamic_pointer_cast<nix::LocalStore>();
    require(local && local->readOnly.get() && store->storeDir == logicalStore
        && local->getRealStoreDir() == root + "/nix/store"
        && local->stateDir.get() == root + "/nix/var/nix");

    if (roots) {
        return readRoots(*local, request);
    }

    Json response{{"version", 1}, {"objects", Json::array()}};
    // Reserve the exact outer JSON punctuation before each entry grows the
    // result. No successful partial response is written before all entries.
    std::size_t responseBytes = response.dump().size();
    std::string previous;
    for (const auto & requested : request["paths"]) {
        require(requested.contains("path") && requested["path"].is_string());
        const auto path = requested["path"].get<std::string>();
        require(previous.empty() || previous < path);
        auto object = readObject(*store, requested);
        const auto encoded = object.dump();
        const auto separator = response["objects"].empty() ? 0U : 1U;
        require(separator <= maximumResponseBytes - responseBytes);
        responseBytes += separator;
        require(encoded.size() <= maximumResponseBytes - responseBytes);
        responseBytes += encoded.size();
        response["objects"].push_back(std::move(object));
        previous = path;
    }
    auto encoded = response.dump();
    require(encoded.size() == responseBytes && encoded.size() <= maximumResponseBytes);
    return encoded;
}

} // namespace

int main(int argc, char **)
{
    try {
        require(argc == 1);
        const auto response = readStore(readRequest());
        std::cout.write(response.data(), response.size());
        std::cout.flush();
        return std::cout ? 0 : 1;
    } catch (...) {
        // Exception details and impure DB strings are not an authority or
        // unbounded diagnostic protocol. The parent retains real exit/capture.
        std::cerr << "fixed private-store readback failed\n";
        return 1;
    }
}
