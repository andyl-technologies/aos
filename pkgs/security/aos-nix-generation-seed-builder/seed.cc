// SPDX-License-Identifier: Apache-2.0
/* Build-only seed DATA using the selected Nix LocalStore and NAR engines.
 * The finalized descriptor is measured outside its root. No runtime owner,
 * generation, signature, resource admission or currentness is created here.
 */
#include "archive.hh"
#include "config.hh"
#include "config-global.hh"
#include "file-descriptor.hh"
#include "file-system.hh"
#include "fs-sink.hh"
#include "globals.hh"
#include "hash.hh"
#include "local-store.hh"
#include "path-info.hh"
#include "serialise.hh"
#include "shared.hh"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using Json = nlohmann::json;
constexpr uint64_t controlLimit = 64ULL << 20;
constexpr uint64_t objectNarLimit = 64ULL << 30;
constexpr uint64_t closureNarLimit = 1ULL << 40;
constexpr uint64_t rootNarLimit = closureNarLimit + (1ULL << 30);
constexpr size_t rootCountLimit = 4096;
constexpr size_t pathCountLimit = 65536;
constexpr std::string_view controlDirectory = "etc/aos/nix-generation";
constexpr char targetDomain[] = "aos.sandbox.nix.seed.target.v1";
constexpr char contentDomain[] = "aos.sandbox.nix.seed.content.v1";
constexpr std::string_view seedConfig =
    "build-users-group =\n"
    "experimental-features = nix-command flakes read-only-local-store\n"
    "gc-reserved-space = 0\n"
    "substitute = false\n"
    "substituters =\n"
    "trusted-substituters =\n"
    "use-sqlite-wal = false\n";

void require(bool condition, std::string_view reason)
{
    if (!condition) throw std::runtime_error(std::string(reason));
}

uint64_t addBounded(uint64_t left, uint64_t right, uint64_t limit)
{
    require(left <= limit && right <= limit - left, "seed byte/count bound exceeded");
    return left + right;
}

struct stat inspect(const fs::path & path)
{
    struct stat result {};
    if (lstat(path.c_str(), &result) != 0) throw nix::SysError("lstat '%s'", path.string());
    return result;
}

struct stat inspectFd(int descriptor)
{
    struct stat result {};
    if (fstat(descriptor, &result) != 0) throw nix::SysError("fstat seed original");
    return result;
}

void requireSameFile(const struct stat & before, const struct stat & after)
{
    require(before.st_dev == after.st_dev && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode && before.st_size == after.st_size
        && before.st_mtim.tv_sec == after.st_mtim.tv_sec
        && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec,
        "seed original changed during read");
}

// Test the same buffered source, not just its underlying file offset.
void requireEof(nix::Source & source)
{
    char extra;
    try {
        require(source.read(&extra, 1) == 0, "trailing bytes after seed input");
    } catch (const nix::EndOfFile &) {
        return;
    }
}

std::string readBounded(const fs::path & path, uint64_t limit = controlLimit)
{
    nix::AutoCloseFD file(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (!file) throw nix::SysError("open seed control '%s'", path.string());
    const auto before = inspectFd(file.get());
    require(S_ISREG(before.st_mode) && before.st_size >= 0
        && uint64_t(before.st_size) <= limit
        && uint64_t(before.st_size) <= std::numeric_limits<size_t>::max(),
        "seed control kind or extent outside bound");

    std::string bytes(size_t(before.st_size), '\0');
    nix::FdSource source(file.get());
    source(bytes.data(), bytes.size());
    requireEof(source);
    requireSameFile(before, inspectFd(file.get()));
    requireSameFile(before, inspect(path));
    return bytes;
}

void writeFresh(const fs::path & path, std::string_view bytes)
{
    nix::AutoCloseFD file(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644));
    if (!file) throw nix::SysError("create seed output '%s'", path.string());
    nix::writeFull(file.get(), bytes);
    if (fsync(file.get()) != 0) throw nix::SysError("sync seed output '%s'", path.string());
    file.close();
}

void requireTarget(std::string_view target)
{
    require(!target.empty() && target.size() <= 256
        && std::all_of(target.begin(), target.end(), [](unsigned char byte) {
            return byte >= 0x21 && byte <= 0x7e;
        }), "invalid seed target");
    require(target == "x86_64-linux" || target == "aarch64-linux", "unsupported seed target");
}

void configureNix()
{
    nix::initNix(false);
    for (const auto & [name, value] : std::array<std::pair<const char *, const char *>, 12> {{
        {"gc-reserved-space", "0"}, {"use-sqlite-wal", "false"},
        {"fsync-metadata", "true"}, {"build-users-group", ""},
        {"substitute", "false"}, {"substituters", ""},
        {"trusted-substituters", ""}, {"build-hook", ""},
        {"pre-build-hook", ""}, {"post-build-hook", ""},
        {"use-case-hack", "false"}, {"experimental-features", "read-only-local-store"}
    }}) {
        require(nix::globalConfig.set(name, value), "unknown selected Nix setting");
    }
}

nix::Store::Params storeParameters(const fs::path & root, bool readOnly)
{
    return {{"root", root.string()}, {"store", "/nix/store"},
        {"real", (root / "nix/store").string()},
        {"state", (root / "nix/var/nix").string()},
        {"log", (root / "nix/var/log/nix").string()},
        {"read-only", readOnly ? "true" : "false"}};
}

void requireLocation(const nix::LocalStore & store, const fs::path & root, bool readOnly)
{
    require(store.storeDir == "/nix/store" && store.realStoreDir.get() == (root / "nix/store").string()
        && store.stateDir.get() == (root / "nix/var/nix").string()
        && store.logDir.get() == (root / "nix/var/log/nix").string()
        && store.rootDir.get() == std::optional<std::string>(root.string())
        && store.readOnly.get() == readOnly, "LocalStore resolved outside seed root");
}

nix::StorePath canonicalPath(const nix::Store & store, const std::string & path)
{
    require(path.size() <= 4096, "store path exceeds seed bound");
    auto parsed = store.parseStorePath(path);
    require(store.printStorePath(parsed) == path, "noncanonical seed store path");
    return parsed;
}

nix::ValidPathInfos decodeRegistration(const nix::Store & store, const std::string & bytes)
{
    require(bytes.size() <= controlLimit, "registration exceeds seed bound");
    std::istringstream stream(bytes);
    nix::ValidPathInfos result;
    while (stream.peek() != std::char_traits<char>::eof()) {
        require(result.size() < pathCountLimit, "too many registered seed paths");
        auto info = nix::decodeValidPathInfo(store, stream, std::nullopt);
        require(info.has_value(), "incomplete seed registration");
        require(!info->deriver && info->narHash.algo == nix::HashAlgorithm::SHA256
            && info->narSize > 0 && info->narSize <= objectNarLimit,
            "invalid seed registration information");
        auto path = info->path;
        require(result.emplace(path, std::move(*info)).second, "duplicate seed registration path");
    }
    require(stream.eof() && !stream.bad() && !result.empty(), "registration input was not fully consumed");
    return result;
}

struct Graph
{
    std::string inventory;
    nix::ValidPathInfos paths;
    nix::StorePathSet roots;
};

void requireKeys(const Json & object, std::initializer_list<const char *> keys)
{
    require(object.is_object() && object.size() == keys.size(), "unexpected graph fields");
    for (const char * key : keys) require(object.contains(key), "missing graph field");
}

Graph readGraph(const nix::Store & store, const fs::path & inventoryPath, const std::string & registration)
{
    Graph graph {readBounded(inventoryPath), decodeRegistration(store, registration), {}};
    const auto document = Json::parse(graph.inventory);
    require(document.dump() == graph.inventory, "graph is not canonical compact JSON");
    requireKeys(document, {"paths", "roots", "schema", "subtractRoots"});
    require(document.at("schema") == "aos.reference-graph/v1"
        && document.at("subtractRoots").is_array() && document.at("subtractRoots").empty(),
        "unexpected graph schema or subtraction");
    const auto & roots = document.at("roots");
    const auto & rows = document.at("paths");
    require(roots.is_array() && !roots.empty() && roots.size() <= rootCountLimit
        && rows.is_array() && rows.size() == graph.paths.size(), "invalid graph cardinality");

    std::string previous;
    for (const auto & value : roots) {
        const auto path = value.get<std::string>();
        require(previous.empty() || previous < path, "graph roots not sorted and unique");
        previous = path;
        const auto parsed = canonicalPath(store, path);
        require(graph.paths.contains(parsed), "graph root missing from complete map");
        graph.roots.insert(parsed);
    }

    previous.clear();
    uint64_t total = 0;
    for (const auto & row : rows) {
        requireKeys(row, {"narHash", "narSize", "path", "references"});
        const auto path = row.at("path").get<std::string>();
        require(previous.empty() || previous < path, "graph paths not sorted and unique");
        previous = path;
        const auto parsed = canonicalPath(store, path);
        const auto found = graph.paths.find(parsed);
        require(found != graph.paths.end(), "graph path missing from registration");
        const auto & info = found->second;
        require(row.at("narSize").is_number_unsigned(), "invalid graph NAR size");
        require(row.at("narSize").get<uint64_t>() == info.narSize
            && nix::Hash::parseAny(row.at("narHash").get<std::string>(), nix::HashAlgorithm::SHA256) == info.narHash,
            "graph NAR hash/size differs from registration");
        total = addBounded(total, info.narSize, closureNarLimit);

        const auto & references = row.at("references");
        require(references.is_array() && references.size() == info.references.size(), "graph reference count mismatch");
        nix::StorePathSet parsedReferences;
        std::string previousReference;
        for (const auto & value : references) {
            const auto reference = value.get<std::string>();
            require(previousReference.empty() || previousReference < reference, "graph references not sorted and unique");
            previousReference = reference;
            auto parsedReference = canonicalPath(store, reference);
            require(graph.paths.contains(parsedReference), "incomplete seed reference closure");
            parsedReferences.insert(std::move(parsedReference));
        }
        require(parsedReferences == info.references, "graph references differ from registration");
    }
    return graph;
}

nix::StorePathSet requireMap(nix::LocalStore & store, const nix::ValidPathInfos & paths)
{
    nix::StorePathSet expected;
    std::set<std::string> diskNames {".links"};
    for (const auto & [path, info] : paths) {
        expected.insert(path);
        diskNames.insert(fs::path(store.printStorePath(path)).filename().string());
    }
    require(store.queryAllValidPaths() == expected, "LocalStore valid set differs from seed map");
    for (const auto & entry : fs::directory_iterator(store.realStoreDir.get())) {
        require(diskNames.erase(entry.path().filename().string()) == 1,
            "unregistered object in private seed store");
    }
    require(diskNames.empty(), "registered object missing from private seed store");
    for (const auto & [path, expectedInfo] : paths) {
        const auto actual = store.queryPathInfo(path);
        require(actual->path == path && actual->narHash == expectedInfo.narHash
            && actual->narSize == expectedInfo.narSize && actual->references == expectedInfo.references
            && actual->registrationTime == 1 && !actual->deriver
            && !actual->ultimate && actual->sigs.empty() && !actual->ca,
            "LocalStore row differs from complete seed map");
    }
    return expected;
}

class BoundedSink final : public nix::Sink
{
    nix::Sink & destination;
    uint64_t limit;
    uint64_t count = 0;

public:
    BoundedSink(nix::Sink & destination, uint64_t limit) : destination(destination), limit(limit) { }

    void operator()(std::string_view bytes) override
    {
        count = addBounded(count, bytes.size(), limit);
        destination(bytes);
    }
};

void rewindScratch(int file, bool truncate)
{
    if (truncate && ftruncate(file, 0) != 0) throw nix::SysError("truncate seed NAR scratch");
    if (lseek(file, 0, SEEK_SET) != 0) throw nix::SysError("rewind seed NAR scratch");
}

nix::HashResult dumpNar(const fs::path & path, int file, uint64_t limit, std::string_view domain = {})
{
    rewindScratch(file, true);
    nix::FdSink fileSink(file);
    nix::HashSink hashSink(nix::HashAlgorithm::SHA256);
    hashSink(domain);
    nix::TeeSink tee(fileSink, hashSink);
    BoundedSink bounded(tee, limit);
    nix::dumpPath(path.string(), bounded);

    // Both sinks are buffered. Successful destructor cleanup is not evidence.
    fileSink.flush();
    hashSink.flush();
    auto result = hashSink.finish();
    require(result.second >= domain.size(), "invalid NAR hash extent");
    result.second -= domain.size();
    const auto extent = inspectFd(file);
    require(extent.st_size >= 0 && uint64_t(extent.st_size) == result.second, "scratch NAR extent mismatch");
    rewindScratch(file, false);
    return result;
}

void requireEmptyDirectory(const fs::path & path)
{
    require(S_ISDIR(inspect(path).st_mode) && fs::is_empty(path), "nonempty or missing seed control directory");
}

void requireFinalControls(const fs::path & root, bool finishFresh)
{
    const auto state = root / "nix/var/nix";
    const auto database = state / "db";
    require(readBounded(database / "schema", 2) == "10", "unexpected seed DB schema");
    require(readBounded(database / "reserved", 0).empty(), "seed reserved file is not empty");
    const auto db = inspect(database / "db.sqlite");
    require(S_ISREG(db.st_mode) && db.st_size > 0 && uint64_t(db.st_size) <= controlLimit,
        "seed DB outside bound");

    for (const auto & entry : fs::directory_iterator(database)) {
        const auto name = entry.path().filename().string();
        if (name == "schema" || name == "reserved" || name == "db.sqlite" || name == "big-lock") continue;
        if (finishFresh && name == "db.sqlite-journal" && readBounded(entry.path(), 0).empty()) {
            require(fs::remove(entry.path()), "could not remove closed empty seed journal");
        } else {
            throw std::runtime_error("unexpected auxiliary in finalized seed DB");
        }
    }
    require(readBounded(database / "big-lock", 0).empty(), "seed DB lock file is not empty");

    const auto profilesLink = state / "gcroots/profiles";
    require(S_ISLNK(inspect(profilesLink).st_mode), "missing seed profiles link");
    if (finishFresh) {
        require(fs::read_symlink(profilesLink) == state / "profiles", "unexpected constructor profiles target");
        require(fs::remove(profilesLink), "could not replace fresh profiles link");
        fs::create_symlink("../profiles", profilesLink);
    }
    require(fs::read_symlink(profilesLink) == "../profiles", "seed profiles link is not relative");
    for (const auto & path : {root / "nix/store/.links", state / "temproots",
        state / "profiles/per-user", state / "gcroots/per-user"}) requireEmptyDirectory(path);
    for (const auto & entry : fs::directory_iterator(state / "profiles"))
        require(entry.path().filename() == "per-user", "unexpected seed profile");
    for (const auto & entry : fs::directory_iterator(state / "gcroots"))
        require(entry.path().filename() == "per-user" || entry.path().filename() == "profiles", "unexpected seed GC root");
    require(readBounded(root / "etc/nix/nix.conf") == seedConfig, "seed config differs from fixed bytes");
}

void requireExecutable(const fs::path & root, const std::string & logical, const Graph & graph, const nix::Store & store)
{
    require(logical.size() <= 4096 && logical.ends_with("/bin/nix"), "invalid selected Nix executable path");
    const auto package = logical.substr(0, logical.size() - std::string_view("/bin/nix").size());
    const auto parsed = canonicalPath(store, package);
    require(graph.roots.contains(parsed), "selected Nix package is not an explicit root");
    const auto file = inspect(root.string() + logical);
    require(S_ISREG(file.st_mode) && (file.st_mode & 0111) != 0, "selected copied Nix executable is not regular executable");
}

void buildSeed(const fs::path & root, const fs::path & graphDirectory,
    std::string_view target, const std::string & executable, int scratch)
{
    require(fs::create_directory(root), "seed root must be freshly created");
    fs::create_directories(root / "nix/var/log/nix");
    {
        nix::LocalStore store(storeParameters(root, false));
        requireLocation(store, root, false);
        const auto inputRegistration = readBounded(graphDirectory / "registration");
        auto graph = readGraph(store, graphDirectory / "inventory.json", inputRegistration);

        for (auto & [path, info] : graph.paths) {
            const auto logical = store.printStorePath(path);
            const auto source = dumpNar(logical, scratch, info.narSize);
            require(source.first == info.narHash && source.second == info.narSize, "source NAR differs from graph");
            nix::FdSource restoreSource(scratch);
            const fs::path copied = root.string() + logical;
            nix::restorePath(copied, restoreSource);
            requireEof(restoreSource);
            const auto restored = dumpNar(copied, scratch, info.narSize);
            require(restored == source, "private restored NAR differs from source");
            info.registrationTime = 1;
        }
        store.registerValidPaths(graph.paths);
        const auto paths = requireMap(store, graph.paths);
        requireExecutable(root, executable, graph, store);

        const auto registration = store.makeValidityRegistration(paths, false, true);
        const auto decoded = decodeRegistration(store, registration);
        require(decoded.size() == graph.paths.size(), "final registration map differs");
        for (const auto & [path, info] : graph.paths) {
            const auto & row = decoded.at(path);
            require(row.narHash == info.narHash && row.narSize == info.narSize && row.references == info.references,
                "final registration differs from original map");
        }

        fs::create_directories(root / controlDirectory);
        fs::create_directories(root / "etc/nix");
        writeFresh(root / controlDirectory / "inventory.json", graph.inventory);
        writeFresh(root / controlDirectory / "registration", registration);
        writeFresh(root / controlDirectory / "target-system", target);
        writeFresh(root / "etc/nix/nix.conf", seedConfig);
    }
    // SQLite and its writable LocalStore owner have been destroyed.
    requireFinalControls(root, true);
}

struct Counters
{
    uint64_t regularBytes = 0;
    uint64_t entries = 0;
    std::set<std::pair<dev_t, ino_t>> inodes;
};

class RegularCounter final : public nix::CreateRegularFileSink
{
    uint64_t expected;
    uint64_t consumed = 0;
    bool executable;
    bool markedExecutable = false;
    bool declaredSize = false;

public:
    explicit RegularCounter(const struct stat & file)
        : expected(uint64_t(file.st_size)), executable((file.st_mode & 0111) != 0) { }

    void isExecutable() override { markedExecutable = true; }

    void preallocateContents(uint64_t size) override
    {
        require(!declaredSize && size == expected, "NAR regular extent differs from original");
        declaredSize = true;
    }

    void operator()(std::string_view bytes) override
    {
        consumed = addBounded(consumed, bytes.size(), expected);
    }

    void finish() const
    {
        require(declaredSize && consumed == expected && markedExecutable == executable,
            "NAR regular contents or executable state differs from original");
    }
};

class TreeCounter final : public nix::FileSystemObjectSink
{
    fs::path root;
    Counters counters;

    std::pair<fs::path, struct stat> observe(const nix::CanonPath & relative, mode_t kind)
    {
        require(relative.rel().size() <= 4096, "relative seed path exceeds bound");
        const auto path = root / std::string(relative.rel());
        const auto file = inspect(path);
        require((file.st_mode & S_IFMT) == kind, "NAR entry kind differs from original");
        counters.entries = addBounded(counters.entries, 1, std::numeric_limits<uint64_t>::max());
        const bool first = counters.inodes.emplace(file.st_dev, file.st_ino).second;
        if (kind == S_IFREG) {
            require(file.st_size >= 0 && file.st_nlink == 1, "unexpected shared regular inode in private seed");
            if (first) counters.regularBytes = addBounded(counters.regularBytes, uint64_t(file.st_size), rootNarLimit);
        }
        return {path, file};
    }

public:
    explicit TreeCounter(fs::path root) : root(std::move(root)) { }

    void createDirectory(const nix::CanonPath & path) override
    {
        observe(path, S_IFDIR);
    }

    void createRegularFile(const nix::CanonPath & path,
        std::function<void(nix::CreateRegularFileSink &)> consume) override
    {
        const auto [original, before] = observe(path, S_IFREG);
        RegularCounter sink(before);
        consume(sink);
        sink.finish();
        requireSameFile(before, inspect(original));
    }

    void createSymlink(const nix::CanonPath & path, const std::string & target) override
    {
        const auto [original, before] = observe(path, S_IFLNK);
        require(fs::read_symlink(original).string() == target, "NAR symlink differs from original");
        requireSameFile(before, inspect(original));
    }

    const Counters & result() const { return counters; }
};

void putInteger(std::array<char, 280> & bytes, size_t offset, size_t width, uint64_t value)
{
    require(width <= 8 && offset + width <= bytes.size()
        && (width == 8 || value < (uint64_t(1) << (width * 8))), "descriptor integer outside width");
    for (size_t index = 0; index < width; ++index)
        bytes[offset + width - index - 1] = char(value >> (index * 8));
}

void putHash(std::array<char, 280> & bytes, size_t offset, const nix::Hash & hash)
{
    require(hash.algo == nix::HashAlgorithm::SHA256 && hash.hashSize == 32 && offset + 32 <= bytes.size()
        && std::any_of(hash.hash, hash.hash + 32, [](uint8_t byte) { return byte != 0; }), "invalid descriptor SHA256");
    std::copy(hash.hash, hash.hash + 32, bytes.begin() + offset);
}

void measureSeed(const fs::path & root, const fs::path & output,
    std::string_view target, const std::string & executable, int scratch)
{
    requireFinalControls(root, false);
    const auto registration = readBounded(root / controlDirectory / "registration");
    const auto config = readBounded(root / "etc/nix/nix.conf");
    require(readBounded(root / controlDirectory / "target-system", 256) == target, "target control mismatch");
    std::string inventory;
    size_t roots = 0;
    size_t paths = 0;
    {
        nix::LocalStore store(storeParameters(root, true));
        requireLocation(store, root, true);
        auto graph = readGraph(store, root / controlDirectory / "inventory.json", registration);
        const auto validPaths = requireMap(store, graph.paths);
        require(store.makeValidityRegistration(validPaths, false, true) == registration,
            "final seed registration is not the upstream canonical stream");
        requireExecutable(root, executable, graph, store);
        for (const auto & [path, info] : graph.paths) {
            const auto actual = dumpNar(root.string() + store.printStorePath(path), scratch, info.narSize);
            require(actual.first == info.narHash && actual.second == info.narSize, "final copied NAR differs from graph");
        }
        inventory = std::move(graph.inventory);
        roots = graph.roots.size();
        paths = graph.paths.size();
    }
    requireFinalControls(root, false);

    const auto rootBefore = inspect(root);
    require(S_ISDIR(rootBefore.st_mode), "final seed root is not a directory");
    const auto content = dumpNar(root, scratch, rootNarLimit, std::string_view(contentDomain, sizeof(contentDomain)));
    nix::FdSource source(scratch);
    TreeCounter counter(root);
    nix::parseDump(counter, source);
    requireEof(source);
    requireSameFile(rootBefore, inspect(root));
    const auto & counts = counter.result();

    std::array<char, 280> descriptor {};
    std::copy_n("AOSNGS01", 8, descriptor.begin());
    putInteger(descriptor, 8, 2, 1);
    std::string targetPreimage(targetDomain, sizeof(targetDomain));
    targetPreimage.append(target);
    putHash(descriptor, 12, nix::hashString(nix::HashAlgorithm::SHA256, targetPreimage));
    putHash(descriptor, 44, nix::hashFile(nix::HashAlgorithm::SHA256, root.string() + executable));
    putHash(descriptor, 76, nix::hashString(nix::HashAlgorithm::SHA256, inventory));
    putHash(descriptor, 108, nix::hashString(nix::HashAlgorithm::SHA256, registration));
    putHash(descriptor, 140, nix::hashFile(nix::HashAlgorithm::SHA256, (root / "nix/var/nix/db/db.sqlite").string()));
    putHash(descriptor, 172, nix::hashString(nix::HashAlgorithm::SHA256, config));
    putHash(descriptor, 204, content.first);
    putInteger(descriptor, 236, 8, counts.regularBytes);
    putInteger(descriptor, 244, 8, counts.inodes.size());
    putInteger(descriptor, 252, 8, counts.entries);
    putInteger(descriptor, 260, 4, roots);
    putInteger(descriptor, 264, 4, paths);
    putInteger(descriptor, 268, 4, rootBefore.st_uid);
    putInteger(descriptor, 272, 4, rootBefore.st_gid);
    putInteger(descriptor, 276, 2, rootBefore.st_mode & 07777);

    Json measured = {{"schema", "aos.nix-generation-seed.measurement/v1"},
        {"target", std::string(target)}, {"rootCount", roots}, {"pathCount", paths},
        {"uniqueRegularBytes", counts.regularBytes}, {"distinctInodes", counts.inodes.size()},
        {"entries", counts.entries}, {"rootNarBytes", content.second}};
    writeFresh(output / "inventory.json", inventory);
    writeFresh(output / "registration", registration);
    writeFresh(output / "nix.conf", config);
    writeFresh(output / "measurement.json", measured.dump());
    // The success descriptor is last and never becomes part of the measured root.
    writeFresh(output / "seed280", std::string_view(descriptor.data(), descriptor.size()));
}

} // namespace

int main(int argc, char ** argv)
{
    try {
        require(argc == 6, "usage: seed-builder build ROOT GRAPH TARGET NIX_PATH | measure ROOT OUT TARGET NIX_PATH");
        const std::string action = argv[1];
        require(action == "build" || action == "measure", "unsupported seed action");
        const fs::path root = argv[2];
        const fs::path other = argv[3];
        require(root.is_absolute() && root.lexically_normal() == root
            && root.string().size() <= 4096 && other.is_absolute(), "invalid build-only root path");
        const std::string target = argv[4];
        requireTarget(target);
        configureNix();

        const auto scratchDirectory = nix::createTempDir("", "aos-nix-seed", true, true, 0700);
        nix::AutoDelete scratchCleanup(scratchDirectory);
        const auto scratchPath = fs::path(scratchDirectory) / "nar";
        nix::AutoCloseFD scratch(open(scratchPath.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (!scratch) throw nix::SysError("create seed NAR scratch");
        if (action == "build") buildSeed(root, other, target, argv[5], scratch.get());
        else measureSeed(root, other, target, argv[5], scratch.get());
        return 0;
    } catch (const std::exception & error) {
        std::cerr << "Nix seed DATA preparation failed: " << error.what() << '\n';
        return 1;
    }
}
