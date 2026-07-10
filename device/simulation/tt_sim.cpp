#include <stdint.h>

#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <poll.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr uint8_t CMD_WRITE_L1 = 0x01;
constexpr uint8_t CMD_WRITE_REG = 0x02;
constexpr uint8_t CMD_READ_L1 = 0x03;
constexpr uint8_t CMD_WRITE_DRAM = 0x09;
constexpr uint8_t CMD_READ_DRAM = 0x0A;
constexpr uint8_t CMD_WRITE_L1_MCAST = 0x0B;

constexpr uint8_t CMD_READ_PCIE = 0x20;
constexpr uint8_t CMD_WRITE_PCIE = 0x21;

constexpr uint8_t RESP_OK = 0x00;

constexpr uint32_t kWormholeDebugSoftResetAddr = 0xFFB121B0;
constexpr uint32_t kQuasarSoftResetAddr = 0x030179B0;
constexpr uint32_t kQuasarLocalSoftResetAddr0 = 0x018000B8;
constexpr uint32_t kQuasarLocalSoftResetAddr1 = 0x018100B8;
constexpr uint32_t kQuasarLocalSoftResetAddr2 = 0x018200B8;
constexpr uint32_t kQuasarLocalSoftResetAddr3 = 0x018300B8;
constexpr uint64_t kMaxDebugAddress = 0xFFFFFFFFull;
constexpr uint64_t kTensixGoMsgAddr = 0x5C;
constexpr uint64_t kTensixGoMsgSignalAddr = kTensixGoMsgAddr + 3;

constexpr const char* kNeoSocketEnvVar = "TT_NEO_DBG_SOCKET";
constexpr const char* kSocketEnvVar = "TT_WORMHOLE_DBG_SOCKET";
constexpr const char* kDefaultSocketPath = "/tmp/tt_sim.sock";
constexpr const char* kPcieSocketEnvVar = "TT_WORMHOLE_PCIE_SOCKET";
constexpr const char* kDefaultPcieSocketPath = "/tmp/tt_sim_pcie.sock";

std::mutex g_client_mutex;
int g_client_fd = -1;
std::atomic<bool> g_pcie_service_stop{false};
std::thread g_pcie_service_thread;
std::unordered_map<uint64_t, uint32_t> g_soft_reset_shadow;
std::unordered_map<uint64_t, uint8_t> g_pci_mem_shadow;
std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint8_t>> g_special_tile_l1_shadow;
void (*g_pci_dma_mem_rd_cb)(uint64_t paddr, void* p, uint32_t size) = nullptr;
void (*g_pci_dma_mem_wr_cb)(uint64_t paddr, const void* p, uint32_t size) = nullptr;
enum class SimDebugLevel { NONE = 0, INFO = 1, DEBUG = 2 };
SimDebugLevel g_debug_level = SimDebugLevel::NONE;
int g_pcie_service_listen_fd = -1;
constexpr uint8_t kDramTileCoords[][2] = {
    {2, 7}, {3, 7},
};

uint64_t tile_key(uint32_t x, uint32_t y) {
    return (static_cast<uint64_t>(x) << 32) | y;
}

std::string dbg_socket_path() {
    const char* neo_env = std::getenv(kNeoSocketEnvVar);
    if (neo_env) {
        return neo_env;
    }
    const char* env = std::getenv(kSocketEnvVar);
    return env ? env : kDefaultSocketPath;
}

std::string pcie_socket_path() {
    const char* env = std::getenv(kPcieSocketEnvVar);
    return env ? env : kDefaultPcieSocketPath;
}

uint64_t normalize_pcie_dma_offset(uint64_t paddr) {
    constexpr uint64_t kWormholePcieBase = 0x800000000ULL;
    return paddr >= kWormholePcieBase ? (paddr - kWormholePcieBase) : paddr;
}

bool is_dram_tile(uint32_t x, uint32_t y) {
    for (const auto& coord : kDramTileCoords) {
        if (coord[0] == x && coord[1] == y) {
            return true;
        }
    }
    return false;
}

bool is_eth_border_tile(uint32_t x, uint32_t y) {
    return x >= 18 && x <= 25 && y >= 16 && y <= 17;
}

bool is_arc_tile(uint32_t x, uint32_t y) {
    return (x == 0 && y == 10) || (x == 8 && y == 0);
}

bool is_pcie_tile(uint32_t x, uint32_t y) {
    return (x == 0 && y == 3) || (x == 2 && y == 0) || (x == 11 && y == 0);
}

bool is_locally_shadowed_tile(uint32_t x, uint32_t y) {
    return is_eth_border_tile(x, y) || is_arc_tile(x, y) || is_pcie_tile(x, y);
}

void shadow_write_tile_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size) {
    auto& tile_shadow = g_special_tile_l1_shadow[tile_key(x, y)];
    const auto* in = static_cast<const uint8_t*>(p);
    for (uint32_t i = 0; i < size; ++i) {
        tile_shadow[addr + i] = in[i];
    }
}

void shadow_read_tile_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size) {
    auto* out = static_cast<uint8_t*>(p);
    std::memset(out, 0, size);

    auto tile_it = g_special_tile_l1_shadow.find(tile_key(x, y));
    if (tile_it == g_special_tile_l1_shadow.end()) {
        return;
    }

    const auto& tile_shadow = tile_it->second;
    for (uint32_t i = 0; i < size; ++i) {
        auto it = tile_shadow.find(addr + i);
        if (it != tile_shadow.end()) {
            out[i] = it->second;
        }
    }
}

void shadow_mark_init_done_for_tile(uint32_t x, uint32_t y) {
    auto& tile_shadow = g_special_tile_l1_shadow[tile_key(x, y)];
    tile_shadow[kTensixGoMsgAddr + 0] = 0x00;
    tile_shadow[kTensixGoMsgAddr + 1] = 0x00;
    tile_shadow[kTensixGoMsgAddr + 2] = 0x00;
    tile_shadow[kTensixGoMsgSignalAddr] = 0x00;
}

bool is_soft_reset_addr(uint64_t addr) {
    return addr == static_cast<uint64_t>(kWormholeDebugSoftResetAddr) ||
           addr == static_cast<uint64_t>(kQuasarSoftResetAddr) ||
           addr == static_cast<uint64_t>(kQuasarLocalSoftResetAddr0) ||
           addr == static_cast<uint64_t>(kQuasarLocalSoftResetAddr1) ||
           addr == static_cast<uint64_t>(kQuasarLocalSoftResetAddr2) ||
           addr == static_cast<uint64_t>(kQuasarLocalSoftResetAddr3);
}

bool is_debug_address_supported(uint64_t addr) {
    return addr <= kMaxDebugAddress;
}

void init_debug() {
    if (g_debug_level != SimDebugLevel::NONE) {
        return;
    }
    const char* env = std::getenv("TT_SIM_DEBUG");
    if (!env || env[0] == '\0') {
        return;
    }
    if (std::strcmp(env, "debug") == 0) {
        g_debug_level = SimDebugLevel::DEBUG;
    } else {
        g_debug_level = SimDebugLevel::INFO;
    }
}

void dbg_info(const char* fmt, ...) {
    if (static_cast<int>(g_debug_level) < static_cast<int>(SimDebugLevel::INFO)) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    std::fputs("[tt_sim] ", stderr);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    va_end(args);
}

void dbg_debug(const char* fmt, ...) {
    if (static_cast<int>(g_debug_level) < static_cast<int>(SimDebugLevel::DEBUG)) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    std::fputs("[tt_sim] ", stderr);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    va_end(args);
}

std::string dump_bytes(const uint8_t* data, uint32_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    uint32_t limit = size > 64 ? 64 : size;
    for (uint32_t i = 0; i < limit; ++i) {
        if (i != 0) {
            out << ' ';
        }
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

void close_client_locked() {
    if (g_client_fd >= 0) {
        dbg_info("close client fd=%d", g_client_fd);
        close(g_client_fd);
        g_client_fd = -1;
    }
}

bool connect_client_locked() {
    if (g_client_fd >= 0) {
        return true;
    }

    std::string path = dbg_socket_path();
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        dbg_info("socket() failed: %s", std::strerror(errno));
        return false;
    }

    sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        dbg_info("socket path too long: %s", path.c_str());
        close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        dbg_info("connect(%s) failed: %s", path.c_str(), std::strerror(errno));
        close(fd);
        return false;
    }

    g_client_fd = fd;
    dbg_info("connected to %s fd=%d", path.c_str(), g_client_fd);
    return true;
}

bool write_exact(int fd, const void* buf, size_t len) {
    const uint8_t* ptr = static_cast<const uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t ret = ::write(fd, ptr, remaining);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            dbg_info("write_exact failed: %s", std::strerror(errno));
            return false;
        }
        if (ret == 0) {
            dbg_info("write_exact failed: wrote 0 bytes");
            return false;
        }
        ptr += ret;
        remaining -= static_cast<size_t>(ret);
    }
    return true;
}

bool read_exact(int fd, void* buf, size_t len) {
    uint8_t* ptr = static_cast<uint8_t*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t ret = ::read(fd, ptr, remaining);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            dbg_info("read_exact failed: %s", std::strerror(errno));
            return false;
        }
        if (ret == 0) {
            dbg_info("read_exact failed: read 0 bytes");
            return false;
        }
        ptr += ret;
        remaining -= static_cast<size_t>(ret);
    }
    return true;
}

void encode_u32_le(uint8_t* dst, uint32_t value) {
    dst[0] = static_cast<uint8_t>(value & 0xFFu);
    dst[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
    dst[2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
    dst[3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
}

uint32_t decode_u32_le(const uint8_t* src) {
    return static_cast<uint32_t>(src[0]) |
           (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[3]) << 24);
}

uint64_t decode_u64_le(const uint8_t* src) {
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        value |= static_cast<uint64_t>(src[i]) << (8 * i);
    }
    return value;
}

void fill_cmd_header(uint8_t* header, uint8_t cmd, uint8_t tile_x, uint8_t tile_y, uint32_t addr, uint32_t size) {
    header[0] = cmd;
    header[1] = tile_x;
    header[2] = tile_y;
    encode_u32_le(header + 3, addr);
    encode_u32_le(header + 7, size);
}

void send_pcie_status(int fd, uint8_t status) {
    (void)write_exact(fd, &status, 1);
}

void run_pcie_service() {
    std::string path = pcie_socket_path();

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        dbg_info("pcie service socket() failed: %s", std::strerror(errno));
        return;
    }

    unlink(path.c_str());

    sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        dbg_info("pcie service path too long: %s", path.c_str());
        close(listen_fd);
        return;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        dbg_info("pcie service bind(%s) failed: %s", path.c_str(), std::strerror(errno));
        close(listen_fd);
        return;
    }
    if (listen(listen_fd, 1) != 0) {
        dbg_info("pcie service listen(%s) failed: %s", path.c_str(), std::strerror(errno));
        close(listen_fd);
        unlink(path.c_str());
        return;
    }

    g_pcie_service_listen_fd = listen_fd;
    dbg_info("pcie service listening on %s", path.c_str());

    while (!g_pcie_service_stop.load(std::memory_order_acquire)) {
        struct pollfd pfd = {listen_fd, POLLIN, 0};
        if (poll(&pfd, 1, 200) <= 0) {
            continue;
        }

        int fd = accept(listen_fd, nullptr, nullptr);
        if (fd < 0) {
            dbg_info("pcie service accept failed: %s", std::strerror(errno));
            continue;
        }
        dbg_info("pcie service accepted client fd=%d", fd);

        while (!g_pcie_service_stop.load(std::memory_order_acquire)) {
            uint8_t header[13];
            if (!read_exact(fd, header, sizeof(header))) {
                break;
            }

            uint8_t cmd = header[0];
            uint64_t raw_paddr = decode_u64_le(header + 1);
            uint64_t paddr = normalize_pcie_dma_offset(raw_paddr);
            uint32_t size = decode_u32_le(header + 9);
            dbg_debug("pcie service cmd=0x%02x raw_paddr=0x%llx paddr=0x%llx size=%u",
                    cmd,
                    static_cast<unsigned long long>(raw_paddr),
                    static_cast<unsigned long long>(paddr),
                    size);

            if (cmd == CMD_READ_PCIE) {
                std::vector<uint8_t> payload(size, 0);
                {
                    std::lock_guard<std::mutex> lock(g_client_mutex);
                    if (!g_pci_dma_mem_rd_cb) {
                        dbg_info("pcie read rejected: callback not registered paddr=0x%llx size=%u",
                                static_cast<unsigned long long>(paddr), size);
                        send_pcie_status(fd, 0x01);
                        continue;
                    }
                    dbg_debug("pcie read callback begin paddr=0x%llx size=%u",
                            static_cast<unsigned long long>(paddr), size);
                    g_pci_dma_mem_rd_cb(paddr, payload.data(), size);
                    dbg_debug("pcie read callback end paddr=0x%llx size=%u data=%s",
                            static_cast<unsigned long long>(paddr),
                            size,
                            dump_bytes(payload.data(), size).c_str());
                }
                if (!write_exact(fd, "\x00", 1) ||
                    (size > 0 && !write_exact(fd, payload.data(), size))) {
                    dbg_info("pcie read response write failed paddr=0x%llx size=%u",
                            static_cast<unsigned long long>(paddr), size);
                    break;
                }
                dbg_info("pcie read response sent paddr=0x%llx size=%u",
                        static_cast<unsigned long long>(paddr), size);
                continue;
            }

            if (cmd == CMD_WRITE_PCIE) {
                std::vector<uint8_t> payload(size, 0);
                if (size > 0 && !read_exact(fd, payload.data(), size)) {
                    break;
                }
                {
                    std::lock_guard<std::mutex> lock(g_client_mutex);
                    if (!g_pci_dma_mem_wr_cb) {
                        dbg_info("pcie write rejected: callback not registered paddr=0x%llx size=%u",
                                static_cast<unsigned long long>(paddr), size);
                        send_pcie_status(fd, 0x01);
                        continue;
                    }
                    dbg_info("pcie write callback begin paddr=0x%llx size=%u data=%s",
                            static_cast<unsigned long long>(paddr),
                            size,
                            dump_bytes(payload.data(), size).c_str());
                    g_pci_dma_mem_wr_cb(paddr, payload.data(), size);
                    dbg_info("pcie write callback end paddr=0x%llx size=%u",
                            static_cast<unsigned long long>(paddr), size);
                }
                send_pcie_status(fd, 0x00);
                dbg_info("pcie write response sent paddr=0x%llx size=%u",
                        static_cast<unsigned long long>(paddr), size);
                continue;
            }

            send_pcie_status(fd, 0x01);
        }

        close(fd);
    }

    close(listen_fd);
    unlink(path.c_str());
    g_pcie_service_listen_fd = -1;
}

void start_pcie_service_locked() {
    if (g_pcie_service_thread.joinable()) {
        return;
    }
    g_pcie_service_stop.store(false, std::memory_order_release);
    g_pcie_service_thread = std::thread(run_pcie_service);
}

void stop_pcie_service_locked() {
    g_pcie_service_stop.store(true, std::memory_order_release);
    if (g_pcie_service_listen_fd >= 0) {
        close(g_pcie_service_listen_fd);
        g_pcie_service_listen_fd = -1;
    }
    if (g_pcie_service_thread.joinable()) {
        g_pcie_service_thread.join();
    }
}

bool send_cmd_locked(
    uint8_t cmd,
    uint8_t tile_x,
    uint8_t tile_y,
    uint32_t addr,
    uint32_t size,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_status) {
    if (!connect_client_locked()) {
        dbg_info("send_cmd: connect failed cmd=0x%02x tile=(%u,%u)", cmd, tile_x, tile_y);
        return false;
    }

    uint8_t header[11];
    fill_cmd_header(header, cmd, tile_x, tile_y, addr, size);

    if (!write_exact(g_client_fd, header, sizeof(header))) {
        close_client_locked();
        return false;
    }

    if (payload_len > 0 && !write_exact(g_client_fd, payload, payload_len)) {
        close_client_locked();
        return false;
    }

    uint8_t status = 0;
    if (!read_exact(g_client_fd, &status, 1)) {
        close_client_locked();
        return false;
    }

    if (out_status) {
        *out_status = status;
    }
    dbg_debug(
        "send_cmd: cmd=0x%02x tile=(%u,%u) addr=0x%08x size=%u status=0x%02x",
        cmd,
        tile_x,
        tile_y,
        addr,
        size,
        status);
    return true;
}

bool send_cmd_read_locked(
    uint8_t cmd,
    uint8_t tile_x,
    uint8_t tile_y,
    uint32_t addr,
    uint32_t size,
    uint8_t* out_data) {
    uint8_t status = 0;
    if (!send_cmd_locked(cmd, tile_x, tile_y, addr, size, nullptr, 0, &status)) {
        return false;
    }

    if (status != RESP_OK) {
        return false;
    }

    if (size > 0 && !read_exact(g_client_fd, out_data, size)) {
        close_client_locked();
        return false;
    }

    return true;
}

bool send_cmd_mcast_write_locked(
    uint8_t src_x,
    uint8_t src_y,
    uint8_t start_x,
    uint8_t start_y,
    uint8_t end_x,
    uint8_t end_y,
    uint8_t noc_index,
    uint32_t noc_ctrl,
    uint32_t addr,
    uint32_t size,
    const uint8_t* payload,
    size_t payload_len) {
    if (!connect_client_locked()) {
        dbg_info("mcast send_cmd: connect failed src=(%u,%u)", src_x, src_y);
        return false;
    }

    uint8_t header[11];
    fill_cmd_header(header, CMD_WRITE_L1_MCAST, src_x, src_y, addr, size);

    uint8_t meta[9];
    meta[0] = start_x;
    meta[1] = start_y;
    meta[2] = end_x;
    meta[3] = end_y;
    meta[4] = noc_index;
    encode_u32_le(meta + 5, noc_ctrl);

    if (!write_exact(g_client_fd, header, sizeof(header)) ||
        !write_exact(g_client_fd, meta, sizeof(meta)) ||
        (payload_len > 0 && !write_exact(g_client_fd, payload, payload_len))) {
        close_client_locked();
        return false;
    }

    uint8_t status = 0;
    if (!read_exact(g_client_fd, &status, 1)) {
        close_client_locked();
        return false;
    }

    dbg_debug(
        "mcast send_cmd: src=(%u,%u) rect=(%u,%u)->(%u,%u) noc=%u addr=0x%08x size=%u status=0x%02x",
        src_x,
        src_y,
        start_x,
        start_y,
        end_x,
        end_y,
        noc_index,
        addr,
        size,
        status);
    return status == RESP_OK;
}

bool read_debug_payload_locked(
    const char* log_prefix,
    uint8_t cmd,
    uint32_t x,
    uint32_t y,
    uint64_t addr,
    void* p,
    uint32_t size,
    bool zero_fill_on_failure,
    bool log_dump_on_success) {
    if (!is_debug_address_supported(addr)) {
        if (zero_fill_on_failure) {
            std::memset(p, 0, size);
        }
        return false;
    }

    bool ok = send_cmd_read_locked(
        cmd,
        static_cast<uint8_t>(x),
        static_cast<uint8_t>(y),
        static_cast<uint32_t>(addr),
        size,
        static_cast<uint8_t*>(p));

    if (!ok) {
        if (zero_fill_on_failure) {
            std::memset(p, 0, size);
        }
        dbg_info("%s: failed%s", log_prefix, zero_fill_on_failure ? ", zero-filled" : "");
        return false;
    }

    if (log_dump_on_success) {
        dbg_debug("%s: ok size=%u dump=%s", log_prefix, size, dump_bytes(static_cast<const uint8_t*>(p), size).c_str());
    }
    return true;
}

bool write_debug_payload_locked(
    const char* log_prefix,
    uint8_t cmd,
    uint32_t x,
    uint32_t y,
    uint64_t addr,
    const void* p,
    uint32_t size) {
    if (!is_debug_address_supported(addr)) {
        return false;
    }

    uint8_t status = 0;
    bool ok = send_cmd_locked(
        cmd,
        static_cast<uint8_t>(x),
        static_cast<uint8_t>(y),
        static_cast<uint32_t>(addr),
        size,
        static_cast<const uint8_t*>(p),
        size,
        &status);
    if (!ok || status != RESP_OK) {
        dbg_info("%s: failed status=0x%02x", log_prefix, status);
        return false;
    }
    dbg_info("%s: submitted", log_prefix);
    return true;
}

bool write_soft_reset_locked(uint32_t x, uint32_t y, uint64_t addr, const void* p) {
    uint32_t value = 0;
    std::memcpy(&value, p, sizeof(value));
    uint8_t payload[sizeof(value)];
    encode_u32_le(payload, value);

    if (is_locally_shadowed_tile(x, y)) {
        g_soft_reset_shadow[tile_key(x, y)] = value;
        if (value == 0) {
            shadow_mark_init_done_for_tile(x, y);
        }
        dbg_info("wr: soft reset locally acknowledged for special tile=(%u,%u) value=0x%08x", x, y, value);
        return true;
    }

    uint8_t status = 0;
    bool ok = send_cmd_locked(
        CMD_WRITE_REG,
        static_cast<uint8_t>(x),
        static_cast<uint8_t>(y),
        static_cast<uint32_t>(addr),
        sizeof(value),
        payload,
        sizeof(payload),
        &status);
    if (ok && status == RESP_OK) {
        g_soft_reset_shadow[tile_key(x, y)] = value;
        dbg_info("wr: soft reset updated value=0x%08x", value);
        return true;
    }
    return false;
}

}  // namespace

extern "C" {
void libttsim_dram_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size);
void libttsim_dram_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size);
void libttsim_tile_noc_mcast_wr_bytes(
    uint32_t src_x,
    uint32_t src_y,
    uint32_t start_x,
    uint32_t start_y,
    uint32_t end_x,
    uint32_t end_y,
    uint32_t noc_index,
    uint32_t noc_ctrl,
    uint64_t addr,
    const void* p,
    uint32_t size);

void libttsim_init() {
    std::lock_guard<std::mutex> lock(g_client_mutex);
    init_debug();
    g_soft_reset_shadow.clear();
    g_pci_mem_shadow.clear();
    g_special_tile_l1_shadow.clear();
    connect_client_locked();
}

void libttsim_exit() {
    std::lock_guard<std::mutex> lock(g_client_mutex);
    close_client_locked();
    stop_pcie_service_locked();
    g_soft_reset_shadow.clear();
    g_pci_mem_shadow.clear();
    g_special_tile_l1_shadow.clear();
    g_pci_dma_mem_rd_cb = nullptr;
    g_pci_dma_mem_wr_cb = nullptr;
}

uint32_t libttsim_pci_config_rd32(uint32_t bus_device_function, uint32_t offset) {
    (void)bus_device_function;
    if (offset == 0) {
        constexpr uint32_t kTenstorrentVendorId = 0x1E52;
        constexpr uint32_t kQuasarDeviceId = 0xfeed;
        return (kQuasarDeviceId << 16) | kTenstorrentVendorId;
    }
    return 0;
}

void libttsim_set_pci_dma_mem_callbacks(
    void (*pfn_pci_dma_mem_rd_bytes)(uint64_t paddr, void* p, uint32_t size),
    void (*pfn_pci_dma_mem_wr_bytes)(uint64_t paddr, const void* p, uint32_t size)) {
    std::lock_guard<std::mutex> lock(g_client_mutex);
    g_pci_dma_mem_rd_cb = pfn_pci_dma_mem_rd_bytes;
    g_pci_dma_mem_wr_cb = pfn_pci_dma_mem_wr_bytes;
    dbg_info("register pcie dma callbacks rd=%p wr=%p",
            reinterpret_cast<void*>(g_pci_dma_mem_rd_cb),
            reinterpret_cast<void*>(g_pci_dma_mem_wr_cb));
    if (g_pci_dma_mem_rd_cb != nullptr && g_pci_dma_mem_wr_cb != nullptr) {
        dbg_info("starting pcie service after callback registration");
        start_pcie_service_locked();
    }
}

void libttsim_pci_mem_rd_bytes(uint64_t paddr, void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_client_mutex);
    auto* out = static_cast<uint8_t*>(p);
    for (uint32_t i = 0; i < size; ++i) {
        const uint64_t addr = paddr + i;
        const auto it = g_pci_mem_shadow.find(addr);
        out[i] = (it == g_pci_mem_shadow.end()) ? 0 : it->second;
    }
}

void libttsim_pci_mem_wr_bytes(uint64_t paddr, const void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_client_mutex);
    const auto* in = static_cast<const uint8_t*>(p);
    for (uint32_t i = 0; i < size; ++i) {
        g_pci_mem_shadow[paddr + i] = in[i];
    }
}

void libttsim_tile_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    if (is_dram_tile(x, y)) {
        libttsim_dram_rd_bytes(x, y, addr, p, size);
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_debug("rd: tile=(%u,%u) addr=0x%llx size=%u", x, y, static_cast<unsigned long long>(addr), size);

    if (is_locally_shadowed_tile(x, y)) {
        shadow_read_tile_bytes(x, y, addr, p, size);
        dbg_debug("rd: satisfied locally for special tile=(%u,%u)", x, y);
        return;
    }

    if (is_soft_reset_addr(addr) && size >= sizeof(uint32_t)) {
        uint32_t value = 0;
        auto it = g_soft_reset_shadow.find(tile_key(x, y));
        if (it != g_soft_reset_shadow.end()) {
            value = it->second;
        }
        std::memset(p, 0, size);
        encode_u32_le(static_cast<uint8_t*>(p), value);
        return;
    }

    read_debug_payload_locked("rd", CMD_READ_L1, x, y, addr, p, size, true, false);
}

void libttsim_tile_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    if (is_dram_tile(x, y)) {
        libttsim_dram_wr_bytes(x, y, addr, p, size);
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_info("wr: tile=(%u,%u) addr=0x%llx size=%u", x, y, static_cast<unsigned long long>(addr), size);

    if (is_soft_reset_addr(addr) && size >= sizeof(uint32_t)) {
        uint32_t value = 0;
        std::memcpy(&value, p, sizeof(value));
        dbg_info("wr: write soft reset value 0x%x", value);
        write_soft_reset_locked(x, y, addr, p);
        return;
    }

    if (is_locally_shadowed_tile(x, y)) {
        shadow_write_tile_bytes(x, y, addr, p, size);
        dbg_info("wr: stored locally for special tile=(%u,%u)", x, y);
        return;
    }

    write_debug_payload_locked("wr", CMD_WRITE_L1, x, y, addr, p, size);
}

void libttsim_tile_noc_mcast_wr_bytes(
    uint32_t src_x,
    uint32_t src_y,
    uint32_t start_x,
    uint32_t start_y,
    uint32_t end_x,
    uint32_t end_y,
    uint32_t noc_index,
    uint32_t noc_ctrl,
    uint64_t addr,
    const void* p,
    uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_info(
        "mcast wr: src=(%u,%u) rect=(%u,%u)->(%u,%u) noc=%u ctrl=0x%x addr=0x%llx size=%u",
        src_x,
        src_y,
        start_x,
        start_y,
        end_x,
        end_y,
        noc_index,
        noc_ctrl,
        static_cast<unsigned long long>(addr),
        size);

    if (!is_debug_address_supported(addr)) {
        return;
    }

    send_cmd_mcast_write_locked(
        static_cast<uint8_t>(src_x),
        static_cast<uint8_t>(src_y),
        static_cast<uint8_t>(start_x),
        static_cast<uint8_t>(start_y),
        static_cast<uint8_t>(end_x),
        static_cast<uint8_t>(end_y),
        static_cast<uint8_t>(noc_index),
        noc_ctrl,
        static_cast<uint32_t>(addr),
        size,
        static_cast<const uint8_t*>(p),
        size);
}

void libttsim_dram_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_debug("dram rd: tile=(%u,%u) addr=0x%llx size=%u", x, y, static_cast<unsigned long long>(addr), size);
    read_debug_payload_locked("dram rd", CMD_READ_DRAM, x, y, addr, p, size, true, true);
}

void libttsim_dram_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_info("dram wr: tile=(%u,%u) addr=0x%llx size=%u", x, y, static_cast<unsigned long long>(addr), size);
    write_debug_payload_locked("dram wr", CMD_WRITE_DRAM, x, y, addr, p, size);
}

void libttsim_clock(uint32_t n_clocks) {
    (void)n_clocks;
}

}  // extern "C"
