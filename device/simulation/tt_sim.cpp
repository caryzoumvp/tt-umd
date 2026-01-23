#include <stdint.h>

#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr uint8_t CMD_WRITE_L1 = 0x01;
constexpr uint8_t CMD_WRITE_REG = 0x02;
constexpr uint8_t CMD_READ_L1 = 0x03;
constexpr uint8_t CMD_WRITE_LOCALRAM = 0x07;
constexpr uint8_t CMD_READ_LOCALRAM = 0x08;
constexpr uint8_t CMD_WRITE_DRAM = 0x09;
constexpr uint8_t CMD_READ_DRAM = 0x0A;

constexpr uint8_t RESP_OK = 0x00;

constexpr uint32_t kDebugSoftResetAddr = 0xFFB121B0;

constexpr const char* kSocketEnvVar = "TT_WORMHOLE_DBG_SOCKET";
constexpr const char* kDefaultSocketPath = "/tmp/tt_sim.sock";

std::mutex g_client_mutex;
int g_client_fd = -1;
std::unordered_map<uint64_t, uint32_t> g_soft_reset_shadow;
bool g_debug_enabled = false;
constexpr uint8_t kDramTileCoords[][2] = {
    {0, 0}, {0, 1}, {0, 11},
    {0, 5}, {0, 6}, {0, 7},
    {5, 0}, {5, 1}, {5, 11},
    {5, 2}, {5, 9}, {5, 10},
    {5, 3}, {5, 4}, {5, 8},
    {5, 5}, {5, 6}, {5, 7},
};

uint64_t tile_key(uint32_t x, uint32_t y) {
    return (static_cast<uint64_t>(x) << 32) | y;
}

std::string dbg_socket_path() {
    const char* env = std::getenv(kSocketEnvVar);
    return env ? env : kDefaultSocketPath;
}

bool is_dram_tile(uint32_t x, uint32_t y) {
    for (const auto &coord : kDramTileCoords) {
        if (coord[0] == x && coord[1] == y) {
            return true;
        }
    }
    return false;
}

void init_debug() {
    if (g_debug_enabled) {
        return;
    }
    const char* env = std::getenv("TT_SIM_DEBUG");
    g_debug_enabled = env && env[0] != '\0';
}

void dbg_log(const char* fmt, ...) {
    if (!g_debug_enabled) {
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
        dbg_log("close client fd=%d", g_client_fd);
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
        dbg_log("socket() failed: %s", std::strerror(errno));
        return false;
    }

    sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        dbg_log("socket path too long: %s", path.c_str());
        close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        dbg_log("connect(%s) failed: %s", path.c_str(), std::strerror(errno));
        close(fd);
        return false;
    }

    g_client_fd = fd;
    dbg_log("connected to %s fd=%d", path.c_str(), g_client_fd);
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
            dbg_log("write_exact failed: %s", std::strerror(errno));
            return false;
        }
        if (ret == 0) {
            dbg_log("write_exact failed: wrote 0 bytes");
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
            dbg_log("read_exact failed: %s", std::strerror(errno));
            return false;
        }
        if (ret == 0) {
            dbg_log("read_exact failed: read 0 bytes");
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
        dbg_log("send_cmd: connect failed cmd=0x%02x tile=(%u,%u)", cmd, tile_x, tile_y);
        return false;
    }

    uint8_t header[11];
    header[0] = cmd;
    header[1] = tile_x;
    header[2] = tile_y;
    encode_u32_le(header + 3, addr);
    encode_u32_le(header + 7, size);

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
    dbg_log("send_cmd: cmd=0x%02x tile=(%u,%u) addr=0x%08x size=%u status=0x%02x",
            cmd, tile_x, tile_y, addr, size, status);
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

bool is_localram_addr(uint32_t addr) {
    uint32_t bank = (addr >> 28) & 0xFu;
    return bank >= 1 && bank <= 4;
}

bool is_soft_reset_addr(uint64_t addr) {
    return addr == static_cast<uint64_t>(kDebugSoftResetAddr);
}

}  // namespace

extern "C" {
void libttsim_dram_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size);
void libttsim_dram_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size);

void libttsim_init() {
    std::lock_guard<std::mutex> lock(g_client_mutex);
    init_debug();
    g_soft_reset_shadow.clear();
    connect_client_locked();
}

void libttsim_exit() {
    std::lock_guard<std::mutex> lock(g_client_mutex);
    close_client_locked();
    g_soft_reset_shadow.clear();
}

uint32_t libttsim_pci_config_rd32(uint32_t bus_device_function, uint32_t offset) {
    (void)bus_device_function;
    (void)offset;
    return 0x401E1E52;
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
    dbg_log("rd: tile=(%u,%u) addr=0x%llx size=%u", x, y,
            static_cast<unsigned long long>(addr), size);

    if (is_soft_reset_addr(addr) && size == sizeof(uint32_t)) {
        uint32_t value = 0;
        auto it = g_soft_reset_shadow.find(tile_key(x, y));
        if (it != g_soft_reset_shadow.end()) {
            value = it->second;
        }
        encode_u32_le(static_cast<uint8_t*>(p), value);
        return;
    }

    if (addr > 0xFFFFFFFFull) {
        std::memset(p, 0, size);
        return;
    }

    uint32_t addr32 = static_cast<uint32_t>(addr);
    uint8_t* out = static_cast<uint8_t*>(p);
    uint8_t tile_x = static_cast<uint8_t>(x);
    uint8_t tile_y = static_cast<uint8_t>(y);
    bool ok = false;
    if (is_localram_addr(addr32)) {
        ok = send_cmd_read_locked(CMD_READ_LOCALRAM, tile_x, tile_y, addr32, size, out);
    } else {
        ok = send_cmd_read_locked(CMD_READ_L1, tile_x, tile_y, addr32, size, out);
    }

    if (!ok) {
        std::memset(p, 0, size);
        dbg_log("rd: failed, zero-filled");
    }
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
    dbg_log("wr: tile=(%u,%u) addr=0x%llx size=%u", x, y,
            static_cast<unsigned long long>(addr), size);

    if (is_soft_reset_addr(addr) && size == sizeof(uint32_t)) {
        uint32_t value = 0;
        std::memcpy(&value, p, sizeof(value));
        uint8_t payload[sizeof(value)];
        encode_u32_le(payload, value);

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
            dbg_log("wr: soft reset updated value=0x%08x", value);
        }
        return;
    }

    if (addr > 0xFFFFFFFFull) {
        return;
    }

    uint32_t addr32 = static_cast<uint32_t>(addr);
    const uint8_t* in = static_cast<const uint8_t*>(p);
    uint8_t tile_x = static_cast<uint8_t>(x);
    uint8_t tile_y = static_cast<uint8_t>(y);

    if (is_localram_addr(addr32)) {
        send_cmd_locked(CMD_WRITE_LOCALRAM, tile_x, tile_y, addr32, size, in, size, nullptr);
    } else {
        send_cmd_locked(CMD_WRITE_L1, tile_x, tile_y, addr32, size, in, size, nullptr);
    }
}

void libttsim_dram_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_log("dram rd: tile=(%u,%u) addr=0x%llx size=%u", x, y,
            static_cast<unsigned long long>(addr), size);

    if (addr > 0xFFFFFFFFull) {
        std::memset(p, 0, size);
        return;
    }

    uint32_t addr32 = static_cast<uint32_t>(addr);
    uint8_t* out = static_cast<uint8_t*>(p);
    uint8_t tile_x = static_cast<uint8_t>(x);
    uint8_t tile_y = static_cast<uint8_t>(y);
    bool ok = send_cmd_read_locked(CMD_READ_DRAM, tile_x, tile_y, addr32, size, out);

    if (!ok) {
        std::memset(p, 0, size);
        dbg_log("dram rd: failed, zero-filled");
        return;
    }

    dbg_log("dram rd: ok size=%u dump=%s", size, dump_bytes(out, size).c_str());
}

void libttsim_dram_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_client_mutex);
    dbg_log("dram wr: tile=(%u,%u) addr=0x%llx size=%u", x, y,
            static_cast<unsigned long long>(addr), size);

    if (addr > 0xFFFFFFFFull) {
        return;
    }

    uint32_t addr32 = static_cast<uint32_t>(addr);
    const uint8_t* in = static_cast<const uint8_t*>(p);
    uint8_t tile_x = static_cast<uint8_t>(x);
    uint8_t tile_y = static_cast<uint8_t>(y);
    send_cmd_locked(CMD_WRITE_DRAM, tile_x, tile_y, addr32, size, in, size, nullptr);
}

void libttsim_clock(uint32_t n_clocks) {
    (void)n_clocks;
}

}  // extern "C"
