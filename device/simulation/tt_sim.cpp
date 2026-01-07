#include <stdint.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

constexpr uint64_t kL1SizeBytes = 1464 * 1024;
struct TileMemory {
    std::vector<uint8_t> l1;
    std::unordered_map<uint64_t, uint8_t> mmio;
    uint64_t max_l1_touched = 0;
    bool touched = false;
};

struct TileShared {
    int fd = -1;
    uint8_t* map = nullptr;
    size_t size = 0;
    sem_t* sem = SEM_FAILED;
    bool ready = false;
};

std::mutex g_mem_mutex;
std::unordered_map<uint64_t, TileMemory> g_tiles;
std::unordered_map<uint64_t, TileShared> g_shared;

uint64_t tile_key(uint32_t x, uint32_t y) {
    return (static_cast<uint64_t>(x) << 32) | y;
}

TileMemory& get_tile(uint32_t x, uint32_t y) {
    uint64_t key = tile_key(x, y);
    auto& tile = g_tiles[key];
    if (tile.l1.empty()) {
        tile.l1.assign(kL1SizeBytes, 0);
    }
    tile.touched = true;
    return tile;
}

std::string shm_name(uint32_t x, uint32_t y) {
    const char* prefix = std::getenv("TT_SIM_SHM_PREFIX");
    std::string base = prefix ? prefix : "/ttsim_l1";
    return base + "_x" + std::to_string(x) + "_y" + std::to_string(y);
}

std::string sem_name(uint32_t x, uint32_t y) {
    const char* prefix = std::getenv("TT_SIM_SEM_PREFIX");
    std::string base = prefix ? prefix : "/ttsim_l1_sem";
    return base + "_x" + std::to_string(x) + "_y" + std::to_string(y);
}

TileShared& get_shared(uint32_t x, uint32_t y) {
    uint64_t key = tile_key(x, y);
    auto& shared = g_shared[key];
    if (shared.map) {
        return shared;
    }

    const size_t total = kL1SizeBytes;
    std::string shm = shm_name(x, y);
    std::string sem = sem_name(x, y);

    shared.fd = shm_open(shm.c_str(), O_CREAT | O_RDWR, 0666);
    if (shared.fd < 0) {
        return shared;
    }
    if (ftruncate(shared.fd, static_cast<off_t>(total)) != 0) {
        close(shared.fd);
        shared.fd = -1;
        return shared;
    }
    shared.map = static_cast<uint8_t*>(
        mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_SHARED, shared.fd, 0));
    if (shared.map == MAP_FAILED) {
        shared.map = nullptr;
        close(shared.fd);
        shared.fd = -1;
        return shared;
    }
    shared.size = total;
    shared.sem = sem_open(sem.c_str(), O_CREAT, 0666, 0);
    return shared;
}

}  // namespace

extern "C" {
void libttsim_init() {
    std::lock_guard<std::mutex> lock(g_mem_mutex);
    g_tiles.clear();
    g_shared.clear();
}

void libttsim_exit() {
    std::lock_guard<std::mutex> lock(g_mem_mutex);
    for (auto& entry : g_shared) {
        TileShared& shared = entry.second;
        if (shared.sem != SEM_FAILED) {
            sem_close(shared.sem);
            shared.sem = SEM_FAILED;
        }
        if (shared.map && shared.map != MAP_FAILED) {
            munmap(shared.map, shared.size);
            shared.map = nullptr;
        }
        if (shared.fd >= 0) {
            close(shared.fd);
            shared.fd = -1;
        }
    }
    g_shared.clear();
}

uint32_t libttsim_pci_config_rd32(uint32_t bus_device_function, uint32_t offset) {
    (void)bus_device_function;
    (void)offset;
    return 0x401E1E52;
}

void libttsim_tile_rd_bytes(uint32_t x, uint32_t y, uint64_t addr, void* p, uint32_t size) {
    // if (!p || size == 0) {
    //     return;
    // }
    // std::lock_guard<std::mutex> lock(g_mem_mutex);
    // TileMemory& tile = get_tile(x, y);
    // uint8_t* out = static_cast<uint8_t*>(p);
    // for (uint32_t i = 0; i < size; ++i) {
    //     uint64_t cur = addr + i;
    //     if (cur < tile.l1.size()) {
    //         TileShared& shared = get_shared(x, y);
    //         if (!shared.ready && shared.sem != SEM_FAILED) {
    //             sem_wait(shared.sem);
    //             shared.ready = true;
    //         }
    //         if (shared.map && cur < shared.size) {
    //             out[i] = shared.map[cur];
    //             tile.l1[cur] = out[i];
    //         } else {
    //             out[i] = tile.l1[cur];
    //         }
    //     } else {
    //         auto it = tile.mmio.find(cur);
    //         out[i] = (it == tile.mmio.end()) ? 0 : it->second;
    //     }
    // }
}

void libttsim_tile_wr_bytes(uint32_t x, uint32_t y, uint64_t addr, const void* p, uint32_t size) {
    if (!p || size == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mem_mutex);
    TileMemory& tile = get_tile(x, y);
    const uint8_t* in = static_cast<const uint8_t*>(p);
    for (uint32_t i = 0; i < size; ++i) {
        uint64_t cur = addr + i;
        if (cur < tile.l1.size()) {
            tile.l1[cur] = in[i];
            tile.max_l1_touched = std::max(tile.max_l1_touched, cur);
            TileShared& shared = get_shared(x, y);
            if (shared.map && cur < shared.size) {
                shared.map[cur] = in[i];
            }
        } else {
            tile.mmio[cur] = in[i];
        }
    }
}

void libttsim_clock(uint32_t n_clocks) {
    (void)n_clocks;
}

}  // extern "C"
