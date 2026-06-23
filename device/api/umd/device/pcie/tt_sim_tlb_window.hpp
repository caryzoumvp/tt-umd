// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "umd/device/pcie/tlb_window.hpp"

namespace tt::umd {

// Forward declaration.
class TTSimCommunicator;
class TlbHandle;
struct tlb_data;

/**
 * Simulation TlbWindow implementation that keeps TLB configuration in software
 * and translates accesses back into tile/DRAM socket operations.
 *
 * Unlike silicon, the gem5-backed TTSim path does not have a real PCI BAR/TLB
 * aperture. The TLB config (core coordinates + address) is therefore used to
 * reconstruct the target core/address for each access, similar to RTL sim.
 */
class TTSimTlbWindow : public TlbWindow {
public:
    TTSimTlbWindow(std::unique_ptr<TlbHandle> handle, TTSimCommunicator* communicator, const tlb_data config = {});

    // Implementation of memory access methods using TTSimCommunicator.
    void write16(uint64_t offset, uint16_t value) override;
    uint16_t read16(uint64_t offset) override;
    void write32(uint64_t offset, uint32_t value) override;
    uint32_t read32(uint64_t offset) override;
    void write_register(uint64_t offset, const void* data, size_t size) override;
    void read_register(uint64_t offset, void* data, size_t size) override;
    void write_block(uint64_t offset, const void* data, size_t size) override;
    void read_block(uint64_t offset, void* data, size_t size) override;

    void safe_write16(uint64_t offset, uint16_t value) override;

    uint16_t safe_read16(uint64_t offset) override;

private:
    void translate_and_write(uint64_t offset, const void* data, size_t size);
    void translate_and_read(uint64_t offset, void* data, size_t size);

    TTSimCommunicator* sim_communicator_;
};

}  // namespace tt::umd
