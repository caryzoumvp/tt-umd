// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
//
// SPDX-License-Identifier: Apache-2.0

#include "umd/device/pcie/tt_sim_tlb_handle.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <tt-logger/tt-logger.hpp>
#include <utility>

#include "umd/device/chip_helpers/simulation_tlb_allocator.hpp"
#include "umd/device/simulation/tt_sim_communicator.hpp"
#include "umd/device/types/arch.hpp"
#include "umd/device/types/tlb.hpp"

namespace tt::umd {

TTSimTlbHandle::TTSimTlbHandle(
    std::shared_ptr<SimulationTlbAllocator> allocator,
    TTSimCommunicator* communicator,
    int tlb_id,
    size_t size,
    const TlbMapping tlb_mapping) :
    allocator_(std::move(allocator)) {
    (void)communicator;
    tlb_id_ = tlb_id;
    tlb_size_ = size;
    tlb_mapping_ = tlb_mapping;

    // Keep a fake, non-dereferenceable base pointer only for TlbWindow address
    // arithmetic. gem5-backed TTSim does not model a real PCI BAR/TLB aperture.
    if (allocator_ && allocator_->get_architecture_impl()->get_architecture() != tt::ARCH::QUASAR) {
        tlb_base_ = reinterpret_cast<uint8_t*>(allocator_->get_tlb_address_from_index(tlb_id_));
    }

    log_debug(
        LogUMD,
        "Created TTSimTlbHandle with ID {} size {} address 0x{:x}",
        tlb_id_,
        tlb_size_,
        reinterpret_cast<uint64_t>(tlb_base_));
}

std::unique_ptr<TTSimTlbHandle> TTSimTlbHandle::create(
    std::shared_ptr<SimulationTlbAllocator> allocator,
    TTSimCommunicator* communicator,
    int tlb_id,
    size_t size,
    const TlbMapping tlb_mapping) {
    return std::unique_ptr<TTSimTlbHandle>(
        new TTSimTlbHandle(std::move(allocator), communicator, tlb_id, size, tlb_mapping));
}

TTSimTlbHandle::~TTSimTlbHandle() noexcept { TTSimTlbHandle::free_tlb(); }

void TTSimTlbHandle::configure(const tlb_data& new_config) {
    tlb_config_ = new_config;
    tlb_config_.local_offset = new_config.local_offset / tlb_size_;

    // These fields are not used by the software-translated TTSim TLB path.
    tlb_config_.ordering = 0;
    tlb_config_.static_vc = 0;

    log_debug(
        LogUMD,
        "Configured TTSim software TLB {} local_offset={}, x_end={}, y_end={}, noc_sel={}, mcast={}",
        tlb_id_,
        tlb_config_.local_offset,
        tlb_config_.x_end,
        tlb_config_.y_end,
        tlb_config_.noc_sel,
        tlb_config_.mcast);
}

void TTSimTlbHandle::free_tlb() noexcept {
    if (allocator_) {
        allocator_->deallocate_tlb_index(tlb_id_);
        allocator_ = nullptr;

        log_debug(LogUMD, "Freed simulation TLB with ID {}", tlb_id_);
    }
}

tt::ARCH TTSimTlbHandle::get_arch() const { return allocator_->get_architecture(); }

}  // namespace tt::umd
