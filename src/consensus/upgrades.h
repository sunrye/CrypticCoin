// Copyright (c) 2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCASH_CONSENSUS_UPGRADES_H
#define ZCASH_CONSENSUS_UPGRADES_H

#include "consensus.h"
#include <string>

struct NUInfo {
    /** Branch ID (a random non-zero 32-bit value) */
    uint32_t nBranchId;
    /** User-facing name for the upgrade */
    std::string strName;
    /** User-facing information string about the upgrade */
    std::string strInfo;
};

/**
 * General information about each network upgrade.
 * Ordered by Consensus::UpgradeIndex.
 */
extern const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES];

extern const uint32_t SPROUT_BRANCH_ID;

bool NetworkUpgradeActive(int nHeight, const Consensus::Params& params, Consensus::UpgradeIndex idx);

int CurrentEpoch(int nHeight, const Consensus::Params& params);

uint32_t CurrentEpochBranchId(int nHeight, const Consensus::Params& params);

#endif // ZCASH_CONSENSUS_UPGRADES_H