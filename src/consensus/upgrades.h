// Copyright (c) 2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCASH_CONSENSUS_UPGRADES_H
#define ZCASH_CONSENSUS_UPGRADES_H

#include "consensus.h"

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
const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES] = {
        {
                /*.nBranchId =*/ 0,
                /*.strName =*/ "Sprout",
                /*.strInfo =*/ "The Zcash network at launch",
        },
        {
                /*.nBranchId =*/ 0x74736554,
                /*.strName =*/ "Test dummy",
                /*.strInfo =*/ "Test dummy info",
        },
        {
                /*.nBranchId =*/ 0x5ba81b19,
                /*.strName =*/ "Overwinter",
                /*.strInfo =*/ "See https://z.cash/upgrade/overwinter.html for details.",
        }
};

 const uint32_t SPROUT_BRANCH_ID = NetworkUpgradeInfo[Consensus::BASE_SPROUT].nBranchId;

bool NetworkUpgradeActive(int nHeight, const Consensus::Params& params, Consensus::UpgradeIndex idx)
{
    return true;
}

int CurrentEpoch(int nHeight, const Consensus::Params& params) {
    for (auto idxInt = Consensus::MAX_NETWORK_UPGRADES - 1; idxInt >= Consensus::BASE_SPROUT; idxInt--) {
        if (NetworkUpgradeActive(nHeight, params, Consensus::UpgradeIndex(idxInt))) {
            return idxInt;
        }
    }
    // Base case
    return Consensus::BASE_SPROUT;
}

uint32_t CurrentEpochBranchId(int nHeight, const Consensus::Params& params) {
    return NetworkUpgradeInfo[CurrentEpoch(nHeight, params)].nBranchId;
}

#endif // ZCASH_CONSENSUS_UPGRADES_H