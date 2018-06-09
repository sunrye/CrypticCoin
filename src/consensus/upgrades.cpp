#include "upgrades.h"

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
    return false;
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