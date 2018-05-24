#ifndef ZCASH_CONSENSUS_UPGRADES_H
#define ZCASH_CONSENSUS_UPGRADES_H

#include "consensus.h"

bool NetworkUpgradeActive(int nHeight, const Consensus::Params& params, Consensus::UpgradeIndex idx)
{
    return true;
}

#endif // ZCASH_CONSENSUS_UPGRADES_H