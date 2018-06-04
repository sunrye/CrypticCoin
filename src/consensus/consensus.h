// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdint.h>

/** The minimum allowed block version (network rule) */
static const int32_t MIN_BLOCK_VERSION = 4;
/** The minimum allowed transaction version (network rule) */
static const int32_t SPROUT_MIN_TX_VERSION = 1;
/** The minimum allowed Overwinter transaction version (network rule) */
static const int32_t OVERWINTER_MIN_TX_VERSION = 3;
/** The maximum allowed Overwinter transaction version (network rule) */
static const int32_t OVERWINTER_MAX_TX_VERSION = 3;
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 2000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = 20000;
/** The maximum size of a transaction (network rule) */
static const unsigned int MAX_TX_SIZE = 100000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** The minimum value which is invalid for expiry height, used by CTransaction and CMutableTransaction */
static constexpr uint32_t TX_EXPIRY_HEIGHT_THRESHOLD = 500000000;

/** Flags for LockTime() */
enum {
   /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
   LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** Used as the flags parameter to CheckFinalTx() in non-consensus code */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_MEDIAN_TIME_PAST;

namespace Consensus {

    /**
     * Index into Params.vUpgrades and NetworkUpgradeInfo
     *
     * Being array indices, these MUST be numbered consecutively.
     *
     * The order of these indices MUST match the order of the upgrades on-chain, as
     * several functions depend on the enum being sorted.
     */
    enum UpgradeIndex {
        // Sprout must be first
        BASE_SPROUT,
        UPGRADE_TESTDUMMY,
        UPGRADE_OVERWINTER,
        // NOTE: Also add new upgrades to NetworkUpgradeInfo in upgrades.cpp
        MAX_NETWORK_UPGRADES
    };

    struct NetworkUpgrade {

    };

    struct Params {

    };

}

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
