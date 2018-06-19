// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
CAmount minRelayTxFee = DEFAULT_MIN_RELAY_TX_FEE;