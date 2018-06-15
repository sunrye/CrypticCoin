// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CRYPTICCOIN_AMOUNT_H
#define CRYPTICCOIN_AMOUNT_H

#include <stdlib.h>
#include <string>

typedef long long int64;

typedef int64 CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

static const CAmount MAX_MONEY = 7598607361 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }


static const int64 MIN_TX_FEE = 1 * CENT;
static const int64 MIN_RELAY_TX_FEE = 1 * CENT;
static const int64 PREMINE_AMOUNT = 3039442960 * COIN;
static const int64 FREECO_AMOUNT = 379930370 * COIN;
static const int64 AMB_FREECO_AMOUNT = 759860740 * COIN;

static const int64 MIN_TXOUT_AMOUNT = MIN_TX_FEE;

#endif //CRYPTICCOIN_AMOUNT_H
