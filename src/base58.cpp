// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"

template<class DATA_TYPE, CBitcoinAddress::Base58Type PREFIX, size_t SER_SIZE>
bool CZCEncoding<DATA_TYPE, PREFIX, SER_SIZE>::Set(const DATA_TYPE& addr) {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << addr;
    std::vector<unsigned char> addrSerialized(ss.begin(), ss.end());
    assert(addrSerialized.size() == SER_SIZE);
    // TODO version check
    SetData(PREFIX, &addrSerialized[0], SER_SIZE);
    return true;
}

template<class DATA_TYPE, CBitcoinAddress::Base58Type PREFIX, size_t SER_SIZE>
DATA_TYPE CZCEncoding<DATA_TYPE, PREFIX, SER_SIZE>::Get() const {
    if (vchData.size() != SER_SIZE) {
        throw std::runtime_error(
            PrependName(" is invalid")
        );
    }

    // TODO version check
    if (nVersion != PREFIX) {
        throw std::runtime_error(
            PrependName(" is for wrong network type")
        );
    }

    std::vector<unsigned char> serialized(vchData.begin(), vchData.end());

    CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
    DATA_TYPE ret;
    ss >> ret;
    return ret;
}

// Explicit instantiations for libzcash::PaymentAddress
template bool CZCEncoding<libzcash::PaymentAddress,
                          CBitcoinAddress::ZCPAYMENT_ADDRRESS,
                          libzcash::SerializedPaymentAddressSize>::Set(const libzcash::PaymentAddress& addr);
template libzcash::PaymentAddress CZCEncoding<libzcash::PaymentAddress,
                                              CBitcoinAddress::ZCPAYMENT_ADDRRESS,
                                              libzcash::SerializedPaymentAddressSize>::Get() const;

// Explicit instantiations for libzcash::ViewingKey
template bool CZCEncoding<libzcash::ViewingKey,
                          CBitcoinAddress::ZCVIEWING_KEY,
                          libzcash::SerializedViewingKeySize>::Set(const libzcash::ViewingKey& vk);
template libzcash::ViewingKey CZCEncoding<libzcash::ViewingKey,
                                          CBitcoinAddress::ZCVIEWING_KEY,
                                          libzcash::SerializedViewingKeySize>::Get() const;

// Explicit instantiations for libzcash::SpendingKey
template bool CZCEncoding<libzcash::SpendingKey,
                          CBitcoinAddress::ZCSPENDING_KEY,
                          libzcash::SerializedSpendingKeySize>::Set(const libzcash::SpendingKey& sk);
template libzcash::SpendingKey CZCEncoding<libzcash::SpendingKey,
                                           CBitcoinAddress::ZCSPENDING_KEY,
                                           libzcash::SerializedSpendingKeySize>::Get() const;