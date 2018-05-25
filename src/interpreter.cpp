// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"
#include "interpreter.h"
#include "script.h"
#include "serialize.h"
#include "uint256.h"

using namespace std;

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer
{
private:
    const CTransaction &txTo;  //! reference to the spending transaction (the one being serialized)
    const CScript &scriptCode; //! output script being consumed
    const unsigned int nIn;    //! input index of txTo being signed
    const bool fAnyoneCanPay;  //! whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //! whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //! whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
            txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
            fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
            fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
            fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode */
    template<typename S>
    void SerializeScriptCode(S &s, int nType, int nVersion) const
    {
        auto size = scriptCode.size();
        ::WriteCompactSize(s, size);
        s.write((char*)&scriptCode.begin()[0], size);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput, int nType, int nVersion) const
    {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout, nType, nVersion);
        // Serialize the script
        assert(nInput != NOT_AN_INPUT);
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScript(), nType, nVersion);
        else
            SerializeScriptCode(s, nType, nVersion);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0, nType, nVersion);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence, nType, nVersion);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput, int nType, int nVersion) const
    {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut(), nType, nVersion);
        else
            ::Serialize(s, txTo.vout[nOutput], nType, nVersion);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s, int nType, int nVersion) const
    {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion, nType, nVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
            SerializeInput(s, nInput, nType, nVersion);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
            SerializeOutput(s, nOutput, nType, nVersion);
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime, nType, nVersion);

        // Serialize vjoinsplit
        if (txTo.nVersion >= 2)
        {
            //
            // SIGHASH_* functions will hash portions of
            // the transaction for use in signatures. This
            // keeps the JoinSplit cryptographically bound
            // to the transaction.
            //
            ::Serialize(s, txTo.vjoinsplit, nType, nVersion);
            if (txTo.vjoinsplit.size() > 0)
            {
                ::Serialize(s, txTo.joinSplitPubKey, nType, nVersion);

                CTransaction::joinsplit_sig_t nullSig = {};
                ::Serialize(s, nullSig, nType, nVersion);
            }
        }
    }
};

const unsigned char ZCASH_PREVOUTS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'Z','c','a','s','h','P','r','e','v','o','u','t','H','a','s','h'};
const unsigned char ZCASH_SEQUENCE_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'Z','c','a','s','h','S','e','q','u','e','n','c','H','a','s','h'};
const unsigned char ZCASH_OUTPUTS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'Z','c','a','s','h','O','u','t','p','u','t','s','H','a','s','h'};
const unsigned char ZCASH_JOINSPLITS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'Z','c','a','s','h','J','S','p','l','i','t','s','H','a','s','h'};

uint256 GetPrevoutHash(const CTransaction& txTo)
{
    CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_PREVOUTS_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo)
{
    CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_SEQUENCE_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo)
{
    CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vout.size(); n++)
    {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

uint256 GetJoinSplitsHash(const CTransaction& txTo)
{
    CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_JOINSPLITS_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vjoinsplit.size(); n++)
    {
        ss << txTo.vjoinsplit[n];
    }
    ss << txTo.joinSplitPubKey;
    return ss.GetHash();
}

} // anon namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo)
{
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
    hashJoinSplits = GetJoinSplitsHash(txTo);
}

SigVersion SignatureHashVersion(const CTransaction& txTo)
{
    if (txTo.fOverwintered)
    {
        return SIGVERSION_OVERWINTER;
    }
    else
    {
        return SIGVERSION_SPROUT;
    }
}

uint256 SignatureHash(
        const CScript& scriptCode,
        const CTransaction& txTo,
        unsigned int nIn,
        int nHashType,
        const CAmount& amount,
        uint32_t consensusBranchId,
        const PrecomputedTransactionData* cache)
{
    if (nIn >= txTo.vin.size() && nIn != NOT_AN_INPUT)
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }

    auto sigversion = SignatureHashVersion(txTo);

    if (sigversion == SIGVERSION_OVERWINTER)
    {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        uint256 hashJoinSplits;

        if (!(nHashType & SIGHASH_ANYONECANPAY))
        {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE)
        {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }

        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE)
        {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        }
        else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size())
        {
            CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_OUTPUTS_HASH_PERSONALIZATION);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        if (!txTo.vjoinsplit.empty())
        {
            hashJoinSplits = cache ? cache->hashJoinSplits : GetJoinSplitsHash(txTo);
        }

        uint32_t leConsensusBranchId = htole32(consensusBranchId);
        unsigned char personalization[16] = {};
        memcpy(personalization, "ZcashSigHash", 12);
        memcpy(personalization+12, &leConsensusBranchId, 4);

        CBLAKE2bWriter ss(SER_GETHASH, 0, personalization);
        // Header
        ss << txTo.fOverwintered;
        ss << txTo.nVersion;
        // Version group ID
        ss << txTo.nVersionGroupId;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // JoinSplits
        ss << hashJoinSplits;
        // Locktime
        ss << txTo.nLockTime;
        // Expiry height
        ss << txTo.nExpiryHeight;
        // Sighash type
        ss << nHashType;

        // If this hash is for a transparent input signature
        // (i.e. not for txTo.joinSplitSig):
        if (nIn != NOT_AN_INPUT)
        {
            // The input being signed (replacing the scriptSig with scriptCode + amount)
            // The prevout may already be contained in hashPrevout, and the nSequence
            // may already be contained in hashSequence.
            ss << txTo.vin[nIn].prevout;
            ss << scriptCode;
            ss << amount;
            ss << txTo.vin[nIn].nSequence;
        }

        return ss.GetHash();
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lock-in the txout payee at same index as txin
        if (nIn >= txTo.vout.size())
        {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nIn);
            return 1;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}


