#ifndef CRYPTICCOIN_TRANSACTION_H
#define CRYPTICCOIN_TRANSACTION_H

#include "bignum.h"
#include "serialize.h"
#include "script.h"
#include "uint256.h"
#include "amount.h"
// #include "random.h"
// #include "util.h"
// #include "version.h"
#include "consensus/consensus.h"

#include <boost/array.hpp>
#include <boost/variant.hpp>

#include "zcash/NoteEncryption.hpp"
#include "zcash/Zcash.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"

class CTxIndex;
class CTxDB;
class CTransaction;
class CDiskTxPos;
class CBlockIndex;

// Overwinter transaction version
static const int32_t OVERWINTER_TX_VERSION = 3;
static_assert(OVERWINTER_TX_VERSION >= OVERWINTER_MIN_TX_VERSION,
              "Overwinter tx version must not be lower than minimum");
static_assert(OVERWINTER_TX_VERSION <= OVERWINTER_MAX_TX_VERSION,
              "Overwinter tx version must not be higher than maximum");

// Sapling transaction version
static const int32_t SAPLING_TX_VERSION = 4;
static_assert(SAPLING_TX_VERSION >= SAPLING_MIN_TX_VERSION,
              "Sapling tx version must not be lower than minimum");
static_assert(SAPLING_TX_VERSION <= SAPLING_MAX_TX_VERSION,
              "Sapling tx version must not be higher than maximum");

static constexpr size_t GROTH_PROOF_SIZE = (
        48 + // π_A
        96 + // π_B
        48); // π_C

namespace libzcash {
    typedef boost::array<unsigned char, GROTH_PROOF_SIZE> GrothProof;
}

/**
 * A shielded input to a transaction. It contains data that describes a Spend transfer.
 */
class SpendDescription
{
public:
    typedef boost::array<unsigned char, 64> spend_auth_sig_t;

    uint256 cv;                    //!< A value commitment to the value of the input note.
    uint256 anchor;                //!< A Merkle root of the Sapling note commitment tree at some block height in the past.
    uint256 nullifier;             //!< The nullifier of the input note.
    uint256 rk;                    //!< The randomized public key for spendAuthSig.
    libzcash::GrothProof zkproof;  //!< A zero-knowledge proof using the spend circuit.
    spend_auth_sig_t spendAuthSig; //!< A signature authorizing this spend.

    SpendDescription() { }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cv);
        READWRITE(anchor);
        READWRITE(nullifier);
        READWRITE(rk);
        READWRITE(zkproof);
        READWRITE(spendAuthSig);
    );

    friend bool operator==(const SpendDescription& a, const SpendDescription& b)
    {
        return (
                a.cv == b.cv &&
                a.anchor == b.anchor &&
                a.nullifier == b.nullifier &&
                a.rk == b.rk &&
                a.zkproof == b.zkproof &&
                a.spendAuthSig == b.spendAuthSig
        );
    }

    friend bool operator!=(const SpendDescription& a, const SpendDescription& b)
    {
        return !(a == b);
    }
};

static constexpr size_t SAPLING_ENC_CIPHERTEXT_SIZE = (
        1 +  // leading byte
        11 + // d
        8 +  // value
        32 + // rcm
        ZC_MEMO_SIZE + // memo
        NOTEENCRYPTION_AUTH_BYTES);

static constexpr size_t SAPLING_OUT_CIPHERTEXT_SIZE = (
        32 + // pkd_new
        32 + // esk
        NOTEENCRYPTION_AUTH_BYTES);

/**
 * A shielded output to a transaction. It contains data that describes an Output transfer.
 */
class OutputDescription
{
public:
    typedef boost::array<unsigned char, SAPLING_ENC_CIPHERTEXT_SIZE> sapling_enc_ct_t; // TODO: Replace with actual type
    typedef boost::array<unsigned char, SAPLING_OUT_CIPHERTEXT_SIZE> sapling_out_ct_t; // TODO: Replace with actual type

    uint256 cv;                     //!< A value commitment to the value of the output note.
    uint256 cm;                     //!< The note commitment for the output note.
    uint256 ephemeralKey;           //!< A Jubjub public key.
    sapling_enc_ct_t encCiphertext; //!< A ciphertext component for the encrypted output note.
    sapling_out_ct_t outCiphertext; //!< A ciphertext component for the encrypted output note.
    libzcash::GrothProof zkproof;   //!< A zero-knowledge proof using the output circuit.

    OutputDescription() { }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(cv);
        READWRITE(cm);
        READWRITE(ephemeralKey);
        READWRITE(encCiphertext);
        READWRITE(outCiphertext);
        READWRITE(zkproof);
    );

    friend bool operator==(const OutputDescription& a, const OutputDescription& b)
    {
        return (
                a.cv == b.cv &&
                a.cm == b.cm &&
                a.ephemeralKey == b.ephemeralKey &&
                a.encCiphertext == b.encCiphertext &&
                a.outCiphertext == b.outCiphertext &&
                a.zkproof == b.zkproof
        );
    }

    friend bool operator!=(const OutputDescription& a, const OutputDescription& b)
    {
        return !(a == b);
    }
};

template <typename Stream>
class SproutProofSerializer : public boost::static_visitor<>
{
    Stream& s;
    bool useGroth;

public:
    SproutProofSerializer(Stream& s, bool useGroth) : s(s), useGroth(useGroth) {}

    void operator()(const libzcash::ZCProof& proof) const
    {
        if (useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected GrothProof, found PHGRProof)");
        }
        ::Serialize(s, proof);
    }

    void operator()(const libzcash::GrothProof& proof) const
    {
        if (!useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected PHGRProof, found GrothProof)");
        }
        ::Serialize(s, proof);
    }
};

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, const T& proof, bool useGroth, CSerActionSerialize ser_action)
{
    auto ps = SproutProofSerializer<Stream>(s, useGroth);
    boost::apply_visitor(ps, proof);
}

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, T& proof, bool useGroth, CSerActionUnserialize ser_action)
{
    if (useGroth) {
        libzcash::GrothProof grothProof;
        ::Unserialize(s, grothProof);
        proof = grothProof;
    } else {
        libzcash::ZCProof pghrProof;
        ::Unserialize(s, pghrProof);
        proof = pghrProof;
    }
}

class JSDescription
{
public:
    // These values 'enter from' and 'exit to' the value
    // pool, respectively.
    CAmount vpub_old;
    CAmount vpub_new;

    // JoinSplits are always anchored to a root in the note
    // commitment tree at some point in the blockchain
    // history or in the history of the current
    // transaction.
    uint256 anchor;

    // Nullifiers are used to prevent double-spends. They
    // are derived from the secrets placed in the note
    // and the secret spend-authority key known by the
    // spender.
    boost::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;

    // Note commitments are introduced into the commitment
    // tree, blinding the public about the values and
    // destinations involved in the JoinSplit. The presence of
    // a commitment in the note commitment tree is required
    // to spend it.
    boost::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    // Ephemeral key
    uint256 ephemeralKey;

    // Ciphertexts
    // These contain trapdoors, values and other information
    // that the recipient needs, including a memo field. It
    // is encrypted using the scheme implemented in crypto/NoteEncryption.cpp
    boost::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{ {{0}} }};

    // Random seed
    uint256 randomSeed;

    // MACs
    // The verification of the JoinSplit requires these MACs
    // to be provided as an input.
    boost::array<uint256, ZC_NUM_JS_INPUTS> macs;

    // JoinSplit proof
    // This is a zk-SNARK which ensures that this JoinSplit is valid.
    boost::variant<libzcash::ZCProof, libzcash::GrothProof> proof;

    JSDescription(): vpub_old(0), vpub_new(0) { }

    JSDescription(ZCJoinSplit& params,
                  const uint256& pubKeyHash,
                  const uint256& rt,
                  const boost::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
                  const boost::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
                  CAmount vpub_old,
                  CAmount vpub_new,
                  bool computeProof = true, // Set to false in some tests
                  uint256 *esk = nullptr // payment disclosure
    );

    static JSDescription Randomized(
            ZCJoinSplit& params,
            const uint256& pubKeyHash,
            const uint256& rt,
            boost::array<libzcash::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            boost::array<libzcash::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            boost::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
            boost::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof = true, // Set to false in some tests
            uint256 *esk = nullptr, // payment disclosure
            std::function<int(int)> gen = GetRandInt
    );

    // Verifies that the JoinSplit proof is correct.
    bool Verify(
            ZCJoinSplit& params,
            libzcash::ProofVerifier& verifier,
            const uint256& pubKeyHash
    ) const;

    // Returns the calculated h_sig
    uint256 h_sig(ZCJoinSplit& params, const uint256& pubKeyHash) const;

    IMPLEMENT_SERIALIZE
    (
//        bool fOverwintered = s.GetVersion() >> 31;    // TODO: SS Stream& s
//        int32_t txVersion = s.GetVersion() & 0x7FFFFFFF;
//        bool useGroth = fOverwintered && txVersion >= SAPLING_TX_VERSION;

        READWRITE(vpub_old);
        READWRITE(vpub_new);
        READWRITE(anchor);
        READWRITE(nullifiers);
        READWRITE(commitments);
        READWRITE(ephemeralKey);
        READWRITE(randomSeed);
        READWRITE(macs);
        // ::SerReadWriteSproutProof(s, proof, useGroth, ser_action); // TODO: SS !
        READWRITE(ciphertexts);
    );

    friend bool operator==(const JSDescription& a, const JSDescription& b)
    {
        return (
                a.vpub_old == b.vpub_old &&
                a.vpub_new == b.vpub_new &&
                a.anchor == b.anchor &&
                a.nullifiers == b.nullifiers &&
                a.commitments == b.commitments &&
                a.ephemeralKey == b.ephemeralKey &&
                a.ciphertexts == b.ciphertexts &&
                a.randomSeed == b.randomSeed &&
                a.macs == b.macs &&
                a.proof == b.proof
        );
    }

    friend bool operator!=(const JSDescription& a, const JSDescription& b)
    {
        return !(a == b);
    }
};

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = (unsigned int) -1; }
    bool IsNull() const { return (hash == 0 && n == (unsigned int) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max())
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max())
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<unsigned int>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        return strprintf(" %s %d", prevout.hash.ToString().c_str(), prevout.n);
    }

    std::string ToString() const
    {
        std::string str;
        str += "CTxIn(";
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != std::numeric_limits<unsigned int>::max())
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(CAmount nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    // {
    //     // "Dust" is defined in terms of CTransaction::minRelayTxFee,
    //     // which has units satoshis-per-kilobyte.
    //     // If you'd pay more than 1/3 in fees
    //     // to spend something, then we consider it dust.
    //     // A typical spendable txout is 34 bytes big, and will
    //     // need a CTxIn of at least 148 bytes to spend:
    //     // so dust is a spendable txout less than 54 satoshis
    //     // with default minRelayTxFee.
    //     if (scriptPubKey.IsUnspendable())
    //         return 0;

    //     size_t nSize = GetSerializeSize(*this, SER_DISK, 0) + 148u;
    //     return 3*minRelayTxFee.GetFee(nSize);
    // }

    // bool IsDust(const CFeeRate &minRelayTxFee) const
    // {
    //     return (nValue < GetDustThreshold(minRelayTxFee));
    // }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        return strprintf(" out %s %s", FormatMoney(nValue).c_str(), scriptPubKey.ToString(true).c_str());
    }

    std::string ToString() const
    {
        if (IsEmpty()) return "CTxOut(empty)";
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", FormatMoney(nValue).c_str(), scriptPubKey.ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

// Overwinter version group id
static constexpr uint32_t OVERWINTER_VERSION_GROUP_ID = 0x03C48270;
static_assert(OVERWINTER_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");

// Sapling version group id
static constexpr uint32_t SAPLING_VERSION_GROUP_ID = 0x892F2085;
static_assert(SAPLING_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");


enum GetMinFee_mode
{
    GMF_BLOCK,
    GMF_RELAY,
    GMF_SEND,
};

typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
//private:
//    /** Memory only. */
//    const uint256 hash;
//    void UpdateHash() const;
//protected:
//    /** Developer testing only.  Set evilDeveloperFlag to true.
//     * Convert a CMutableTransaction into a CTransaction without invoking UpdateHash()
//     */
//    CTransaction(const CMutableTransaction &tx, bool evilDeveloperFlag);
public:
    static const int CURRENT_VERSION = 1; // TODO: SS ?

    typedef boost::array<unsigned char, 64> joinsplit_sig_t;
    typedef boost::array<unsigned char, 64> binding_sig_t;

    // Transactions that include a list of JoinSplits are >= version 2.
    static const int32_t SPROUT_MIN_CURRENT_VERSION = 1;
    static const int32_t SPROUT_MAX_CURRENT_VERSION = 2;
    static const int32_t OVERWINTER_MIN_CURRENT_VERSION = 3;
    static const int32_t OVERWINTER_MAX_CURRENT_VERSION = 3;
    static const int32_t SAPLING_MIN_CURRENT_VERSION = 4;
    static const int32_t SAPLING_MAX_CURRENT_VERSION = 4;

    static_assert(SPROUT_MIN_CURRENT_VERSION >= SPROUT_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert(OVERWINTER_MIN_CURRENT_VERSION >= OVERWINTER_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (OVERWINTER_MAX_CURRENT_VERSION <= OVERWINTER_MAX_TX_VERSION &&
                    OVERWINTER_MAX_CURRENT_VERSION >= OVERWINTER_MIN_CURRENT_VERSION),
                   "standard rule for tx version should be consistent with network rule");

    static_assert(SAPLING_MIN_CURRENT_VERSION >= SAPLING_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (SAPLING_MAX_CURRENT_VERSION <= SAPLING_MAX_TX_VERSION &&
                    SAPLING_MAX_CURRENT_VERSION >= SAPLING_MIN_CURRENT_VERSION),
                   "standard rule for tx version should be consistent with network rule");

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    bool fOverwintered;
    int nVersion;
    uint32_t nVersionGroupId;
    uint32_t nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime; 
    uint32_t nExpiryHeight;
    CAmount valueBalance;
    std::vector<SpendDescription> vShieldedSpend;
    std::vector<OutputDescription> vShieldedOutput;
    std::vector<JSDescription> vjoinsplit;
    uint256 joinSplitPubKey;
    CTransaction::joinsplit_sig_t joinSplitSig = {{0}};
    CTransaction::binding_sig_t bindingSig = {{0}};

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nTime);
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        nTime = GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsFinal(int nBlockHeight=0, int64 nBlockTime=0) const;

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (unsigned int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
    }

    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    /** Check for standard transaction types
        @return True if all outputs (scriptPubKeys) use only standard transaction forms
    */
    bool IsStandard() const;

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
        @see CTransaction::FetchInputs
    */
    bool AreInputsStandard(const MapPrevTx& mapInputs) const;

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
        @see CTransaction::FetchInputs
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
        @see CTransaction::FetchInputs
     */
    unsigned int GetP2SHSigOpCount(const MapPrevTx& mapInputs) const;

    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64 GetValueOut() const;

    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64 GetValueIn(const MapPrevTx& mapInputs) const;

    static bool AllowFree(double dPriority);

    int64 GetMinFee(unsigned int nBlockSize=1, bool fAllowFree=false, enum GetMinFee_mode mode=GMF_BLOCK) const;

    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL);

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        std::string str;
        str += strprintf("%s %s", GetHash().ToString().c_str(), IsCoinBase()? "base" : (IsCoinStake()? "stake" : "user"));
        return str;
    }

    std::string ToString() const
    {
        std::string str;
        str += IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
        str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%" PRIszu", vout.size=%" PRIszu", nLockTime=%d)\n",
                GetHash().ToString().substr(0,10).c_str(),
                nTime,
                nVersion,
                vin.size(),
                vout.size(),
                nLockTime);
        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }

    bool ReadFromDisk(CTxDB& txdb, const uint256& hash, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB& txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

     @param[in] txdb	Transaction database
     @param[in] mapTestPool	List of pending changes to the transaction index database
     @param[in] fBlock	True if being called to add a new best-block to the chain
     @param[in] fMiner	True if being called by CreateNewBlock
     @param[out] inputsRet	Pointers to this transaction's inputs
     @param[out] fInvalid	returns true if transaction is invalid
     @return	Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool,
                     bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

    /** Sanity check previous transactions, then, if all checks succeed,
        mark them as spent by this transaction.

        @param[in] inputs	Previous transactions (from FetchInputs)
        @param[out] mapTestPool	Keeps track of inputs that need to be updated on disk
        @param[in] posThisTx	Position of this transaction on disk
        @param[in] pindexBlock
        @param[in] fBlock	true if called from ConnectBlock
        @param[in] fMiner	true if called from CreateNewBlock
        @param[in] fStrictPayToScriptHash	true if fully validating p2sh transactions
        @return Returns true if all checks succeed
     */
    bool ConnectInputs(CTxDB& txdb, MapPrevTx inputs,
                       std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
                       const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true);
    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);
    bool GetCoinAge(CTxDB& txdb, uint64& nCoinAge) const;  // ppcoin: get transaction coin age

protected:
    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};




bool IsStandardTx(const CTransaction& tx);
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime);


#endif //CRYPTICCOIN_TRANSACTION_H
