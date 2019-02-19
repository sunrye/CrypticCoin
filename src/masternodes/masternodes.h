// Copyright (c) 2019 The Crypticcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MASTERNODES_H
#define MASTERNODES_H

#include "amount.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "serialize.h"
#include "dbwrapper.h"
#include "uint256.h"

#include <map>
#include <stdint.h>

#include <boost/scoped_ptr.hpp>

static const CAmount MN_COMMON_FEE = COIN/1000; /// @todo change me
static const CAmount MN_ACTIVATION_FEE = MN_COMMON_FEE;
static const CAmount MN_SETOPERATOR_FEE = MN_COMMON_FEE;
static const CAmount MN_DISMISSVOTE_FEE = MN_COMMON_FEE;
static const CAmount MN_DISMISSVOTERECALL_FEE = MN_COMMON_FEE;
static const CAmount MN_FINALIZEDISMISSVOTING_FEE = MN_COMMON_FEE;

static const int MAX_DISMISS_VOTES_PER_MN = 20;

static const std::vector<unsigned char> MnTxMarker = {'M', 'n', 'T', 'x'};  // 4d6e5478

enum class MasternodesTxType : unsigned char
{
    None = 0,
    AnnounceMasternode    = 'a',
    ActivateMasternode    = 'A',
    SetOperatorReward     = 'O',
    DismissVote           = 'V',
    DismissVoteRecall     = 'v',
    FinalizeDismissVoting = 'F',
    CollateralSpent       = 'C'
};

// Works instead of constants cause 'regtest' differs (don't want to overcharge chainparams)
int GetMnActivationDelay();
CAmount GetMnCollateralAmount();
CAmount GetMnAnnouncementFee();

class CMasternode
{
public:
    //! Announcement metadata section
    //! Human readable name of this MN, len >= 3, len <= 255
    std::string name;
    //! Owner auth address. Can be used as an ID
    CKeyID ownerAuthAddress;
    //! Operator auth address. Can be used as an ID
    CKeyID operatorAuthAddress;
    //! Owner reward address.
    CScript ownerRewardAddress;

//    //! Operator reward metadata section
//    //! Operator reward address. Optional
//    CScript operatorRewardAddress;
//    //! Amount of reward, transferred to <Operator reward address>, instead of <Owner reward address>. Optional
//    CAmount operatorRewardAmount;

    //! Announcement block height
    uint32_t height;
    //! Min activation block height. Computes as <announcement block height> + max(100, number of active masternodes)
    uint32_t minActivationHeight;
    //! Activation block height. -1 if not activated
    int32_t activationHeight;
    //! Deactiavation height (just for trimming DB)
    int32_t deadSinceHeight;

    //! This fields are for transaction rollback (by disconnecting block)
    uint256 activationTx;
    uint256 collateralSpentTx;
    uint256 dismissFinalizedTx;

    uint32_t counterVotesFrom;
    uint32_t counterVotesAgainst;

    //! empty constructor
    CMasternode() {}

    //! constructor helper, runs without any checks
    void FromTx(CTransaction const & tx, int heightIn, std::vector<unsigned char> const & metadata);

    //! construct a CMasternode from a CTransaction, at a given height
    CMasternode(CTransaction const & tx, int heightIn, std::vector<unsigned char> const & metadata)
    {
        FromTx(tx, heightIn, metadata);
    }

    bool IsActive() const
    {
        return activationTx != uint256() && collateralSpentTx == uint256() && dismissFinalizedTx == uint256();
    }

    std::string GetHumanReadableStatus() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(ownerAuthAddress);
        READWRITE(operatorAuthAddress);
        READWRITE(*(CScriptBase*)(&ownerRewardAddress));
//        READWRITE(*(CScriptBase*)(&operatorRewardAddress));
//        READWRITE(operatorRewardAmount);
        READWRITE(height);
        READWRITE(minActivationHeight);
        READWRITE(activationHeight);    //! totally unused!!!
        READWRITE(deadSinceHeight);

        READWRITE(activationTx);
        READWRITE(collateralSpentTx);
        READWRITE(dismissFinalizedTx);

        // no need to store in DB! real-time counters
//        READWRITE(counterVotesFrom);
//        READWRITE(counterVotesAgainst);
    }

    //! equality test
    friend bool operator==(CMasternode const & a, CMasternode const & b);
    friend bool operator!=(CMasternode const & a, CMasternode const & b);
};

//! Active dismiss votes, committed by masternode. len <= MAX_DISMISS_VOTES_PER_MN
class CDismissVote
{
public:
    //! Masternode ID
    uint256 from;

    //! Masternode ID. The block until this vote is active
    uint256 against;

    uint32_t reasonCode;
    //! len <= 255
    std::string reasonDescription;

    //! Deactiavation height (just for trimming DB)
    int32_t deadSinceHeight;
    //! Deactiavation transaction affected by, own or alien (recall vote or finalize dismission)
    uint256 disabledByTx;

    void FromTx(CTransaction const & tx, std::vector<unsigned char> const & metadata);

    //! construct a CMasternode from a CTransaction, at a given height
    CDismissVote(CTransaction const & tx, std::vector<unsigned char> const & metadata)
    {
        FromTx(tx, metadata);
    }

    //! empty constructor
    CDismissVote() { }

    bool IsActive() const
    {
        return disabledByTx == uint256();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(from);
        READWRITE(against);
        READWRITE(reasonCode);
        READWRITE(reasonDescription);
        READWRITE(deadSinceHeight);
        READWRITE(disabledByTx);
    }

    friend bool operator==(CDismissVote const & a, CDismissVote const & b);
    friend bool operator!=(CDismissVote const & a, CDismissVote const & b);
};

typedef std::map<uint256, CMasternode> CMasternodes;  // nodeId -> masternode object,
typedef std::set<uint256> CActiveMasternodes;         // just nodeId's,
typedef std::map<CKeyID, uint256> CMasternodesByAuth; // for two indexes, owner->nodeId, operator->nodeId

typedef std::map<uint256, CDismissVote> CDismissVotes;
typedef std::multimap<uint256, uint256> CDismissVotesIndex; // just index, from->against or against->from

// 'multi' used only in to ways: for collateral spent and voting finalization (to save deactivated votes)
typedef std::multimap<uint256, std::pair<uint256, MasternodesTxType> > CMasternodesUndo;

class CMasternodesDB;

class CMasternodesView
{
private:
    CMasternodesDB & db;
    boost::scoped_ptr<CDBBatch> currentBatch;

    CMasternodes allNodes;
    CActiveMasternodes activeNodes;
    CMasternodesByAuth nodesByOwner;
    CMasternodesByAuth nodesByOperator;

    CDismissVotes votes;
    CDismissVotesIndex votesFrom;
    CDismissVotesIndex votesAgainst;

    CMasternodesUndo txsUndo;

public:
    typedef struct {
        uint256 id;
        CKeyID operatorAuthAddress;
        CKeyID ownerAuthAddress;
    } CMasternodeIDs;

    enum class AuthIndex { ByOwner, ByOperator };
    enum class VoteIndex { From, Against };

    CMasternodesView(CMasternodesDB & mndb) : db(mndb) {}
    ~CMasternodesView() {}

    CMasternodes const & GetMasternodes() const
    {
        return allNodes;
    }

    CActiveMasternodes const & GetActiveMasternodes() const
    {
        return activeNodes;
    }

    boost::optional<CMasternodesByAuth::const_iterator>
    ExistMasternode(AuthIndex where, CKeyID const & auth) const;

    CMasternode const * ExistMasternode(uint256 const & id) const;

    CDismissVotes const & GetVotes() const
    {
        return votes;
    }

    CDismissVotesIndex const & GetActiveVotesFrom() const
    {
        return votesFrom;
    }

    CDismissVotesIndex const & GetActiveVotesAgainst() const
    {
        return votesAgainst;
    }

    boost::optional<CDismissVotesIndex::const_iterator>
    ExistActiveVoteIndex(VoteIndex where, uint256 const & from, uint256 const & against) const;

    //! Initial load of all data
    void Load();

    //! Process event of spending collateral. It is assumed that the node exists
    bool OnCollateralSpent(uint256 const & nodeId, uint256 const & txid, uint input, int height);

    bool OnMasternodeAnnounce(uint256 const & nodeId, CMasternode const & node);
    bool OnMasternodeActivate(uint256 const & txid, uint256 const & nodeId, CKeyID const & operatorId, int height);
    bool OnDismissVote(uint256 const & txid, CDismissVote const & vote, CKeyID const & operatorId);
    bool OnDismissVoteRecall(uint256 const & txid, uint256 const & against, CKeyID const & operatorId, int height);
    bool OnFinalizeDismissVoting(uint256 const & txid, uint256 const & nodeId, int height);

//    bool HasUndo(uint256 const & txid) const;
    bool OnUndo(uint256 const & txid);

    uint32_t GetMinDismissingQuorum();

    void PrepareBatch();
    void WriteBatch();
    void DropBatch();

private:
    boost::optional<CMasternodeIDs> AmI(AuthIndex where) const;
public:
    boost::optional<CMasternodeIDs> AmIOperator() const;
    boost::optional<CMasternodeIDs> AmIOwner() const;
    boost::optional<CMasternodeIDs> AmIActiveOperator() const;
    boost::optional<CMasternodeIDs> AmIActiveOwner() const;

private:
    void Clear();
    void DeactivateVote(uint256 const & voteId, uint256 const & txid, int height);
    void DeactivateVotesFor(uint256 const & nodeId, uint256 const & txid, int height);
};

//! Checks if given tx is probably one of 'MasternodeTx', returns tx type and serialized metadata in 'data'
MasternodesTxType GuessMasternodeTxType(CTransaction const & tx, std::vector<unsigned char> & metadata);

#endif // MASTERNODES_H