// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#include "crypter.h"
#include "sync.h"
#include "zcash/Address.hpp"
#include "zcash/NoteEncryption.hpp"
#include <boost/signals2/signal.hpp>

class CScript;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;
    mutable CCriticalSection cs_SpendingKeyStore;

public:
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKey(const CKey& key) =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    //! Add a spending key to the store.
    virtual bool AddSpendingKey(const libzcash::SpendingKey &sk) =0;

    //! Check whether a spending key corresponding to a given payment address is present in the store.
    virtual bool HaveSpendingKey(const libzcash::PaymentAddress &address) const =0;
    virtual bool GetSpendingKey(const libzcash::PaymentAddress &address, libzcash::SpendingKey& skOut) const =0;
    virtual void GetPaymentAddresses(std::set<libzcash::PaymentAddress> &setAddress) const =0;

    //! Support for viewing keys
    virtual bool AddViewingKey(const libzcash::ViewingKey &vk) =0;
    virtual bool RemoveViewingKey(const libzcash::ViewingKey &vk) =0;
    virtual bool HaveViewingKey(const libzcash::PaymentAddress &address) const =0;
    virtual bool GetViewingKey(const libzcash::PaymentAddress &address, libzcash::ViewingKey& vkOut) const =0;

    virtual bool GetSecret(const CKeyID &address, CSecret& vchSecret, bool &fCompressed) const
    {
        CKey key;
        if (!GetKey(address, key))
            return false;
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }
};

typedef std::map<CKeyID, std::pair<CSecret, bool> > KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::map<libzcash::PaymentAddress, libzcash::SpendingKey> SpendingKeyMap;
typedef std::map<libzcash::PaymentAddress, libzcash::ViewingKey> ViewingKeyMap;
typedef std::map<libzcash::PaymentAddress, ZCNoteDecryption> NoteDecryptorMap;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    ScriptMap mapScripts;
    SpendingKeyMap mapSpendingKeys;
    ViewingKeyMap mapViewingKeys;
    NoteDecryptorMap mapNoteDecryptors;

public:
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut.Reset();
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    bool AddSpendingKey(const libzcash::SpendingKey &sk);
    bool HaveSpendingKey(const libzcash::PaymentAddress &address) const
    {
        bool result;
        {
            LOCK(cs_SpendingKeyStore);
            result = (mapSpendingKeys.count(address) > 0);
        }
        return result;
    }
    bool GetSpendingKey(const libzcash::PaymentAddress &address, libzcash::SpendingKey &skOut) const
    {
        {
            LOCK(cs_SpendingKeyStore);
            SpendingKeyMap::const_iterator mi = mapSpendingKeys.find(address);
            if (mi != mapSpendingKeys.end())
            {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }
    bool GetNoteDecryptor(const libzcash::PaymentAddress &address, ZCNoteDecryption &decOut) const
    {
        {
            LOCK(cs_SpendingKeyStore);
            NoteDecryptorMap::const_iterator mi = mapNoteDecryptors.find(address);
            if (mi != mapNoteDecryptors.end())
            {
                decOut = mi->second;
                return true;
            }
        }
        return false;
    }
    void GetPaymentAddresses(std::set<libzcash::PaymentAddress> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_SpendingKeyStore);
            SpendingKeyMap::const_iterator mi = mapSpendingKeys.begin();
            while (mi != mapSpendingKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
            ViewingKeyMap::const_iterator mvi = mapViewingKeys.begin();
            while (mvi != mapViewingKeys.end())
            {
                setAddress.insert((*mvi).first);
                mvi++;
            }
        }
    }

    virtual bool AddViewingKey(const libzcash::ViewingKey &vk);
    virtual bool RemoveViewingKey(const libzcash::ViewingKey &vk);
    virtual bool HaveViewingKey(const libzcash::PaymentAddress &address) const;
    virtual bool GetViewingKey(const libzcash::PaymentAddress &address, libzcash::ViewingKey& vkOut) const;
};

typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;
typedef std::map<libzcash::PaymentAddress, std::vector<unsigned char> > CryptedSpendingKeyMap;

/** Keystore which keeps the private keys encrypted.
 * It derives from the basic key store, which is used if no encryption is active.
 */
class CCryptoKeyStore : public CBasicKeyStore
{
private:
    // if fUseCrypto is true, mapKeys must be empty
    // if fUseCrypto is false, vMasterKey must be empty
    bool fUseCrypto;

protected:
    CryptedKeyMap mapCryptedKeys;
    CKeyingMaterial vMasterKey;
    CryptedSpendingKeyMap mapCryptedSpendingKeys;

    bool SetCrypted();

    // will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

public:
    CCryptoKeyStore() : fUseCrypto(false)
    {
    }

    bool IsCrypted() const
    {
        return fUseCrypto;
    }

    bool IsLocked() const
    {
        if (!IsCrypted())
            return false;
        bool result;
        {
            LOCK(cs_KeyStore);
            result = vMasterKey.empty();
        }
        return result;
    }

    bool Lock();

    virtual bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKey(address);
            return mapCryptedKeys.count(address) > 0;
        }
        return false;
    }
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        if (!IsCrypted())
        {
            CBasicKeyStore::GetKeys(setAddress);
            return;
        }
        setAddress.clear();
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        while (mi != mapCryptedKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }
        virtual bool AddCryptedSpendingKey(const libzcash::PaymentAddress &address,
                                       const libzcash::ReceivingKey &rk,
                                       const std::vector<unsigned char> &vchCryptedSecret);
    bool AddSpendingKey(const libzcash::SpendingKey &sk);
    bool HaveSpendingKey(const libzcash::PaymentAddress &address) const
    {
        {
            LOCK(cs_SpendingKeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveSpendingKey(address);
            return mapCryptedSpendingKeys.count(address) > 0;
        }
        return false;
    }
    bool GetSpendingKey(const libzcash::PaymentAddress &address, libzcash::SpendingKey &skOut) const;
    void GetPaymentAddresses(std::set<libzcash::PaymentAddress> &setAddress) const
    {
        if (!IsCrypted())
        {
            CBasicKeyStore::GetPaymentAddresses(setAddress);
            return;
        }
        setAddress.clear();
        CryptedSpendingKeyMap::const_iterator mi = mapCryptedSpendingKeys.begin();
        while (mi != mapCryptedSpendingKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }

    /* Wallet status (encrypted, locked) changed.
     * Note: Called without locks held.
     */
    boost::signals2::signal<void (CCryptoKeyStore* wallet)> NotifyStatusChanged;
};

#endif
