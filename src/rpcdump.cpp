// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "importprivkey <CrypticCoinprivkey> [label]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    if (fWalletUnlockMintOnly) // ppcoin: no importprivkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
        pwalletMain->ReacceptWalletTransactions();
    }

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <CrypticCoinaddress>\n"
            "Reveals the private key corresponding to <CrypticCoinaddress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid CrypticCoin address");
    if (fWalletUnlockMintOnly) // ppcoin: no dumpprivkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}


Value z_exportkey(const Array& params, bool fHelp) {
    if (!EnsureWalletIsAvailable(fHelp))
        return Value::null;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportkey \"zaddr\"\n"
            "\nReveals the zkey corresponding to 'zaddr'.\n"
            "Then the z_importkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the private key\n"
            "\nResult:\n"
            "\"key\"                  (string) The private key\n"
            "\nExamples:\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    CZCPaymentAddress address(strAddress);
    auto addr = address.Get();

    libzcash::SpendingKey k;
    if (!pwalletMain->GetSpendingKey(addr, k))
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private zkey for this zaddr");

    CZCSpendingKey spendingkey(k);
    return spendingkey.ToString();
}

Value z_importkey(const Array& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return Value::null;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importkey \"zkey\" ( rescan startHeight )\n"
            "\nAdds a zkey (as returned by z_exportkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"zkey\"           (string, required) The zkey (see z_exportkey)\n"
            "2. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight        (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("yes") == 0) {
                fRescan = true;
            } else if (rescan.compare("no") == 0) {
                fRescan = false;
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2)
        nRescanHeight = params[2].get_int();
    if (nRescanHeight < 0 || nRescanHeight > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    string strSecret = params[0].get_str();
    CZCSpendingKey spendingkey(strSecret);
    auto key = spendingkey.Get();
    auto addr = key.address();

    {
        // Don't throw error in case a key is already there
        if (pwalletMain->HaveSpendingKey(addr)) {
            if (fIgnoreExistingKey) {
                return Value::null;
            }
        } else {
            pwalletMain->MarkDirty();

            if (!pwalletMain-> AddZKey(key))
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding spending key to wallet");

            pwalletMain->mapZKeyMetadata[addr].nCreateTime = 1;
        }

        // We want to scan for transactions and notes
        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(FindBlockByHeight(nRescanHeight), true);
        }
    }

    return Value::null;
}

Value z_exportviewingkey(const Array& params, bool fHelp) {
    if (!EnsureWalletIsAvailable(fHelp))
        return Value::null;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportviewingkey \"zaddr\"\n"
            "\nReveals the viewing key corresponding to 'zaddr'.\n"
            "Then the z_importviewingkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"zaddr\"   (string, required) The zaddr for the viewing key\n"
            "\nResult:\n"
            "\"vkey\"                  (string) The viewing key\n"
            "\nExamples:\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();

    CZCPaymentAddress address(strAddress);
    auto addr = address.Get();

    libzcash::ViewingKey vk;
    if (!pwalletMain->GetViewingKey(addr, vk)) {
        libzcash::SpendingKey k;
        if (!pwalletMain->GetSpendingKey(addr, k)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not hold private key or viewing key for this zaddr");
        }
        vk = k.viewing_key();
    }

    CZCViewingKey viewingkey(vk);
    return viewingkey.ToString();
}

Value z_importviewingkey(const Array& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return Value::null;

    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "z_importviewingkey \"vkey\" ( rescan startHeight )\n"
            "\nAdds a viewing key (as returned by z_exportviewingkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"vkey\"             (string, required) The viewing key (see z_exportviewingkey)\n"
            "2. rescan             (string, optional, default=\"whenkeyisnew\") Rescan the wallet for transactions - can be \"yes\", \"no\" or \"whenkeyisnew\"\n"
            "3. startHeight        (numeric, optional, default=0) Block height to start rescan from\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    // Whether to perform rescan after import
    bool fRescan = true;
    bool fIgnoreExistingKey = true;
    if (params.size() > 1) {
        auto rescan = params[1].get_str();
        if (rescan.compare("whenkeyisnew") != 0) {
            fIgnoreExistingKey = false;
            if (rescan.compare("no") == 0) {
                fRescan = false;
            } else if (rescan.compare("yes") != 0) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "rescan must be \"yes\", \"no\" or \"whenkeyisnew\"");
            }
        }
    }

    // Height to rescan from
    int nRescanHeight = 0;
    if (params.size() > 2) {
        nRescanHeight = params[2].get_int();
    }
    if (nRescanHeight < 0 || nRescanHeight > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    string strVKey = params[0].get_str();
    CZCViewingKey viewingkey(strVKey);
    auto vkey = viewingkey.Get();
    auto addr = vkey.address();

    {
        if (pwalletMain->HaveSpendingKey(addr)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this viewing key");
        }

        // Don't throw error in case a viewing key is already there
        if (pwalletMain->HaveViewingKey(addr)) {
            if (fIgnoreExistingKey) {
                return Value::null;
            }
        } else {
            pwalletMain->MarkDirty();

            if (!pwalletMain->AddViewingKey(vkey)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding viewing key to wallet");
            }
        }

        // We want to scan for transactions and notes
        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(FindBlockByHeight(nRescanHeight), true);
        }
    }

    return Value::null;
}
