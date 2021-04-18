// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#include <sinovate/infinitynodetip.h>
#include <sinovate/infinitynodeman.h>
#include <sinovate/infinitynodersv.h>
#include <sinovate/infinitynodemeta.h>
#include <sinovate/infinitynodepeer.h>
#include <sinovate/flat-database.h>
#include <sinovate/infinitynodeadapter.h>

#include <chainparams.h>
#include <key_io.h>
#include <script/standard.h>
#include <netbase.h>

CInfinitynodeAdapter infnodeAdapter;


CInfinitynodeAdapter::CInfinitynodeAdapter()
{}

int CInfinitynodeAdapter:: testFunc() {
    return 12345678;
}


bool CInfinitynodeAdapter:: buildNonMaturedListFromBlock(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams)
{
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);
        addFromTransaction(block, pindex, view, chainparams, tx);
    }

    return true;
}

bool CInfinitynodeAdapter:: addFromTransaction(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx)
{
    if(tx.IsCoinBase()) {
        return false;
    }

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        std::vector<std::vector<unsigned char>> vSolutions;
        const CScript& prevScript = out.scriptPubKey;
        TxoutType whichType = Solver(prevScript, vSolutions);
        
        //Send to BurnAddress
        //Amount for InfnityNode
        addNonMaturedNode(block, pindex, view, chainparams, tx, out, i);

        //Amount to update Metadata
        addNonMaturedMeta(block, pindex, view, chainparams, tx, out);
    }

    return true;
}
bool CInfinitynodeAdapter:: addNonMaturedNode(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx, const CTxOut& out, unsigned int idx)
{
    std::vector<std::vector<unsigned char>> vSolutions;
    const CScript& prevScript = out.scriptPubKey;
    TxoutType whichType = Solver(prevScript, vSolutions);
    //Send to BurnAddress
    if (whichType == TxoutType::TX_BURN_DATA && Params().GetConsensus().cBurnAddress == EncodeDestination(PKHash(uint160(vSolutions[0]))))
    {
        //Amount for InfnityNode
        if (
        ((Params().GetConsensus().nMasternodeBurnSINNODE_1 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN) ||
        ((Params().GetConsensus().nMasternodeBurnSINNODE_5 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN) ||
        ((Params().GetConsensus().nMasternodeBurnSINNODE_10 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
        ) {
            COutPoint outpoint(tx.GetHash(), idx);
            CInfinitynode inf(PROTOCOL_VERSION, outpoint);
            inf.setHeight(pindex->nHeight);
            inf.setBurnValue(out.nValue);

            if (vSolutions.size() == 2){
                std::string backupAddress(vSolutions[1].begin(), vSolutions[1].end());
                CTxDestination NodeAddress = DecodeDestination(backupAddress);
                if (IsValidDestination(NodeAddress)) {
                    inf.setBackupAddress(backupAddress);
                }
            }
            //SINType
            CAmount nBurnAmount = out.nValue / COIN + 1; //automaticaly round
            inf.setSINType(nBurnAmount / 100000);

            //Address payee: we known that there is only 1 input
            const Coin& coin = view.AccessCoin(tx.vin[0].prevout);

            CTxDestination addressBurnFund;
            if(!ExtractDestination(coin.out.scriptPubKey, addressBurnFund)){
                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                return false;
            }

            inf.setCollateralAddress(EncodeDestination(addressBurnFund));
            inf.setScriptPublicKey(coin.out.scriptPubKey);

            //we have all infos. Then add in mapNonMatured
            if (mapInfinitynodesNonMatured.find(inf.vinBurnFund.prevout) != mapInfinitynodesNonMatured.end()) {
                //exist
                return false;
            } else {
                //non existe
                mapInfinitynodesNonMatured[inf.vinBurnFund.prevout] = inf;
            }
        }
    }

    return true;
}


bool CInfinitynodeAdapter:: addNonMaturedMeta(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx, const CTxOut& out)
{
    std::vector<std::vector<unsigned char>> vSolutions;
    const CScript& prevScript = out.scriptPubKey;
    TxoutType whichType = Solver(prevScript, vSolutions);

    if (whichType == TxoutType::TX_BURN_DATA && Params().GetConsensus().cMetadataAddress == EncodeDestination(PKHash(uint160(vSolutions[0]))))
    {
        //Amount for UpdateMeta
        if ((Params().GetConsensus().nInfinityNodeUpdateMeta - 1) * COIN <= out.nValue && out.nValue <= (Params().GetConsensus().nInfinityNodeUpdateMeta) * COIN) {
            if (vSolutions.size() == 2) {
                std::string metadata(vSolutions[1].begin(), vSolutions[1].end());
                string s;
                stringstream ss(metadata);
                int i = 0;
                int check = 0;
                std::string publicKeyString;
                CService service;
                std::string burnTxID;
                while (getline(ss, s,';')) {
                    CTxDestination NodeAddress;
                    //1st position: Node Address
                    if (i == 0) {
                        publicKeyString = s;
                        std::vector<unsigned char> tx_data = DecodeBase64(publicKeyString.c_str());
                        CPubKey decodePubKey(tx_data.begin(), tx_data.end());
                        if (decodePubKey.IsValid()) {check++;}
                    }
                    //2nd position: Node IP
                    if (i == 1) {
                        if (Lookup(s.c_str(), service, 0, false)) {
                            check++;
                        }
                    }
                    //3th position: 16 character from Infinitynode BurnTx
                    if (i == 2 && s.length() >= 16) {
                        check++;
                        burnTxID = s.substr(0, 16);
                    }
                    //Update node metadata if nHeight is bigger
                    if (check == 3){
                        //Address payee: we known that there is only 1 input
                        const Coin& coin = view.AccessCoin(tx.vin[0].prevout);

                        CTxDestination addressBurnFund;
                        if(!ExtractDestination(coin.out.scriptPubKey, addressBurnFund)){
                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta::metaScan -- False when extract payee from BurnFund tx.\n");
                            return false;
                        }

                        std::ostringstream streamInfo;
                        streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;

                        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta:: meta update: %s, %s, %s\n", 
                                        streamInfo.str(), publicKeyString, service.ToString());
                        int avtiveBK = 0;
                        CMetadata meta = CMetadata(streamInfo.str(), publicKeyString, service, pindex->nHeight, avtiveBK);
                        infnodemeta.Add(meta);
                    }
                    i++;
                }
            }
        }
    }

    return true;
}