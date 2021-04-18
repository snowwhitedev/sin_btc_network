// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODEADAPTER_H
#define SIN_INFINITYNODEADAPTER_H

#include <sinovate/infinitynode.h>
#include <sinovate/infinitynodelockinfo.h>
#include <key_io.h>
#include <logging.h>

using namespace std;

class CInfinitynodeAdapter;

extern CInfinitynodeAdapter infnodeAdapter;

class CInfinitynodeAdapter
{
public:
    std::map<COutPoint, CInfinitynode> mapInfinitynodesNonMatured;    

private:

public:

    CInfinitynodeAdapter();

    int testFunc();

    bool buildNonMaturedListFromBlock(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams);

    bool addFromTransaction(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx);

    bool addNonMaturedNode(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx, const CTxOut& out, unsigned int idx);

    bool addNonMaturedMeta(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, const CTransaction& tx, const CTxOut& out);
};
#endif // SIN_INFINITYNODEADAPTER_H
