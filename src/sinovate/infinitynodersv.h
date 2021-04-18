// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODERSV_H
#define SIN_INFINITYNODERSV_H

#include <key.h>
#include <validation.h>
#include <script/standard.h>
#include <key_io.h>

using namespace std;

class CInfinitynodersv;
class CVote;

extern CInfinitynodersv infnodersv;

class CVote
{
private:
    std::string proposalId;
    CScript voter;
    int nHeight;
    bool opinion;
public:
    CVote() :
        proposalId(),
        voter(),
        nHeight(),
        opinion()
        {}

    CVote(std::string proposalId, CScript voter, int& height, bool& opinion) :
        proposalId(proposalId),
        voter(voter),
        nHeight(height),
        opinion(opinion){}

    SERIALIZE_METHODS(CVote, obj)
    {
        READWRITE(obj.proposalId);
        READWRITE(*(CScriptBase*)(&obj.voter));
        READWRITE(obj.nHeight);
        READWRITE(obj.opinion);
    }

    std::string getProposalId(){return proposalId;}
    CScript getVoter(){return voter;}
    bool getOpinion(){return opinion;}
    int getHeight(){return nHeight;}
};

class CInfinitynodersv
{
private:
    static const std::string SERIALIZATION_VERSION_STRING;
    // critical section to protect the inner data structures
    mutable RecursiveMutex cs;
    // Keep track of current block height
    int nCachedBlockHeight;
public:
    std::map<std::string, std::vector<CVote>> mapProposalVotes;

    CInfinitynodersv();

    SERIALIZE_METHODS(CInfinitynodersv, obj)
    {
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING;
            READWRITE(strVersion);
        }
        READWRITE(obj.mapProposalVotes);
    }

    void Clear();
    bool Add(CVote &vote);
    bool Has(std::string proposal);
    std::vector<CVote>* Find(std::string proposal);
    std::map<std::string, std::vector<CVote>> GetFullProposalVotesMap() { return mapProposalVotes; }

    int getResult(std::string proposal, bool opinion, int mode = 0);
    bool rsvScan(int nHeight);

    std::string ToString() const;
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}

};
#endif // SIN_INFINITYNODERSV_H