/*
* Copyright (c) 2021 Peng Cheng Laboratory.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*-----------------------------------------------------------------------------
 *  
 *  Name:		 Tuple Space Assisted Packet Classification with High Performance on Both Search and Update[1]
 *  Version:	 3.0 (release)
 *  Author:		 Wenjun Li(Peng Cheng Laboratory, Email:wenjunli@pku.edu.cn)	 
 *  Date:		 8/8/2021
 *  Note:		 version 3.0 was modified by Yuxi Liu (under the guidance of Wenjun Li), a graduate student from the Southern University of Science and Technology.  
 *  [1] wenjun Li, Tong Yang, Ori Rottenstreich, Xianfeng Li, Gaogang Xie, Hui Li, Balajee Vamanan, Dagang Li and Huiping Lin, “Tuple Space Assisted Packet Classification with High Performance on Both Search and Update,” In Special Issue on Network Softwarization & Enablers，IEEE Journal on Selected Areas in Communications (JSAC), 2020.
 *-----------------------------------------------------------------------------
 */

#include "CutTSS.h"
using namespace std;

CutTSS::CutTSS(int SIP_Threshold, int DIP_Threshold, int bucketSize, int ratiotssleaf) {
    this->SIP_Threshold = SIP_Threshold;
    this->DIP_Threshold = DIP_Threshold;
    this->binth = bucketSize;
    this->rtssleaf = ratiotssleaf;
    statistics.resize(7, vector<int>(3));
    memory.resize(3, vector<double>(3));
    PSbig = nullptr;
}

void CutTSS::ConstructClassifier(const vector<Rule>& rules) {
    this->rules = rules;
    vector<vector<int> > Thre(3);
    //int DIP_threshold = 1;
    Thre[0] = {SIP_Threshold, DIP_Threshold, -1, -1, -1};
    Thre[1] = {SIP_Threshold, -1, -1, -1, -1};
    Thre[2] = {-1, DIP_Threshold, -1, -1, -1};

    subset = partition(Thre, rules);
    nodeSet.resize(3, nullptr);
    maxPri.resize(4, -1);
    for(int i = 0; i < nodeSet.size(); i++) {
        if(subset[i].empty()) continue;
        statistics[numRules][i] = int(subset[i].size());
        nodeSet[i] = ConstructCutTSSTrie(subset[i], Thre[i], i);
        maxPri[i] = subset[i][0].priority;
    }
    if(!subset.back().empty()) {
        PSbig = new PriorityTupleSpaceSearch();
        PSbig->ConstructClassifier(subset.back());
        maxPri.back() = subset.back()[0].priority;
    }
}


CutTSS::~CutTSS() {
    nodeSet.clear();
}

int CutTSS::ClassifyAPacket(const Packet &packet) {
    int matchPri = -1;
    uint64_t Query = 0;
    if(nodeSet[0]) matchPri = trieLookup(packet, nodeSet[0], 3, Query);
    if(nodeSet[1] && maxPri[1] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[1], 1, Query));
    if(nodeSet[2] && maxPri[2] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[2], 2, Query));
    if(PSbig && maxPri[3] > matchPri){
        if(subset.back().size() <= rtssleaf * PSbig->NumTables()) {
            for(const Rule &rule : subset.back()) {
                Query++;
                if(rule.MatchesPacket(packet)) {
                    matchPri = max(matchPri, rule.priority);
                    break;
                }
            }
        } else {
            matchPri = max(matchPri, PSbig->ClassifyAPacket(packet, Query));
        }
    }
    QueryUpdate(Query);
    return matchPri;
}

int CutTSS::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    int matchPri = -1;
    if(nodeSet[0]) matchPri = trieLookup(packet, nodeSet[0], 3, Query);
    if(nodeSet[1] && maxPri[1] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[1], 1, Query));
    if(nodeSet[2] && maxPri[2] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[2], 2, Query));
    if(PSbig && maxPri[3] > matchPri){
        if(nodeSet[3]->classifier.size() < rtssleaf * PSbig->NumTables()) {
            for(const Rule &rule : nodeSet[3]->classifier) {
                Query++;
                if(rule.MatchesPacket(packet)) {
                    matchPri = max(matchPri, rule.priority);
                    break;
                }
            }
        } else {
            matchPri = max(matchPri, PSbig->ClassifyAPacket(packet, Query));
        }
    }
    QueryUpdate(Query);
    return matchPri;
}

void CutTSS::DeleteRule(const Rule &delete_rule) {
    if(delete_rule.prefix_length[0] >= SIP_Threshold && delete_rule.prefix_length[1] >= DIP_Threshold) {
        trieDelete(delete_rule, nodeSet[0], 3);
    }
    else if(delete_rule.prefix_length[0] >= SIP_Threshold) {
        trieDelete(delete_rule, nodeSet[1], 1);
    }
    else if(delete_rule.prefix_length[1] >= DIP_Threshold) {
        trieDelete(delete_rule, nodeSet[2], 2);
    }
    else {
        PSbig->DeleteRule(delete_rule);
    }
}

void CutTSS::InsertRule(const Rule &insert_rule) {
    if(insert_rule.prefix_length[0] >= SIP_Threshold && insert_rule.prefix_length[1] >= DIP_Threshold) {
        trieInsert(insert_rule, nodeSet[0], 3);
    }
    else if(insert_rule.prefix_length[0] >= SIP_Threshold) {
        trieInsert(insert_rule, nodeSet[1], 1);
    }
    else if(insert_rule.prefix_length[1] >= DIP_Threshold) {
        trieInsert(insert_rule, nodeSet[2], 2);
    }
    else {
        PSbig->InsertRule(insert_rule);
    }
}

Memory CutTSS::MemSizeBytes() const {
    uint32_t totMemory = 0;
    for(int i = 0; i < nodeSet.size(); i++) {
        totMemory += uint32_t(memory[totMem][i]);
    }
    if(PSbig) {
        totMemory += PSbig->MemSizeBytes();
    }
    return totMemory;
}

vector<vector<Rule> > CutTSS::partition(vector<vector<int>> Thre, const vector<Rule> &rules) {
    int n = int(Thre.size());
    std::vector<std::vector<Rule> > subset(n + 1); // + 1 : the big rules rooms in the last subset.
    for (const Rule &rule : rules) {
        bool flag = false;
        for(int i = 0; i < n; i++) {
            bool insertFlag = true;
            for (int dim = 0; dim < MAXDIMENSIONS; dim++) {
                if(Thre[i][dim] == -1) continue;
                if(rule.prefix_length[dim] < Thre[i][dim]) {
                    insertFlag = false;
                    break;
                }
            }
            if(insertFlag) {
                subset[i].push_back(rule);
                flag = true;
                break;
            }
        }
        if(!flag) {
            subset.back().push_back(rule);
        }
    }
    return subset;
}

CutTSSNode* CutTSS::ConstructCutTSSTrie(const vector<Rule> &rules, const vector<int> &dims, int k) {
    int maxCuts = 0;
    for(int d : dims) {
        if(d != -1) maxCuts ++;
    }
    maxCuts = maxCuts == 1 ? 64 : 8;
    vector<vector<unsigned int> > field(MAXDIMENSIONS, vector<unsigned int>(2));
    for(int dim = 0; dim < MAXDIMENSIONS; dim++) {
        field[dim][HighDim] = (uint64_t(1) << maxMask[dim]) - 1;
    }

    auto *root = new CutTSSNode(rules, field, 0, false, Cuts);
    statistics[totArray][k] ++;

    queue<CutTSSNode*> qNode;
    qNode.push(root);
    while(!qNode.empty()) {
        CutTSSNode *node = qNode.front();
        qNode.pop();
        if(node->nrules <= binth) {
            node->isLeaf = true;
            node->nodeType = Linear;
            statistics[totLeafRules][k] += node->nrules;
            statistics[totLeaNode][k] ++;
            statistics[worstLevel][k] = max(statistics[worstLevel][k], node->depth);

            continue;
        }

        CalcCutsn(node, dims);
        int totCuts = 1;
        for(int dim = 0; dim < MAXDIMENSIONS; dim++) {
            if(dims[dim] != -1 && node->ncuts[dim] < maxCuts) {
                node->nodeType = TSS;
            }
            totCuts *= node->ncuts[dim];
        }
        node->children.resize(totCuts, nullptr);
        statistics[totArray][k] += totCuts;

        vector<unsigned int> r(MAXDIMENSIONS), i(MAXDIMENSIONS);
        if(node->nodeType == Cuts) {
            statistics[totNonLeafNode][k] ++;

            int index = 0;

            r[0] = (node->field[0][HighDim] - node->field[0][LowDim]) / node->ncuts[0];
            field[0][LowDim] = node->field[0][LowDim];
            field[0][HighDim] = node->field[0][LowDim] + r[0];
            for(i[0] = 0; i[0] < node->ncuts[0]; i[0]++) {  //sip

                r[1] = (node->field[1][HighDim] - node->field[1][LowDim]) / node->ncuts[1];
                field[1][LowDim] = node->field[1][LowDim];
                field[1][HighDim] = node->field[1][LowDim] + r[1];
                for(i[1] = 0; i[1] < node->ncuts[1]; i[1]++) {  //dip

                    r[2] = (node->field[2][HighDim] - node->field[2][LowDim]) / node->ncuts[2];
                    field[2][LowDim] = node->field[2][LowDim];
                    field[2][HighDim] = node->field[2][LowDim] + r[2];
                    for(i[2] = 0; i[2] < node->ncuts[2]; i[2] ++) {

                        r[3] = (node->field[3][HighDim] - node->field[3][LowDim]) / node->ncuts[3];
                        field[3][LowDim] = node->field[3][LowDim];
                        field[3][HighDim] = node->field[3][LowDim] + r[3];
                        for(i[3] = 0; i[3] < node->ncuts[3]; i[3] ++) {

                            r[4] = (node->field[4][HighDim] - node->field[4][LowDim]) / node->ncuts[4];
                            field[4][LowDim] = node->field[4][LowDim];
                            field[4][HighDim] = node->field[4][LowDim] + r[4];
                            for(i[4] = 0; i[4] < node->ncuts[4]; i[4] ++) {

                                vector<Rule> subRule;
                                for(const Rule &rule : node->classifier) {
                                    bool flag = true;
                                    for(int t = 0; t < MAXDIMENSIONS; t++){
                                        if(rule.range[t][LowDim] > field[t][HighDim] || rule.range[t][HighDim] < field[t][LowDim]) {
                                            flag = false;
                                            break;
                                        }
                                    }
                                    if(flag){
                                        subRule.push_back(rule);
                                    }
                                }
                                if(!subRule.empty()) {
                                    node->children[index] = new CutTSSNode(subRule, field, node->depth + 1, false, Cuts);
                                    qNode.push(node->children[index]);
                                }
                                index++;

                                field[4][LowDim] = field[4][HighDim] + 1;
                                field[4][HighDim] = field[4][LowDim] + r[4];
                            }
                            field[3][LowDim] = field[3][HighDim] + 1;
                            field[3][HighDim] = field[3][LowDim] + r[3];
                        }
                        field[2][LowDim] = field[2][HighDim] + 1;
                        field[2][HighDim] = field[2][LowDim] + r[2];
                    }
                    field[1][LowDim] = field[1][HighDim] + 1;
                    field[1][HighDim] = field[1][LowDim] + r[1];
                }
                field[0][LowDim] = field[0][HighDim] + 1;
                field[0][HighDim] = field[0][LowDim] + r[0];
            }
//            node->classifier.clear();
        } else {    // TSS stage or TSS leaf node stage
            node->isLeaf = true;
            PriorityTupleSpaceSearch ptmp;
            ptmp.ConstructClassifier(node->classifier);
            int numTuple = int(ptmp.NumTables());
            if(node->nrules <= (rtssleaf * numTuple)) {
                node->nodeType = Linear;

                statistics[totLeafRules][k] += node->nrules;
                statistics[totLeaNode][k] ++;
                statistics[worstLevel][k] = max(statistics[worstLevel][k], node->depth);
            } else {
                node->nodeType = TSS;
                node->PSTSS = new PriorityTupleSpaceSearch();
                node->PSTSS->ConstructClassifier(node->classifier);
                memory[totTSSMem][k] += node->PSTSS->MemSizeBytes();

                statistics[totTSSNode][k] ++;
            }
//            node->classifier.clear();
        }
    }
    return root;
}

void CutTSS::CalcCutsn(CutTSSNode *node, const vector<int> &dims) {
    int maxCuts = 0;
    for(int d : dims) {
        if(d != -1) maxCuts ++;
    }
    maxCuts = maxCuts == 1 ? 64 : 8;

    unsigned int lo, hi, r;
    for(int dim = 0; dim < MAXDIMENSIONS; dim++) {
        node->ncuts[dim] = 1;
        if(dims[dim] != -1) {
            while(true) {
                int cntRule = 0;
                for(int i = 0; i < node->classifier.size(); i++) {
                    r = (node->field[dim][HighDim] - node->field[dim][LowDim]) / (node->ncuts[dim]);
                    lo = node->field[dim][LowDim];
                    hi = lo + r;
                    for(int k = 0; k < node->ncuts[dim]; k++) {
                        if((node->classifier[i].range[dim][LowDim] >= lo && node->classifier[i].range[dim][LowDim] <= hi) ||
                           (node->classifier[i].range[dim][HighDim] >= lo && node->classifier[i].range[dim][HighDim] <= hi) ||
                           (node->classifier[i].range[dim][LowDim] <= lo && node->classifier[i].range[dim][HighDim] >= hi)) {
                            cntRule++;
                        }
                        lo = hi + 1;
                        hi = lo + r;
                    }
                }
                if(cntRule != node->nrules) {
                    node->ncuts[dim] = max(node->ncuts[dim] / 2, 1);
                    node->numbit[dim] = int(log(node->ncuts[dim]) / log(2));
                    node->andbit[dim] = (1 << int(log(node->ncuts[dim]) / log(2))) - 1;
                    break;
                }
                else if((node->ncuts[dim] <= maxCuts / 2) && (node->ncuts[dim] < (node->field[dim][HighDim] - node->field[dim][LowDim]) / 2)) {
                    node->ncuts[dim] *= 2;
                } else {
                    node->numbit[dim] = int(log(node->ncuts[dim]) / log(2));
                    node->andbit[dim] = (1 << int(log(node->ncuts[dim]) / log(2))) - 1;
                    break;
                }
            }
        }
    }
}

int CutTSS::trieLookup(const Packet &packet, CutTSSNode *root, int speedUpFlag, uint64_t &Query) {
    int matchPri = -1;
    CutTSSNode* node = root;
    unsigned int numbit = 32;
    unsigned int numbit1 = 32, numbit2 = 32;
    unsigned int cchild;


    switch(speedUpFlag) {
        case 1: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[0];
                cchild = (packet[0] >> numbit) & node->andbit[0];
                node = node->children[cchild];
                Query++;
            }
            break;
        }
        case 2: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[1];
                cchild = (packet[1] >> numbit) & node->andbit[1];
                node = node->children[cchild];
                Query++;
            }
            break;
        }
        case 3: {
            while(node && !node->isLeaf) {
                numbit1 -= node->numbit[0];
                numbit2 -= node->numbit[1];
                cchild = ((packet[0] >> numbit1) & node->andbit[0]) * node->ncuts[1] + ((packet[1] >> numbit2) & node->andbit[1]);
                node = node->children[cchild];
            }
        }
        default:
            break;
    }
    if(!node) {
        return -1;
    }
    if(node->nodeType == TSS) {
        matchPri = node->PSTSS->ClassifyAPacket(packet, Query);
    } else {
        for(const Rule &rule : node->classifier) {
            Query ++;
            if(rule.MatchesPacket(packet)) {
                matchPri = rule.priority;
                break;
            }
        }
    }
    return matchPri;
}

void CutTSS::trieDelete(const Rule &delete_rule, CutTSSNode *root, int speedUpFlag) {
    unsigned int cchild;
    CutTSSNode *node = root;

    unsigned int numbit = 32;
    unsigned int numbit1 = 32;
    unsigned int numbit2 = 32;

    switch(speedUpFlag) {
        case 1: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[0];
                cchild = (delete_rule.range[0][LowDim] >> numbit) & node->andbit[0];
                node = node->children[cchild];
            }
            break;
        }
        case 2: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[1];
                cchild = (delete_rule.range[1][LowDim] >> numbit) & node->andbit[1];
                node = node->children[cchild];
            }
            break;
        }
        case 3: {
            while(node && !node->isLeaf) {
                numbit1 -= node->numbit[0];
                numbit2 -= node->numbit[1];
                cchild = ((delete_rule.range[0][LowDim] >> numbit1) & node->andbit[0]) *
                            node->ncuts[1] + ((delete_rule.range[1][LowDim] >> numbit2) & node->andbit[1]);
                node = node->children[cchild];
            }
        }
        default:
            break;
    }
    if(!node) {
        printf("the node is empty, delete failed! rule id=%d\n",delete_rule.id);
        return ;
    }
    if(node->nodeType == TSS) {
        node->PSTSS->DeleteRule(delete_rule);
    } else {
//        int i, j;
//        for(i = 0; i < node->classifier.size(); i++) {
//            if(node->classifier[i].id == delete_rule.id) break;
//        }
//        for(j = 0; j < node->classifier.size() - 1; j++ ) {
//            node->classifier[j] = node->classifier[j + 1];
//        }
//        node->classifier.pop_back();
        auto iter = lower_bound(node->classifier.begin(), node->classifier.end(), delete_rule);
        if(iter == node->classifier.end()) {
            cout<<"Not Found!"<<endl;
            return;
        }
        node->classifier.erase(iter);
    }

}

void CutTSS::trieInsert(const Rule &insert_rule, CutTSSNode *root, int speedUpFlag) {
    unsigned int cchild;
    CutTSSNode *node = root;

    unsigned int numbit = 32;
    unsigned int numbit1 = 32;
    unsigned int numbit2 = 32;

    switch(speedUpFlag) {
        case 1: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[0];
                cchild = (insert_rule.range[0][LowDim] >> numbit) & ANDBITS1;
                node = node->children[cchild];
            }
            break;
        }
        case 2: {
            while(node && !node->isLeaf) {
                numbit -= node->numbit[1];
                cchild = (insert_rule.range[1][LowDim] >> numbit) & ANDBITS1;
                node = node->children[cchild];
            }
            break;
        }
        case 3: {
            while(node && !node->isLeaf) {
                numbit1 -= node->numbit[0];
                numbit2 -= node->numbit[1];
                cchild = ((insert_rule.range[0][LowDim] >> numbit1) & ANDBITS2) *
                         node->ncuts[1] + ((insert_rule.range[1][LowDim] >> numbit2) & ANDBITS2);
                node = node->children[cchild];
            }
        }
        default:
            break;
    }
    if(!node) {
        return;
    }
    if(node->nodeType == TSS) {
        node->PSTSS->InsertRule(insert_rule);
    } else {
//        auto iter = lower_bound(node->classifier.begin(), node->classifier.end(), insert_rule);
//        node->classifier.insert(iter, insert_rule);
        node->classifier.push_back(insert_rule);
    }
}

size_t CutTSS::NumTables() const {
    int totTables = 0;
    for(int i = 0; i < subset.size(); i++) {
        if(!subset.empty()) {
            totTables++;
        }
    }
    return totTables;
}


