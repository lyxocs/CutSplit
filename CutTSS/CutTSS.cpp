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

#include <math.h>
#include <queue>
#include "CutTSS.h"
#define PTR_SIZE 4
#define LEAF_NODE_SIZE 4
#define TREE_NODE_SIZE 8

using namespace std;

CutTSS::CutTSS(std::string threshold, int bucketSize = 8, int ratiotssleaf = 5) {
    for (int i = 0; i < threshold.size(); i += 2) {
        this->threshold.push_back(atoi(threshold.substr(i, 2).c_str()));
    }
    this->binth = bucketSize;
    this->rtssleaf = ratiotssleaf;
    PSbig = nullptr;
}

CutTSS::CutTSS(int threshold, int bucketSize, int ratiotssleaf) {
    this->threshold = { threshold, threshold, 0, 0, 0 };
    // this->threshold = threshold;
    this->binth = bucketSize;
    this->rtssleaf = ratiotssleaf;
    PSbig = nullptr;
}

void CutTSS::ConstructClassifier(const vector<Rule> &rules) {
    this->rules = rules;
    vector<pair<vector<Rule>, vector<int>>> subset = partition(threshold, ref(rules));
    for (int i = 0; i < subset.size(); i++) {
        printf("rule size: %d, threshold: ", subset[i].first.size());
        for (auto num : subset[i].second) {
            printf("%d ", num);
        }
        printf("\n");
    }
    statistics.resize(7, vector<int>(subset.size() - 1));
    memory.resize(3, vector<double>(subset.size() - 1));
    maxPri.resize(subset.size(), -1);

    for (int i = 0; i < subset.size(); i++) {
        statistics[numRules][i] = static_cast<int>(subset[i].first.size());
        nodeSet.push_back(ConstructCutTSSTrie(subset[i].first, subset[i].second, i));
        maxPri[i] = subset[i].first[0].priority;
    }
}


CutTSS::~CutTSS() {
    nodeSet.clear();
}

int CutTSS::ClassifyAPacket(const Packet &packet) {
    int matchPri = -1;
    uint64_t Query = 0;
    for (int i = nodeSet.size() - 1; i >= 0; i--) {
        if (matchPri < maxPri[i]) {
            matchPri = max(matchPri, trieLookup(packet, nodeSet[i], ref(Query)));
        }
    }
    return matchPri;
}

int CutTSS::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    int matchPri = -1;
    for (int i = nodeSet.size() - 1; i >= 0; i--) {
        if (matchPri < maxPri[i]) {
            matchPri = max(matchPri, trieLookup(packet, nodeSet[i], ref(Query)));
        }
    }
    return matchPri;
}

void CutTSS::DeleteRule(const Rule &delete_rule) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (delete_rule.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    trieDelete(delete_rule, nodeSet[assignments[loc]]);
}

void CutTSS::InsertRule(const Rule &insert_rule) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (insert_rule.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    trieInsert(insert_rule, nodeSet[assignments[loc]]);
}

Memory CutTSS::MemSizeBytes() const {
    uint32_t totMemory = 0;
    for (int i = 0; i < nodeSet.size(); i++) {
        totMemory += uint32_t(memory[totMem][i]);
    }
    if (PSbig) {
        totMemory += PSbig->MemSizeBytes();
    }
    return totMemory;
}

vector<pair<vector<Rule>, vector<int>>> CutTSS::partition(vector<int> threshold, const vector<Rule> &rules) {
    const int ARRAY_SIZE = 1 << threshold.size();

    vector<pair<vector<Rule>, vector<int>>> ret;
    vector<vector<Rule>> subRules(ARRAY_SIZE);
    for (const Rule &rule : rules) {
        int loc = 0;
        for (int dim = threshold.size() - 1; dim >= 0; dim--) {
            loc <<= 1;
            if (rule.prefix_length[dim] >= threshold[dim]) {
                loc++;
            }
        }
        subRules[loc].push_back(rule);
    }

    int cnt = 0;
    for (int i = 0; i < ARRAY_SIZE; i++) {
        if (!subRules[i].empty()) {
            vector<int> tmp;
            int t = i;
            for (int dim = 0; dim < threshold.size(); dim++) {
                if ((1 << dim) & i) {
                    tmp.push_back(threshold[dim]);
                } else {
                    tmp.push_back(0);
                }
            }
            ret.push_back({ subRules[i], tmp });
            assignments[i] = cnt++;
        }
    }

    return ret;
}

CutTSSNode* CutTSS::ConstructCutTSSTrie(const vector<Rule> &rules, const vector<int> &dims, int k) {
    vector<int> left(dims.size());

    CutTSSNode *root = new CutTSSNode(rules, left, 0, false, Cuts);
    statistics[totArray][k]++;

    queue<CutTSSNode *> qNode;
    qNode.push(root);
    while (!qNode.empty()) {
        auto *node = qNode.front();
        qNode.pop();
        if (node->nrules <= binth) {
            node->isLeaf = true;
            node->nodeType = Linear;

            statistics[totLeafRules][k] += node->nrules;
            statistics[totLeafNode][k]++;
            statistics[worstLevel][k] = max(statistics[worstLevel][k], node->depth);
            continue;
        }

        int cutDim = -1;
        int cutBits = -1;
        for (int i = 0; i < dims.size(); i++) {
            if (node->left[i] < dims[i]) {
                cutDim = i;
                cutBits = min(6, dims[i] - node->left[i]);
                break;
            }
        }

        // printf("rule size: %d\n", node->nrules);
        // printf("cutDim: %d\tcutBits:%d\n", cutDim, cutBits);

        // Cuts
        if (cutDim != -1) {
            node->cutDim = cutDim;
            node->andbit = (1 << cutBits) - 1;
            node->numbit = maxMask[cutDim] - node->left[cutDim] - cutBits;

            statistics[totNonLeafNode][k]++;

            vector<vector<Rule>> subRules(1 << cutBits);
            const int MOD = (1 << cutBits) - 1;

            vector<int> childLeft = node->left;
            childLeft[cutDim] += cutBits;
            for (Rule &rule : node->classifier) {
                uint32_t Key = rule.range[cutDim][LowDim] >> (maxMask[cutDim] - cutBits - node->left[cutDim]);
                // LOG_INFO("range:%d, offset: %d\n", rule.range[cutDim][LowDim], (maxMask[cutDim] - cutBits - node->left[cutDim]));
                subRules[Key & MOD].push_back(rule);
            }

            node->children.resize(subRules.size());
            for (int i = 0; i < subRules.size(); i++) {
                if (!subRules[i].empty()) {
                    node->children[i] = new CutTSSNode(subRules[i], childLeft, node->depth + 1, false, Cuts);
                    qNode.push(node->children[i]);
                }
            }
        } else { // TSS | linear
            node->isLeaf = true;
            PriorityTupleSpaceSearch ptmp;
            ptmp.ConstructClassifier(node->classifier);
            int numTuple = static_cast<int>(ptmp.NumTables());
            if (node->nrules <= rtssleaf * numTuple) {
                node->nodeType = Linear;

                statistics[totLeafRules][k] += node->nrules;
                statistics[totLeafNode][k]++;
                statistics[worstLevel][k] = max(statistics[worstLevel][k], node->depth);
            } else {
                node->nodeType = TSS;
                node->PSTSS = new PriorityTupleSpaceSearch();
                node->PSTSS->ConstructClassifier(node->classifier);

                memory[totTSSMem][k] += node->PSTSS->MemSizeBytes();
                statistics[totTSSNode][k] ++;
            }
        }
    }
    return root;
}

int CutTSS::trieLookup(const Packet &packet, CutTSSNode *root, uint64_t &Query) {
    int matchPri = -1;
    CutTSSNode *node = root;
    while (node && !node->isLeaf) {
        uint32_t key = (packet[node->cutDim] >> node->numbit) & node->andbit;
        node = node->children[key];
        Query++;
    }
    if (!node) {
        return -1;
    }
    if (node->nodeType == TSS) {
        return node->PSTSS->ClassifyAPacket(packet);
    } else {
        for (const Rule &rule : node->classifier) {
            Query++;
            if (rule.MatchesPacket(packet)) {
                return rule.priority;
            }
        }
    }
    return -1;
}

void CutTSS::trieDelete(const Rule &delete_rule, CutTSSNode *root) {
    CutTSSNode *node = root;
    while (node && !node->isLeaf) {
        uint32_t key = (delete_rule.range[node->cutDim][LowDim] >> node->numbit) & node->andbit;
        node = node->children[key];
    }
    if (node->nodeType == TSS) {
        return node->PSTSS->DeleteRule(delete_rule);
    } else {
        auto iter = lower_bound(node->classifier.begin(), node->classifier.end(), delete_rule);
        if (iter == node->classifier.end()) {
            // cout << "Not Found!" << endl;
            return;
        }
    }
}

void CutTSS::trieInsert(const Rule &insert_rule, CutTSSNode *root) {
    CutTSSNode *node = root;
    while (node && !node->isLeaf) {
        uint32_t key = (insert_rule.range[node->cutDim][LowDim] >> node->numbit) & node->andbit;
        node = node->children[key];
    }
    if (node->nodeType == TSS) {
        node->PSTSS->InsertRule(insert_rule);
    } else {
        node->classifier.push_back(insert_rule);
    }
}

size_t CutTSS::NumTables() const {
    int totTables = 0;
    for (int i = 0; i < subset.size(); i++) {
        if (!subset.empty()) {
            totTables++;
        }
    }
    return totTables;
}

void CutTSS::FindRule(const Rule r) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (r.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    printf("Tree: %d <---> %d\n", loc, assignments[loc]);
    CutTSSNode *node = nodeSet[assignments[loc]];
    while (node && !node->isLeaf) {
        uint32_t key = (r.range[node->cutDim][LowDim] >> node->numbit) & node->andbit;
        printf("key: %d %d %d %d\n", node->cutDim, node->numbit, node->andbit, key);
        node = node->children[key];
    }

    if (!node) {
        printf("node not exist!\n");
    } else if (node->nodeType == TSS) {
        printf("TSS node!\n");
    } else {
        printf("Linear node!\n");
    }
}

void CutTSS::FindPacket(const Packet p) {
    int matchPri = -1;
    for (int i = 0; i < nodeSet.size(); i++) {
        printf("Tree #%d:\n", i);
        int tmpPri = -1;
        if (matchPri < maxPri[i]) {
            auto *node = nodeSet[i];
            while (node && !node->isLeaf) {
                uint32_t key = (p[node->cutDim] >> node->numbit) & node->andbit;
                printf("key: %d %d %d %d\n", node->cutDim, node->numbit, node->andbit, key);
                node = node->children[key];
            }
            if (!node) {
                printf("not exists!\n");
            } else if (node->nodeType == TSS) {
                printf("TSS\n");
                tmpPri = node->PSTSS->ClassifyAPacket(p);
            } else {
                printf("Linear\n");
                for (const Rule &rule : node->classifier) {
                    if (rule.MatchesPacket(p)) {
                        tmpPri = rule.priority;
                    }
                }
            }
        }
        printf("Pri: %d --- %d\n", tmpPri, matchPri);
        matchPri = max(tmpPri, matchPri);
    }
}

size_t CutTSS::RulesInTable(size_t tableIndex) const {
    return 0;
}
