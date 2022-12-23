#include "CutSplit.h"

CutSplit::CutSplit(std::string threshold, int bucketSize) {
    for (int i = 0; i < threshold.size(); i += 2) {
        this->threshold.push_back(atoi(threshold.substr(i, 2).c_str()));
    }
    this->binth = bucketSize;
    HSbig = nullptr;
}

CutSplit::CutSplit(int bucketSize,int threshold) {
    this->threshold = { threshold, threshold, 0, 0, 0 };
    // this->threshold = threshold;
    this->binth = bucketSize;
    HSbig = nullptr;
}

void CutSplit::ConstructClassifier(const vector<Rule> &rules) {
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
        nodeSet.push_back(ConstructCSTrie(subset[i].first, subset[i].second, i));
        maxPri[i] = subset[i].first[0].priority;
    }
}


CutSplit::~CutSplit() {
    nodeSet.clear();
}

int CutSplit::ClassifyAPacket(const Packet &packet) {
    int matchPri = -1;
    uint64_t Query = 0;
    for (int i = nodeSet.size() - 1; i >= 0; i--) {
        if (matchPri < maxPri[i]) {
            matchPri = max(matchPri, trieLookup(packet, nodeSet[i], ref(Query)));
        }
    }
    return matchPri;
}

int CutSplit::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    int matchPri = -1;
    for (int i = nodeSet.size() - 1; i >= 0; i--) {
        if (matchPri < maxPri[i]) {
            matchPri = max(matchPri, trieLookup(packet, nodeSet[i], ref(Query)));
        }
    }
    return matchPri;
}

void CutSplit::DeleteRule(const Rule &delete_rule) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (delete_rule.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    trieDelete(delete_rule, nodeSet[assignments[loc]]);
}

void CutSplit::InsertRule(const Rule &insert_rule) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (insert_rule.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    trieInsert(insert_rule, nodeSet[assignments[loc]]);
}

Memory CutSplit::MemSizeBytes() const {
    uint32_t totMemory = 0;
    for (int i = 0; i < nodeSet.size(); i++) {
        totMemory += uint32_t(memory[totMem][i]);
    }
    if (HSbig) {
        totMemory += HSbig->MemSizeBytes();
    }
    return totMemory;
}

vector<pair<vector<Rule>, vector<int>>> CutSplit::partition(vector<int> threshold, const vector<Rule> &rules) {
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

CutSplitNode* CutSplit::ConstructCSTrie(const vector<Rule> &rules, const vector<int> &dims, int k) {
    vector<int> left(dims.size());

    CutSplitNode *root = new CutSplitNode(rules, left, 0, false, Cuts);
    statistics[totArray][k]++;

    queue<CutSplitNode *> qNode;
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
                    node->children[i] = new CutSplitNode(subRules[i], childLeft, node->depth + 1, false, Cuts);
                    qNode.push(node->children[i]);
                }
            }
        } else { // HyperSplit
            node->isLeaf = true;
            node->HSnode = new HyperSplit(binth);
            node->HSnode->ConstructClassifier(node->classifier);
            node->nodeType = HS;
            memory[totTSSMem][k] += node->HSnode->MemSizeBytes();
            statistics[totTSSNode][k] ++;
        }
    }
    return root;
}

int CutSplit::trieLookup(const Packet &packet, CutSplitNode *root, uint64_t &Query) {
    int matchPri = -1;
    CutSplitNode *node = root;
    while (node && !node->isLeaf) {
        uint32_t key = (packet[node->cutDim] >> node->numbit) & node->andbit;
        node = node->children[key];
        Query++;
    }
    if (!node) {
        return -1;
    }
    if (node->nodeType == HS) {
        return node->HSnode->ClassifyAPacket(packet);
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

void CutSplit::trieDelete(const Rule &delete_rule, CutSplitNode *root) {

}

void CutSplit::trieInsert(const Rule &insert_rule, CutSplitNode *root) {

}

size_t CutSplit::NumTables() const {
    return nodeSet.size();
}

void CutSplit::FindRule(const Rule r) {
    uint32_t loc = 0;
    for (int i = 0; i < threshold.size(); i++) {
        loc <<= 1;
        if (r.prefix_length[i] >= threshold[i]) {
            loc++;
        }
    }
    printf("Tree: %d <---> %d\n", loc, assignments[loc]);
    CutSplitNode *node = nodeSet[assignments[loc]];
    while (node && !node->isLeaf) {
        uint32_t key = (r.range[node->cutDim][LowDim] >> node->numbit) & node->andbit;
        printf("key: %d %d %d %d\n", node->cutDim, node->numbit, node->andbit, key);
        node = node->children[key];
    }

    if (!node) {
        printf("node not exist!\n");
    } else if (node->nodeType == HS) {
        printf("HS node!\n");
    } else {
        printf("Linear node!\n");
    }
}

void CutSplit::FindPacket(const Packet p) {
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
            } else if (node->nodeType == HS) {
                printf("HS\n");
                tmpPri = node->HSnode->ClassifyAPacket(p);
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

size_t CutSplit::RulesInTable(size_t tableIndex) const {
    return 0;
}

