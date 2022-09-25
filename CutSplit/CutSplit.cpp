#include "CutSplit.h"

CutSplit::CutSplit(int bucketSize, int threshold) {
    this->binth = bucketSize;
    this->threshold = threshold;
    HSbig = nullptr;

    statistics.resize(7, vector<int>(3));
    memory.resize(3, vector<double>(3));
}

void CutSplit::ConstructClassifier(const vector<Rule> &rules) {
    vector<vector<int> > Thre(3);
    Thre[0] = {threshold, threshold, -1, -1, -1};
    Thre[1] = {threshold, -1, -1, -1, -1};
    Thre[2] = {-1, threshold, -1, -1, -1};

    subset = partition(Thre, rules);
    nodeSet.resize(3, nullptr);
    maxPri.resize(4, -1);
    for(int i = 0; i < nodeSet.size(); i++) {
        if(subset[i].empty()) continue;
        statistics[numRules][i] = int(subset[i].size());
        nodeSet[i] = ConstructCSTrie(subset[i], Thre[i], i);
        maxPri[i] = subset[i][0].priority;
    }
    if(!subset.back().empty()) {
        HSbig = new HyperSplit(binth);
        HSbig->ConstructClassifier(subset.back());
        maxPri.back() = subset.back()[0].priority;
    }
}

int CutSplit::ClassifyAPacket(const Packet &packet) {
    int matchPri = -1;
    uint64_t Query = 0;
    if(nodeSet[0]) matchPri = trieLookup(packet, nodeSet[0], 3, Query);
    if(nodeSet[1] && maxPri[1] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[1], 1, Query));
    if(nodeSet[2] && maxPri[2] > matchPri) matchPri = max(matchPri, trieLookup(packet, nodeSet[2], 2, Query));
    if(HSbig && maxPri[3] > matchPri) matchPri = max(matchPri, HSbig->ClassifyAPacket(packet, Query));
    QueryUpdate(Query);
    return matchPri;
}

int CutSplit::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    int matchPri = -1;
    if(nodeSet[0]) matchPri = trieLookup(packet, nodeSet[0], 3, Query);
    if(nodeSet[1] && maxPri[1] > matchPri) matchPri = trieLookup(packet, nodeSet[1], 1, Query);
    if(nodeSet[2] && maxPri[2] > matchPri) matchPri = trieLookup(packet, nodeSet[2], 2, Query);
    if(HSbig && maxPri[3] > matchPri) matchPri = HSbig->ClassifyAPacket(packet, Query);
    QueryUpdate(Query);
    return matchPri;
}

void CutSplit::DeleteRule(const Rule &rule) {

}

void CutSplit::InsertRule(const Rule &rule) {

}

Memory CutSplit::MemSizeBytes() const {
    uint32_t totMemory = 0;
    for(int i = 0; i < nodeSet.size(); i++) {
        totMemory += uint32_t(memory[totMem][i]);
    }
    if(HSbig) {
        totMemory += HSbig->MemSizeBytes();
    }
    return totMemory;
}


CutSplitNode *CutSplit::ConstructCSTrie(const vector<Rule> &rules, const vector<int>& dims, int k) {

    int maxCuts = 0;
    for(int d : dims) {
        if(d != -1) maxCuts ++;
    }
    maxCuts = maxCuts == 1 ? 64 : 8;
    vector<vector<unsigned int> > field(MAXDIMENSIONS, vector<unsigned int>(2));
    for(int dim = 0; dim < MAXDIMENSIONS; dim++){
        field[dim][HighDim] = (uint64_t(1) << MaxMask[dim]) - 1;
    }

    auto *root = new CutSplitNode(rules,field, 0, false, Cuts);
    statistics[totArray][k] ++;

    queue<CutSplitNode*> qNode;
    qNode.push(root);
    while(!qNode.empty()) {
        CutSplitNode *node = qNode.front();
        qNode.pop();
        if(node->nrules <= binth) { // Linear leaf node
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
            field[0][HighDim] = field[0][LowDim] + r[0];
            for(i[0] = 0; i[0] < node->ncuts[0]; i[0]++) {  //sip

                r[1] = (node->field[1][HighDim] - node->field[1][LowDim]) / node->ncuts[1];
                field[1][LowDim] = node->field[1][LowDim];
                field[1][HighDim] = field[1][LowDim] + r[1];
                for(i[1] = 0; i[1] < node->ncuts[1]; i[1]++) {  //dip

                    r[2] = (node->field[2][HighDim] - node->field[2][LowDim]) / node->ncuts[2];
                    field[2][LowDim] = node->field[2][LowDim];
                    field[2][HighDim] = field[2][LowDim] + r[2];
                    for(i[2] = 0; i[2] < node->ncuts[2]; i[2] ++) {

                        r[3] = (node->field[3][HighDim] - node->field[3][LowDim]) / node->ncuts[3];
                        field[3][LowDim] = node->field[3][LowDim];
                        field[3][HighDim] = field[3][LowDim] + r[3];
                        for(i[3] = 0; i[3] < node->ncuts[3]; i[3] ++) {

                            r[4] = (node->field[4][HighDim] - node->field[4][LowDim]) / node->ncuts[4];
                            field[4][LowDim] = node->field[4][LowDim];
                            field[4][HighDim] = field[4][LowDim] + r[4];
                            for(i[4] = 0; i[4] < node->ncuts[4]; i[4] ++) {

                                vector<Rule> subRule;
                                for(const Rule &rule : node->rules) {
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
                                    node->children[index] = new CutSplitNode(subRule, field, node->depth + 1, false, Cuts);
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
//            node->rules.clear();
        } else {    // HyperSplit stage
            node->HSnode = new HyperSplit(binth);
            node->HSnode->ConstructClassifier(node->rules);
            node->isLeaf = true;

            memory[totTSSMem][k] += node->HSnode->MemSizeBytes();
            statistics[totTSSNode][k] ++;
//            node->rules.clear();
        }

    }
    return root;
}

void CutSplit::CalcCutsn(CutSplitNode *node, const vector<int>& dims) const {
    int maxCuts = 0;
    for(int d : dims) {
        if(d != -1) maxCuts ++;
    }
    maxCuts = maxCuts == 1 ? 64 : 8;

    for(int dim = 0; dim < MAXDIMENSIONS; dim++) {
        node->ncuts[dim] = 1;
        if(dims[dim] != -1) {
            while(true) {
                if(node->ncuts[dim] < maxCuts && (node->field[dim][HighDim] - node->field[dim][LowDim]) > pow(2, MaxMask[dim] - threshold)) {
                    node->ncuts[dim] <<= 1;
                } else {
                    break;
                }
            }
        }
    }
}

int CutSplit::trieLookup(const Packet &packet, CutSplitNode *root, int speedUpFlag, uint64_t &Query) {
    int matchPri = -1;
    CutSplitNode* node = root;
    unsigned int numbit = 32;
    unsigned int cchild;

    switch (speedUpFlag) {
        case 1: {
            while(node && !node->isLeaf) {
                numbit -= MAXCUTBITS1;
                cchild = (packet[0] >> numbit) & ANDBITS1;
                node = node->children[cchild];
                Query++;
            }
            break;
        }
        case 2: {
            while (node && !node->isLeaf) {
                numbit -= MAXCUTBITS1;
                cchild = (packet[1] >> numbit) & ANDBITS1;
                node = node->children[cchild];
                Query++;
            }
            break;
        }
        case 3: {
            while(node && !node->isLeaf) {
                numbit -= MAXCUTBITS2;
                cchild = ((packet[0] >> numbit) & ANDBITS2) * node->ncuts[1] + ((packet[1] >> numbit) & ANDBITS2);
                node = node->children[cchild];
                Query++;
            }
        }
        default:
            break;
    }
    if(!node) {
        return -1;
    }
    if(node->nodeType == TSS) {
        matchPri = node->HSnode->ClassifyAPacket(packet, Query);
    } else {
        for(const Rule &rule : node->rules) {
            Query++;
            if(rule.MatchesPacket(packet)) {
                matchPri = rule.priority;
                break;
            }
        }
    }

    return matchPri;
}

vector<vector<Rule> > CutSplit::partition(vector<vector<int> > threshold, const vector<Rule>& rules) {
    int n = int(threshold.size());
    std::vector<std::vector<Rule> > subset(n + 1);
    for (const Rule &rule : rules) {
        bool flag = false;
        for(int i = 0; i < n; i++) {
            bool insertFlag = true;
            for (int dim = 0; dim < MAXDIMENSIONS; dim++) {
                if(threshold[i][dim] == -1) continue;
                if(rule.prefix_length[dim] < threshold[i][dim]) {
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
