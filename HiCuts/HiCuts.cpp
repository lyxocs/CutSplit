#include "HiCuts.h"
#include <queue>
#include <set>
using namespace std;

HiCuts::HiCuts(int binth, int maxCuts, double spfac) {
    this->binth = binth;
    this->maxCuts = maxCuts;
    this->spfac = spfac;
}

void HiCuts::ConstructClassifier(const std::vector<Rule> &rules) {
    queue<hc_node*> que;
    vector<vector<uint32_t>> allRange = {{0, UINT32_MAX}, {0, UINT32_MAX}, {0, UINT16_MAX}, {0, UINT16_MAX}, {0, UINT8_MAX}};
    root = new hc_node(rules, allRange);

    que.push(root);
    while (!que.empty()) {
        hc_node *node = que.front();
        que.pop();
        vector<hc_node*> children = ConstructSingleHiCutsNode(node);
        for (auto iter : children) {
            if (iter && !iter->isLeaf) {
                que.push(iter);
            }
        }
    }
}

int HiCuts::ClassifyAPacket(const Packet &packet) {
    hc_node *node = root;
    while (node && !node->isLeaf) {
        int loc = (packet[node->cutDim] - node->range[node->cutDim][LowDim]) / node->rangePerCut;
        // cout << node->children.size() << "\t" << loc << endl;
        node = node->children[loc];
    }
    if (!node) {
        return -1;
    }
    for (const Rule &rule : node->rules) {
        if (rule.MatchesPacket(packet)) {
            return rule.priority;
        }
    }
    return -1;
}

int HiCuts::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    hc_node *node = root;
    while (node && !node->isLeaf) {
        int loc = (packet[node->cutDim] - node->range[node->cutDim][LowDim]) / node->rangePerCut;
        // cout << node->children.size() << "\t" << loc << endl;
        node = node->children[loc];
    }
    if (!node) {
        return -1;
    }
    for (const Rule &rule : node->rules) {
        if (rule.MatchesPacket(packet)) {
            return rule.priority;
        }
    }
    return -1;
}

void HiCuts::DeleteRule(const Rule &rule) {

}

void HiCuts::InsertRule(const Rule &rule) {

}

Memory HiCuts::MemSizeBytes() const {
    return 0;
}

int HiCuts::MemoryAccess() const {
    return 0;
}

size_t HiCuts::NumTables() const {
    return 0;
}

size_t HiCuts::RulesInTable(size_t tableIndex) const {
    return 0;
}

vector<hc_node*> HiCuts::ConstructSingleHiCutsNode(hc_node *node) {
    if (static_cast<int>(node->rules.size()) <= binth) {
        node->isLeaf = true;
        return {};
    }
    // cout << node->depth << "\t" << node->rules.size() << endl;
    vector<hc_node*> children;

    // Select Cut-Dim with max distinct point using heuristic algorithm
    int cutDim = SIP;
    size_t maxDistinctComponents = 0;
    for (int dim = 0; dim < MAXDIMENSIONS; dim++) {
        set<pair<int, int>> Set;
        for (const Rule &rule : node->rules) {
            uint32_t left = max(rule.range[dim][LowDim], node->range[dim][LowDim]);
            uint32_t right = min(rule.range[dim][HighDim], node->range[dim][HighDim]);
            Set.insert({left, right});
        }
        if (Set.size() > maxDistinctComponents) {
            maxDistinctComponents = Set.size();
            cutDim = dim;
        }
    }

    // Compute the number of cuts
    uint64_t rangeLeft = node->range[cutDim][LowDim];
    uint64_t rangeRight = node->range[cutDim][HighDim];
    
    uint32_t cutNum = min(static_cast<uint64_t>(2), rangeRight - rangeLeft);
    // fprintf(stdout, "range left: %lld, range right: %lld\n", rangeLeft, rangeRight);
    while (true) {
        int sm_C = cutNum;
        int rangePerCut = ceil(static_cast<double>(rangeRight - rangeLeft + 1) / static_cast<double>(cutNum));
        for (const Rule &rule : node->rules) {
            uint64_t ruleRangeLeft = max(static_cast<uint64_t>(rule.range[cutDim][LowDim]), rangeLeft);
            uint64_t ruleRangeRight = min(static_cast<uint64_t>(rule.range[cutDim][HighDim]), rangeRight);
            
            sm_C += (ruleRangeRight - rangeLeft - 1) / rangePerCut -
                            (ruleRangeLeft - rangeLeft) / rangePerCut + 1;
        }
        if (sm_C < spfac * node->rules.size() && cutNum * 2 <= rangeRight - rangeLeft) {
            cutNum <<= 1;
        } else {
            break;
        }
    }
    if (cutNum == 1) {
        node->isLeaf = true;
        return {};
    }

    // cutNum == 1

    // cut node
    int rangePerCut = ceil(static_cast<double>(rangeRight - rangeLeft) / static_cast<double>(cutNum));
    children.resize(cutNum, nullptr);
    for (int i = 0; i < cutNum; i++) {
        vector<vector<uint32_t>> childRanges = node->range;
        childRanges[cutDim][LowDim] = rangeLeft + i * rangePerCut;
        childRanges[cutDim][HighDim] = min(rangeRight, rangeLeft + (i + 1) * rangePerCut);

        vector<Rule> childRules;
        for (const Rule &rule : node->rules) {
            if (rule.range[cutDim][HighDim] < childRanges[cutDim][LowDim] ||
                rule.range[cutDim][LowDim] > childRanges[cutDim][HighDim]) {
                    continue;
            } else {
                childRules.push_back(rule);
            }
        }
        if (!childRules.empty()) {
            children[i] = new hc_node(childRules, childRanges, node->depth + 1);
            if (childRules.size() == node->rules.size()) {
                children[i]->isLeaf = true;
            }
        }
        // update tree
    }
    // cout << "depth: " << node->depth << "\trule size: " << node->rules.size() << endl;
    // for (auto iter : children) {
    //     if (iter) {
    //         cout << iter->rules.size() << "  ";
    //     } else {
    //         cout << "0  ";
    //     }
    // }
    // cout << endl;
    node->cutDim = cutDim;
    node->rangePerCut = rangePerCut;
    node->children = children;

    return children;
}
