#include "HyperSplit.h"

HyperSplit::HyperSplit(uint64_t binth) {
    this->binth = binth;
    gChildCount = 0;
    gNumLeafNode = 0;
    gNumLeafNode = 0;
    gWstDepth = 0;
    gAvgDepth = 0;
    gNumTotalNonOverlappings = 0;
    gNumTreeNode = 0;
    totDuplicateRules = 0;
}

void HyperSplit::ConstructClassifier(const vector<Rule> &rules) {
    numRules = int(rules.size());
    root = ConstructHSTree(rules, 0);
}


int HyperSplit::ClassifyAPacket(const Packet &packet) {
    if(!root) {
        return -1;
    }
    hs_node *node = root;
    int Query = 0;
    int matchPri = -1;

    while(!node->isleaf) {
        Query ++;
        if(packet[node->d2s] <= node->thresh) {
            node = node->child[0];
        } else {
            node = node->child[1];
        }
    }
    for(auto & rule : node->ruleset) {
        Query ++;
        if(rule.MatchesPacket(packet)){
            matchPri = rule.priority;
            break;
        }
    }
    QueryUpdate(Query);
    return matchPri;
}

int HyperSplit::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    if(!root) {
        return -1;
    }
    hs_node *node = root;
    int matchPri = -1;

    while(!node->isleaf) {
        Query ++;
        if(packet[node->d2s] <= node->thresh) {
            node = node->child[0];
        } else {
            node = node->child[1];
        }
    }
    for(auto & rule : node->ruleset) {
        Query ++;
        if(rule.MatchesPacket(packet)){
            matchPri = rule.priority;
            break;
        }
    }
    return matchPri;
}


void HyperSplit::DeleteRule(const Rule &rule) {

}

void HyperSplit::InsertRule(const Rule &rule) {

}

hs_node *HyperSplit::ConstructHSTree(const vector<Rule> &rules, int depth) {
    if (rules.size() <= binth) {
        gChildCount ++;
        gNumLeafNode ++;
        gAvgDepth += rules.size() * depth;
        gWstDepth = max(gWstDepth, uint64_t (depth));
        totDuplicateRules += rules.size();
        auto *node = new hs_node(0, depth, 0, true, rules);
        return node;
    }

    /* generate segments for input filtset */
    unsigned int dim, num, pos;
    unsigned int maxDiffSegPts = 1;    /* maximum different segment points */
    unsigned int d2s = 0;        /* dimension to split (with max diffseg) */
    uint64_t thresh;
    unsigned int range[2][2];    /* sub-space ranges for child-nodes */

    vector<vector<uint64_t> > segPoints(MAXDIMENSIONS, vector<uint64_t>(rules.size() * 2, 0));
    vector<vector<uint64_t> > segPointsInfo(MAXDIMENSIONS, vector<uint64_t>(rules.size() * 2, 0));
    vector<uint64_t> tempSegPoints(2 * rules.size());
    double hightAvg, hightAll;
    vector<Rule> childRuleSet;

    for (dim = 0; dim < MAXDIMENSIONS; dim++) {
        for (num = 0; num < rules.size(); num++) {
            segPoints[dim][2 * num] = rules[num].range[dim][LowDim];
            segPoints[dim][2 * num + 1] = rules[num].range[dim][HighDim];
        }
    }

//    Sort the Segment Points
    for (dim = 0; dim < MAXDIMENSIONS; dim++) {
        sort(segPoints[dim].begin(), segPoints[dim].end());
    }

    /*Compress the Segment Points, and select the dimension to split (d2s)*/
    hightAvg = double(2 * rules.size() + 1);
    for (dim = 0; dim < MAXDIMENSIONS; dim++) {
        vector<uint64_t> hightList;
        uint64_t diffSegPts = 1;
        tempSegPoints[0] = segPoints[dim][0];
        for (num = 1; num < 2 * rules.size(); num++) {
            if (segPoints[dim][num] != tempSegPoints[diffSegPts - 1]) {
                tempSegPoints[diffSegPts] = segPoints[dim][num];
                diffSegPts++;
            }
        }
        /*Span the segment points which is both start and end of some rules*/
        pos = 0;
        for (num = 0; num < diffSegPts; num++) {
            int ifStart = 0, ifEnd = 0;
            segPoints[dim][pos] = tempSegPoints[num];
            for (const auto & rule : rules) {
                if (rule.range[dim][LowDim] == tempSegPoints[num]) {
                    ifStart = 1;
                    break;
                }
            }

            for (const auto & rule : rules) {
                if (rule.range[dim][HighDim] == tempSegPoints[num]) {
                    ifEnd = 1;
                    break;
                }
            }
            if (ifStart && ifEnd) {
                segPointsInfo[dim][pos] = 0;
                pos++;
                segPoints[dim][pos] = tempSegPoints[num];
                segPointsInfo[dim][pos] = 1;
                pos++;
            } else if (ifStart) {
                segPointsInfo[dim][pos] = 0;
                pos++;
            } else {
                segPointsInfo[dim][pos] = 1;
                pos++;
            }
        }

        /* now pos is the total number of points in the spanned segment point list */
        if (depth == 0) {
            gNumNonOverLappings[dim] = pos;
            gNumTotalNonOverlappings *= (uint64_t) pos;
        }

        if (pos >= 3) {
            hightAll = 0;
            hightList.resize(pos);
            for (int i = 0; i < pos - 1; i++) {
                hightList[i] = 0;
                for (const auto & rule : rules) {
                    if (rule.range[dim][LowDim] <= segPoints[dim][i] &&
                            rule.range[dim][HighDim] >= segPoints[dim][i + 1]) {
                        hightList[i]++;
                        hightAll++;
                    }
                }
            }

            if (hightAvg > hightAll / (pos - 1)) {
                double hightSum = 0;
                /* select current dimension */
                d2s = dim;
                hightAvg = hightAll / (pos - 1);

                /* the first segment MUST belong to the left child */
                hightSum += double(hightList[0]);
                for (num = 1; num < pos - 1; num++) {
                    if (segPointsInfo[d2s][num] == 0) {
                        thresh = segPoints[d2s][num] - 1;
                    } else {
                        thresh = segPoints[d2s][num];
                    }

                    if (hightSum > hightAll / 2) {
                        break;
                    }
                    hightSum += double(hightList[num]);
                }
                range[0][0] = segPoints[d2s][0];
                range[0][1] = thresh;
                range[1][0] = thresh + 1;
                range[1][1] = segPoints[d2s][pos - 1];

            }
        } // pos >=3
        if (maxDiffSegPts < pos) {
            maxDiffSegPts = pos;
        }
    }

    if (maxDiffSegPts <= 2) {
        auto *node = new hs_node(0, depth, 0, true, rules);
        gChildCount++;
        gNumLeafNode++;
        if (gNumLeafNode % 1000000 == 0)
            printf(".");
        if (gWstDepth < depth)
            gWstDepth = depth;
        gAvgDepth += rules.size() * depth;
        totDuplicateRules += rules.size();
        return node;
    }
    auto *node = new hs_node(d2s, depth, thresh, false, rules);
    gNumTreeNode ++;

//    Generate left child rule list

// children
    vector<Rule> leftRule, rightRule;
    for(const auto &rule : rules) {
        // left
//        bool leftFlag = true, rightFlag = true;
        if(rule.range[d2s][LowDim] <= range[0][HighDim] &&
            rule.range[d2s][HighDim] >= range[0][LowDim]) {
            Rule r = rule;
            r.range[d2s][LowDim] = max(r.range[d2s][LowDim], range[0][LowDim]);
            r.range[d2s][HighDim] = min(r.range[d2s][HighDim], range[0][HighDim]);
            leftRule.push_back(r);
        }
        // right
        if(rule.range[d2s][LowDim] <= range[1][HighDim] &&
            rule.range[d2s][HighDim] >= range[1][LowDim]) {
            Rule r = rule;
            r.range[d2s][LowDim] = max(r.range[d2s][LowDim], range[1][LowDim]);
            r.range[d2s][HighDim] = min(r.range[d2s][HighDim], range[1][HighDim]);
            rightRule.push_back(r);
        }
    }

    if(leftRule.size() == rules.size() || rightRule.size() == rules.size()) {
        node->isleaf = true;
        totDuplicateRules += rules.size();
        gChildCount ++;
        gNumLeafNode ++;
        if (gWstDepth < depth) {
            gWstDepth = depth;
        }
        gAvgDepth += rules.size() * depth;
        totDuplicateRules += rules.size();
        return node;
    }
    node->child[0] = ConstructHSTree(leftRule, depth + 1);
    node->child[1] = ConstructHSTree(rightRule, depth + 1);

    return node;
}

Memory HyperSplit::MemSizeBytes() const {
    Memory totMemory = gNumTreeNode * TREE_NODE_SIZE + gNumLeafNode * LEAF_NODE_SIZE + numRules * PTR_SIZE;
    return totMemory;
}

void HyperSplit::printInfo() {
    queue<hs_node*> que;
    que.push(root);
    int tot = 0;
    while(!que.empty()) {
        hs_node* node = que.front();
        que.pop();
        if (node->isleaf) {
            cout << node->depth << "\t" << node->num << endl;
            tot += node->depth * node->num;
            continue;
        }
        if (node->child[0]) {
            que.push(node->child[0]);
        }
        if (node->child[1]) {
            que.push(node->child[1]);
        }
    }
    cout <<" tot:" << tot << endl;

}