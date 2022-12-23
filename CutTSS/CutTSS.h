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

#ifndef CUTTSS_H
#define CUTTSS_H
#include "../ElementaryClasses.h"
#include "../OVS/TupleSpaceSearch.h"

using namespace std;

#define MAXCUTS1 64  //keys for memory consumption
#define MAXCUTS2 8   //keys for memory consumption
#define MAXCUTBITS1 int(log(MAXCUTS1)/log(2))
#define ANDBITS1 (1<<MAXCUTBITS1) -1
#define MAXCUTBITS2 int(log(MAXCUTS2)/log(2))
#define ANDBITS2 (1<<MAXCUTBITS2) -1

struct CutTSSNode{
    vector<Rule> classifier;
    int nrules;
    int	depth;
	bool isLeaf;
    int nCuts;

    NodeType nodeType;
    int cutDim;
    int numbit;
    int andbit;

    vector<int> left;

    PriorityTupleSpaceSearch *PSTSS;
	vector<CutTSSNode*> children;

    CutTSSNode(const vector<Rule> &rules, vector<int> l, int level = 0,
            bool isleaf = false, NodeType flag = Cuts) {
        classifier = rules;
        nrules = static_cast<int>(rules.size());
        depth = level;
        isLeaf = isleaf;

        nodeType = flag;
        left = l;
    }
};


class CutTSS : public PacketClassifier {
public:
    CutTSS(std::string threshold = "1212000000", int bucketSize = 8, int ratiotssleaf = 5);
    CutTSS(int threshold = 12, int bucketSize = 8, int ratiotssleaf = 5);
	~CutTSS();
	void ConstructClassifier(const std::vector<Rule>& rules) override;
	int ClassifyAPacket(const Packet& packet) override;
    int ClassifyAPacket(const Packet &packet, uint64_t &Query);
    void DeleteRule(const Rule& delete_rule) override;
	void InsertRule(const Rule& insert_rule) override;
	Memory MemSizeBytes() const override;

    size_t NumTables() const;
    virtual size_t RulesInTable(size_t tableIndex) const;

// Priv
    CutTSSNode *ConstructCutTSSTrie(const vector<Rule> &rules, const vector<int> &dims, int k);
    // static vector<vector<Rule>> partition(vector<int> threshold, const vector<Rule> &rules);

    vector<pair<vector<Rule>, vector<int>>> partition(vector<int> threshold, const vector<Rule> &rules);
    // static vector<pair<vector<Rule>, vector<int> > partition(vector<int> threshold, const vector<Rule> &rules);
    static int trieLookup(const Packet &packet, CutTSSNode *root, uint64_t &Query);
    static void trieDelete(const Rule &delete_rule, CutTSSNode *root);
    static void trieInsert(const Rule &insert_rule, CutTSSNode *root);
    string FunName() {
        return "class: CutTSS";
    }

    void prints() {
        printf("\tRESULTS:");

        // for(int k = 0; k < nodeSet.size(); k++) {
        //     if(k == 0)
        //         printf("\n\t***SA Subset Tree(using FiCuts + PSTSS):***\n");
        //     if(k == 1)
        //         printf("\n\t***DA Subset Tree(using FiCuts + PSTSS):***\n");
        //     if(k == 2)
        //         printf("\n\t***SA_DA Subset Tree(using FiCuts + PSTSS):***\n");
        //     if(!nodeSet[k]) continue;

        //     memory[totFiCutsMem][k] = double(statistics[totLeafRules][k] * PTR_SIZE + statistics[totArray][k] * PTR_SIZE +
        //             statistics[totLeaNode][k] * LEAF_NODE_SIZE + statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
        //     memory[totTSSMem][k] = double(memory[totTSSMem][k]);
        //     memory[totMem][k] = memory[totFiCutsMem][k] + memory[totTSSMem][k];

        //     printf("\n\tnumber of rules:%d", statistics[numRules][k]);
        //     printf("\n\tnumber of rules in leaf nodes:%d", statistics[totLeafRules][k]);
        //     printf("\n\tnumber of rules in non-leaf terminal nodes(PSTSS nodes):%d", statistics[numRules][k] - statistics[totLeafRules][k]);
        //     printf("\n\tworst case tree level: %d", statistics[worstLevel][k]);

        //     printf("\n\t-------------------\n");
        //     printf("\tTotal_Rule_Size:%d\n", statistics[totLeafRules][k]);
        //     printf("\tLeaf_FiCuts_Node num:%d\n", statistics[totLeaNode][k]);
        //     printf("\tNonLeaf_FiCuts_Node num:%d\n", statistics[totNonLeafNode][k]);
        //     printf("\tTotal_Array_Size:%d\n", statistics[totArray][k]);
        //     printf("\truleptr_memory: %d\n", statistics[totLeafRules][k] * PTR_SIZE);
        //     printf("\tleaf_node_memory: %d\n", statistics[totLeaNode][k] * LEAF_NODE_SIZE);
        //     printf("\tNonLeaf_int_node_memory: %d\n", statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
        //     printf("\tarray_memory: %d\n", statistics[totArray][k] * PTR_SIZE);
        //     printf("\t-------------------\n");

        //     printf("\ttotal memory(Pre-Cutting): %f(KB)", memory[totFiCutsMem][k] / 1024.0);
        //     printf("\n\ttotal memory(Post_TSS): %f(KB)", memory[totTSSMem][k] / 1024.0);
        //     printf("\n\ttotal memory: %f(KB)", memory[totMem][k] / 1024.0);
        //     printf("\n\tByte/rule: %f", double(memory[totMem][k]) / statistics[numRules][k]);
        //     printf("\n\t-------------------\n");
        //     printf("\t***SUCCESS in building %d-th CutTSS sub-tree(1_sa, 2_da, 3_sa&da)***\n",k);
        // }
        // if(PSbig) {
        //     printf("\n\t***PSTSS for big ruleset:***\n");
        //     PSbig->prints();
        // }
	}

    // DEBUG
    void FindRule(const Rule r);
    void FindPacket(const Packet p);

private:
    std::vector<Rule> rules;
    int binth;
    std::vector<int> threshold;
    // std::vector<int> threshold;
    // int threshold;
    int rtssleaf;

    vector<int> maxMask = {32, 32, 16, 16, 8};
    vector<int> maxPri;
    vector<CutTSSNode*> nodeSet;
    PriorityTupleSpaceSearch *PSbig;

    enum statisticalType {numRules, totLeafRules, worstLevel, totArray, totLeafNode, totNonLeafNode, totTSSNode};
    enum memType {totFiCutsMem, totTSSMem, totMem};
    vector<vector<Rule> > subset;
    vector<vector<int> > statistics;
    vector<vector<double> > memory;

    unordered_map<int, int> assignments;

};

#endif

