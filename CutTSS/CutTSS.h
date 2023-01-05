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

#pragma once
#include "../ElementaryClasses.h"
#include "../OVS/TupleSpaceSearch.h"

using namespace std;

struct CutTSSNode{
    vector<Rule> classifier;
    int nrules;
    int	depth;
	bool isLeaf;

    NodeType nodeType;
    vector<int> ncuts;
    vector<int> numbit, andbit;

    vector<vector<unsigned int> > field;

    PriorityTupleSpaceSearch *PSTSS;
	vector<CutTSSNode*> children;


	CutTSSNode(const vector<Rule> &rules, vector<vector<unsigned int> > f, int level = 0,
               bool isleaf = false, NodeType flag = Cuts) {
	    classifier = rules;
	    nrules = int(rules.size());
        depth = level;
        isLeaf = isleaf;

        nodeType = flag;
        ncuts.resize(MAXDIMENSIONS, 1);
        numbit.resize(MAXDIMENSIONS);
        andbit.resize(MAXDIMENSIONS);
	    field = std::move(f);
	    PSTSS = nullptr;
	}
 };


class CutTSS : public PacketClassifier {
public:
    CutTSS(int SIP_Threshold = 12, int DIP_Threshold = 12, int bucketSize = 8, int ratiotssleaf = 5);
	~CutTSS();
    void ConstructClassifier(const std::vector<Rule>& rules) override;
	int ClassifyAPacket(const Packet& packet) override;
    int ClassifyAPacket(const Packet &packet, uint64_t &Query) override;
    void DeleteRule(const Rule& delete_rule) override;
	void InsertRule(const Rule& insert_rule) override;
	Memory MemSizeBytes() const override;
	size_t NumTables() const override;
	size_t RulesInTable(size_t tableIndex) const override { return rules.size(); }

    static void CalcCutsn(CutTSSNode *node, const vector<int>& dims) ;
    CutTSSNode* ConstructCutTSSTrie(const vector<Rule> &rules, const vector<int>& dims, int k);
    static vector<vector<Rule>> partition(vector<vector<int>> Thre, const vector<Rule> &rules);
    static int trieLookup(const Packet &packet, CutTSSNode *root, int speedUpFlag, uint64_t &Query);
    static void trieDelete(const Rule &delete_rule, CutTSSNode *root, int speedUpFlag);
    static void trieInsert(const Rule &insert_rule, CutTSSNode *root, int speedUpFlag);


    void prints(){
        printf("\tRESULTS:");

        for(int k = 0; k < nodeSet.size(); k++) {
            if(k == 0)
                printf("\n\t***SA Subset Tree(using FiCuts + PSTSS):***\n");
            if(k == 1)
                printf("\n\t***DA Subset Tree(using FiCuts + PSTSS):***\n");
            if(k == 2)
                printf("\n\t***SA_DA Subset Tree(using FiCuts + PSTSS):***\n");
            if(!nodeSet[k]) continue;

            memory[totFiCutsMem][k] = double(statistics[totLeafRules][k] * PTR_SIZE + statistics[totArray][k] * PTR_SIZE +
                    statistics[totLeaNode][k] * LEAF_NODE_SIZE + statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
            memory[totTSSMem][k] = double(memory[totTSSMem][k]);
            memory[totMem][k] = memory[totFiCutsMem][k] + memory[totTSSMem][k];

            printf("\n\tnumber of rules:%d", statistics[numRules][k]);
            printf("\n\tnumber of rules in leaf nodes:%d", statistics[totLeafRules][k]);
            printf("\n\tnumber of rules in non-leaf terminal nodes(PSTSS nodes):%d", statistics[numRules][k] - statistics[totLeafRules][k]);
            printf("\n\tworst case tree level: %d", statistics[worstLevel][k]);

            printf("\n\t-------------------\n");
            printf("\tTotal_Rule_Size:%d\n", statistics[totLeafRules][k]);
            printf("\tLeaf_FiCuts_Node num:%d\n", statistics[totLeaNode][k]);
            printf("\tNonLeaf_FiCuts_Node num:%d\n", statistics[totNonLeafNode][k]);
            printf("\tTotal_Array_Size:%d\n", statistics[totArray][k]);
            printf("\truleptr_memory: %d\n", statistics[totLeafRules][k] * PTR_SIZE);
            printf("\tleaf_node_memory: %d\n", statistics[totLeaNode][k] * LEAF_NODE_SIZE);
            printf("\tNonLeaf_int_node_memory: %d\n", statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
            printf("\tarray_memory: %d\n", statistics[totArray][k] * PTR_SIZE);
            printf("\t-------------------\n");

            printf("\ttotal memory(Pre-Cutting): %f(KB)", memory[totFiCutsMem][k] / 1024.0);
            printf("\n\ttotal memory(Post_TSS): %f(KB)", memory[totTSSMem][k] / 1024.0);
            printf("\n\ttotal memory: %f(KB)", memory[totMem][k] / 1024.0);
            printf("\n\tByte/rule: %f", double(memory[totMem][k]) / statistics[numRules][k]);
            printf("\n\t-------------------\n");
            printf("\t***SUCCESS in building %d-th CutTSS sub-tree(1_sa, 2_da, 3_sa&da)***\n",k);
        }
        if(PSbig) {
            printf("\n\t***PSTSS for big ruleset:***\n");
            PSbig->prints();
        }
	}


private:
    std::vector<Rule> rules;
    int binth;
    int SIP_Threshold;
    int DIP_Threshold;
    int rtssleaf;

    vector<int> maxMask = {32, 32, 16, 16, 8};
    vector<int> maxPri;
    vector<CutTSSNode*> nodeSet;
    PriorityTupleSpaceSearch *PSbig;

    enum statisticalType {numRules, totLeafRules, worstLevel, totArray, totLeaNode, totNonLeafNode, totTSSNode};
    enum memType {totFiCutsMem, totTSSMem, totMem};
    vector<vector<Rule> > subset;
    vector<vector<int> > statistics;
    vector<vector<double> > memory;

};
