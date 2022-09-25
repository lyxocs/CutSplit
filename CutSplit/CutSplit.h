#ifndef CUTTSSV1_2_CUTSPLIT_H
#define CUTTSSV1_2_CUTSPLIT_H

#include <utility>

#include "./../ElementaryClasses.h"
#include "./../HyperSplit/HyperSplit.h"

using namespace std;


struct CutSplitNode {
    bool isLeaf;
    int nrules;
    int depth;
    int nodeType; // (Cuts, Linear, TSS)

    vector<Rule> rules;
    vector<int> ncuts;
    vector<vector<unsigned int> > field;
    HyperSplit *HSnode;

    vector<CutSplitNode*> children;
    explicit CutSplitNode(const vector<Rule> &r, vector<vector<unsigned int> > f, int level = 0, bool isleaf = true, NodeType flag = Cuts) {
        depth = level;
        isLeaf = isleaf;
        nodeType = flag;
        field = std::move(f);
        ncuts.resize(MAXDIMENSIONS, 1);
        rules = r;
        nrules = int(r.size());
        HSnode = nullptr;

//        field[LowDim].resize(MAXDIMENSIONS);
//        field[HighDim].resize(MAXDIMENSIONS);
    }
};


class CutSplit : public PacketClassifier {
public:
    CutSplit(int bucketSize, int threshold);
    void ConstructClassifier(const std::vector<Rule> &rules) override;
    int ClassifyAPacket(const Packet& packet) override;
    int ClassifyAPacket(const Packet& packet, uint64_t& Query) override;
    void DeleteRule(const Rule& rule) override;
    void InsertRule(const Rule& rule) override;
    Memory MemSizeBytes() const override;
    int MemoryAccess() const override { return 0; }
    size_t NumTables() const override { return 0; }
    size_t RulesInTable(size_t tableIndex) const override { return 0;}
    CutSplitNode* ConstructCSTrie(const vector<Rule> &rules, const vector<int>& dims, int k);
    static int trieLookup(const Packet &packet, CutSplitNode *root, int speedUpFlag, uint64_t &Query);
    void CalcCutsn(CutSplitNode* node, const vector<int>& dim) const;
    static vector<vector<Rule> > partition(vector<vector<int> > threshold, const vector<Rule>& rules);


    void prints(){
        printf("\tRESULTS:");

        for(int k = 0; k < nodeSet.size(); k++) {
            if(k == 0)
                printf("\n\t***SA Subset Tree(using FiCuts + HyperSplit):***\n");
            if(k == 1)
                printf("\n\t***DA Subset Tree(using FiCuts + HyperSplit):***\n");
            if(k == 2)
                printf("\n\t***SA_DA Subset Tree(using FiCuts + HyperSplit):***\n");
            if(!nodeSet[k]) continue;

            memory[totFiCutsMem][k] = double(statistics[totLeafRules][k] * PTR_SIZE + statistics[totArray][k] * PTR_SIZE +
                                             statistics[totLeaNode][k] * LEAF_NODE_SIZE + statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
            memory[totTSSMem][k] = double(statistics[totTSSMem][k]);
            memory[totMem][k] = memory[totFiCutsMem][k] + memory[totTSSMem][k];

            printf("\n\tnumber of rules:%d", statistics[numRules][k]);
            printf("\n\tnumber of rules in leaf nodes:%d", statistics[totLeafRules][k]);
            printf("\n\tnumber of rules in non-leaf terminal nodes(HyperSplit nodes):%d", statistics[numRules][k] - statistics[totLeafRules][k]);
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
        if(HSbig) {
            printf("\n\t***HyperSplit for big ruleset:***\n");
            HSbig->prints();
        }
    }

private:

    int binth;
    vector<CutSplitNode*> nodeSet;
    vector<int> maxPri;
    HyperSplit *HSbig;
    int threshold;

    vector<int> MaxMask = {32, 32, 16, 16, 8};


    enum statisticalType {numRules, totLeafRules, worstLevel, totArray, totLeaNode, totNonLeafNode, totTSSNode};
    enum memType {totFiCutsMem, totTSSMem, totMem};
    vector<vector<Rule> > subset;
    vector<vector<int> > statistics;
    vector<vector<double> > memory;
};

#endif //CUTTSSV1_2_CUTSPLIT_H
