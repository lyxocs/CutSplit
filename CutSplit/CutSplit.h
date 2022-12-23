#ifndef CUTTSSV1_2_CUTSPLIT_H
#define CUTTSSV1_2_CUTSPLIT_H

#include <utility>

#include "./../ElementaryClasses.h"
#include "./../HyperSplit/HyperSplit.h"

using namespace std;


struct CutSplitNode {
    vector<Rule> classifier;
    bool isLeaf;
    int nrules;
    int depth;
    NodeType nodeType; // (Cuts, Linear, TSS)
    int cutDim;
    int numbit;
    int andbit;
    vector<int> left;   // save the number of bits fetched

    vector<CutSplitNode*> children;
    HyperSplit *HSnode;

    CutSplitNode(const vector<Rule> &rules, vector<int> l, int level = 0,
            bool isleaf = false, NodeType flag = Cuts) {
        classifier = rules;
        nrules = static_cast<int>(rules.size());
        depth = level;
        isLeaf = isleaf;

        nodeType = flag;
        left = l;
    }
};


class CutSplit : public PacketClassifier {
public:
    CutSplit(std::string threshold = "1212000000", int bucketSize = 8);
    CutSplit(int bucketSize, int threshold);
    ~CutSplit();
    void ConstructClassifier(const std::vector<Rule> &rules) override;
    int ClassifyAPacket(const Packet& packet) override;
    int ClassifyAPacket(const Packet& packet, uint64_t& Query) override;
    void DeleteRule(const Rule& rule) override;
    void InsertRule(const Rule& rule) override;
    Memory MemSizeBytes() const override;
    int MemoryAccess() const override { return 0; }
    size_t NumTables() const;
    size_t RulesInTable(size_t tableIndex) const;

    //Priv

    CutSplitNode *ConstructCSTrie(const vector<Rule> &rules, const vector<int> &dims, int k);
    vector<pair<vector<Rule>, vector<int>>> partition(vector<int> threshold, const vector<Rule> &rules);
    // static vector<pair<vector<Rule>, vector<int> > partition(vector<int> threshold, const vector<Rule> &rules);
    static int trieLookup(const Packet &packet, CutSplitNode *root, uint64_t &Query);
    static void trieDelete(const Rule &delete_rule, CutSplitNode *root);
    static void trieInsert(const Rule &insert_rule, CutSplitNode *root);
    static int trieLookup(const Packet &packet, CutSplitNode *root, int speedUpFlag, uint64_t &Query);


    // DEBUG
    void FindRule(const Rule r);
    void FindPacket(const Packet p);

    void prints(){
        printf("\tRESULTS:");

        // for(int k = 0; k < nodeSet.size(); k++) {
        //     if(k == 0)
        //         printf("\n\t***SA Subset Tree(using FiCuts + HyperSplit):***\n");
        //     if(k == 1)
        //         printf("\n\t***DA Subset Tree(using FiCuts + HyperSplit):***\n");
        //     if(k == 2)
        //         printf("\n\t***SA_DA Subset Tree(using FiCuts + HyperSplit):***\n");
        //     if(!nodeSet[k]) continue;

        //     memory[totFiCutsMem][k] = double(statistics[totLeafRules][k] * PTR_SIZE + statistics[totArray][k] * PTR_SIZE +
        //                                      statistics[totLeaNode][k] * LEAF_NODE_SIZE + statistics[totNonLeafNode][k] * TREE_NODE_SIZE);
        //     memory[totTSSMem][k] = double(statistics[totTSSMem][k]);
        //     memory[totMem][k] = memory[totFiCutsMem][k] + memory[totTSSMem][k];

        //     printf("\n\tnumber of rules:%d", statistics[numRules][k]);
        //     printf("\n\tnumber of rules in leaf nodes:%d", statistics[totLeafRules][k]);
        //     printf("\n\tnumber of rules in non-leaf terminal nodes(HyperSplit nodes):%d", statistics[numRules][k] - statistics[totLeafRules][k]);
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
        // if(HSbig) {
        //     printf("\n\t***HyperSplit for big ruleset:***\n");
        //     HSbig->prints();
        // }
    }

private:
    std::vector<Rule> rules;
    int binth;
    std::vector<int> threshold;
    HyperSplit *HSbig;

    vector<int> maxMask = {32, 32, 16, 16, 8};
    vector<int> maxPri;
    vector<CutSplitNode*> nodeSet;

    enum statisticalType {numRules, totLeafRules, worstLevel, totArray, totLeafNode, totNonLeafNode, totTSSNode};
    enum memType {totFiCutsMem, totTSSMem, totMem};
    vector<vector<Rule> > subset;
    vector<vector<int> > statistics;
    vector<vector<double> > memory;

    unordered_map<int, int> assignments;
};

#endif //CUTTSSV1_2_CUTSPLIT_H
