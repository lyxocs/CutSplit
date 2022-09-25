#ifndef CUTTSSV1_2_HYPERSPLIT_H
#define CUTTSSV1_2_HYPERSPLIT_H
#include "./../ElementaryClasses.h"
using namespace std;

struct hs_node{
    unsigned int		d2s;		/* dimension to split, 2bit is enough */
    unsigned int		depth;		/* tree depth of the node, x bits supports 2^(2^x) segments */
    unsigned int		thresh;		/* thresh value to split the current segments */
    unsigned int        num;        /* the num of rule in current node */
    bool isleaf;
    vector<Rule>        ruleset;
    struct hs_node*	child[2];	/* pointer to child-node, 2 for binary split */
    hs_node(unsigned int d2, unsigned int d, unsigned int t, bool leaf, const vector<Rule>& rules){
        d2s = d2;
        isleaf = leaf;
        depth = d;
        thresh = t;
        ruleset = rules;
        num = rules.size();
        child[0] = child[1] = nullptr;
    }
};


class HyperSplit : public PacketClassifier{
public:
    HyperSplit(uint64_t binth);
    virtual void ConstructClassifier(const std::vector<Rule> &rules);
    virtual int ClassifyAPacket(const Packet& packet);
    virtual int ClassifyAPacket(const Packet &packet, uint64_t &Query);

    virtual void DeleteRule(const Rule& rule);
    virtual void InsertRule(const Rule& rule);
    virtual Memory MemSizeBytes() const;
    virtual int MemoryAccess() const { return 0; }
    virtual size_t NumTables() const { return 0; }
    virtual size_t RulesInTable(size_t tableIndex) const { return 0;}
    hs_node* ConstructHSTree(const vector<Rule> &rules, int depth = 0);

    void prints() {
        Memory totMemory = MemSizeBytes();
        printf("\trules: %d\n", numRules);
        printf("\taverage depth: %lf\n", static_cast<double>(gAvgDepth) / static_cast<double>(totDuplicateRules));
        printf("\tSize(KB): %f\n", double(totMemory) / 1024.0);
        printf("\tByte / rule: %f\n", double(totMemory) / numRules);
    }

    void printInfo();


// private:
public:
    hs_node* root;
    uint64_t binth;

    int numRules;
    uint64_t gChildCount;
    uint64_t gNumTreeNode;
    uint64_t gNumLeafNode;
    uint64_t gWstDepth;
    uint64_t gAvgDepth;
    uint64_t gNumNonOverLappings[MAXDIMENSIONS];
    uint64_t gNumTotalNonOverlappings;
    int totDuplicateRules;
};

#endif //CUTTSSV1_2_HYPERSPLIT_H
