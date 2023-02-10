#ifndef HICUTS_H
#define HICUTS_H
#include "./../ElementaryClasses.h"

class hc_node {
public:
    int cutDim;
    int rangePerCut;
    std::vector<std::vector<uint32_t>> range;
    hc_node(const std::vector<Rule> &rules,
        std::vector<std::vector<uint32_t>> &r, int depth = 0) {
        this->rules = rules;
        isLeaf = false;
        range = r;
        this->depth = depth;
        cutDim = -1;
        rangePerCut = -1;
    }

// private:
    std::vector<Rule> rules;
    std::vector<hc_node*> children;
    int depth;
    int isLeaf;
};

class HiCuts : public PacketClassifier {
public:
    HiCuts(int binth, int maxCuts, double spfac = 4.0);
    void ConstructClassifier(const std::vector<Rule> &rules) override;
    int ClassifyAPacket(const Packet &packet) override;
    int ClassifyAPacket(const Packet &packet, uint64_t &Query) override;

    void DeleteRule(const Rule &rule) override;
    void InsertRule(const Rule &rule) override;
    Memory MemSizeBytes() const override;
    int MemoryAccess() const override;
    size_t NumTables() const override;
    size_t RulesInTable(size_t tableIndex) const override;

    void prints();

private:
    std::vector<hc_node*> ConstructSingleHiCutsNode(hc_node *node);

private:
    int binth;
    int maxCuts;
    double spfac; // space estimation

    hc_node *root;
};

#endif