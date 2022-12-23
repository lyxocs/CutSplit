#ifndef GRAPH_ANALYSE_H
#define GRAPH_ANALYSE_H

#include "../CutSplit/CutSplit.h"
#include "../CutTSS/CutTSS.h"

class GraphAnalyse: public PacketClassifier {
public:
    GraphAnalyse(string methods = "CutTSS");
    void ConstructClassifier(const std::vector<Rule> &rules);
    int ClassifyAPacket(const Packet &packet);
    int ClassifyAPacket(const Packet &packet, uint64_t &Query);
    void DeleteRule(const Rule &rule);
    void InsertRule(const Rule &rule);
    uint32_t MemSizeBytes() const;

    //useless
    virtual size_t NumTables() const;
    virtual size_t RulesInTable(size_t tableIndex) const;
    virtual std::string FunName() {
        return "Derived class: GraphAnalyse";
    }


private:
    PacketClassifier *fun;
    std::string methods;
};

#endif

