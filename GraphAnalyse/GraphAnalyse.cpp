#include <math.h>
#include <limits.h>
#include "GraphAnalyse.h"
#include <numeric>


using namespace std;

struct partition_structure {
    int numInter;
    vector<int> value_counts;
    double QH;
    double QRandom;
    double QTrace;
};

static partition_structure PartitionBenchmarkQ5(vector<tuple<int, int, double>> &edgeList, const vector<Rule> &rules,
    int threshold) {
    partition_structure ret;
    vector<int> ruleLabel(rules.size());

    unordered_map<int, int> mp; // label hash
    int cnt = 0;

    // relabel
    for (int i = 0; i < rules.size(); i++) {
        int label = 0;
        int currentDIM = 0;
        // SIP & DIP
        for (int dim = 0; dim < 2; dim++) {
            if (rules[i].prefix_length[dim] >= threshold) {
                label += 1<<currentDIM;
            }
            currentDIM++;
        }

        // SP & DP
        if (rules[i].prefix_length[SP] >= 00) {
            label += 1<<currentDIM;
        }
        currentDIM++;

        if (rules[i].prefix_length[DP] >= 00) {
            label += 1<<currentDIM;
        }
        currentDIM++;

        // Proto
        if (rules[i].prefix_length[PROTO] >= 00) {
            label += 1<<currentDIM;
        }
        currentDIM++;

        ruleLabel[i] = label;
        if (!mp.count(label)) {
            mp[label] = cnt++;               //wjs not verified.
        }
    }


    vector<vector<double>> num_e(cnt, vector<double>(cnt, 0));

    for (int i = 0; i < edgeList.size(); i++) {
        int label1 = mp[ruleLabel[get<0>(edgeList[i])]];
        int label2 = mp[ruleLabel[get<1>(edgeList[i])]];
        if (label1 != label2) {
            num_e[label1][label2] += get<2>(edgeList[i]);
            num_e[label2][label1] += get<2>(edgeList[i]);  //interchange label1 with label2.
        } else {
            num_e[label1][label2] += get<2>(edgeList[i]);
        }
    }

    vector<vector<double>> D(cnt, vector<double>(cnt, 0));
    vector<vector<double>> E(cnt, vector<double>(cnt, 0));
    D = num_e;
    E = num_e;
    int64_t cntD = 0, cntE = 0;
    for (int i = 0; i < cnt; i++) {
        for (int j = 0; j < cnt; j++) {
            if (i == j) {
                E[i][j] = 0;
                cntD += D[i][j];
            } else {
                D[i][j] = 0;
                cntE += E[i][j];
            }
        }
    }

    vector<vector<double>> e(cnt, vector<double>(cnt, 0));
    e = num_e;
    int64_t totalW = (cntE >> 1) + cntD;                          //wjs-- ">> 1" equivalently divided by 2.

    for (int i = 0; i < cnt; i++) {
        for (int j = 0; j < cnt; j++) {
            if (i == j) {
                e[i][j] /= static_cast<double>(totalW);
            } else {
                e[i][j] /= (2.0 * static_cast<double>(totalW));   //wjs-- add an braket
            }
        }
    }

    ret.numInter = 0;
    ret.QRandom = 0.0;
    ret.QTrace = 0.0;
    for (int i = 0; i < cnt; i++) {
        ret.numInter += num_e[i][i];
    }
    vector<vector<double>> Q(cnt, vector<double>(cnt, 0));
    for (int i = 0; i < cnt; i++) {
        for (int j = 0; j < cnt; j++) {
            double tmp = 0;
            for (int k = 0; k < cnt; k++) {
                tmp += e[i][k] * e[k][j];
            }
            Q[i][j] = tmp;
            ret.QRandom += tmp;
            if (i == j) {
                ret.QTrace += e[i][j];
            }
        }
    }
    ret.QH = ret.QRandom - ret.QTrace;
    return ret;
}

double range_intersection(std::array<Point, 2> Range1, std::array<Point, 2> Range2) {
    uint64_t l1 = Range1[0],r1 = Range1[1];
    uint64_t l2 = Range2[0],r2 = Range2[1];
    vector<uint64_t> Range3(2,0);
    int flag = 0;
    if (l1>l2) { //change sort of two ranges.
        uint64_t temp1 = l1;
        uint64_t temp2 = r1;
        l1 = l2; r1 = r2;
        l2 = temp1; r2 = temp2;
    }
    if (l2<=r1){
        Range3[0] = l2;
        Range3[1] = min(r1,r2);
        flag = 1;
    }
    else {
        flag = -1;  //overlap is empty.
    }
    if (flag == 1) {
        return log2(Range3[1] - Range3[0] + 2.0); //when overlap, the information is at least 1 bit.
    }
    else if ((flag == -1))
        return 0;
}

GraphAnalyse::GraphAnalyse(int bucketSize, int ratiotssleaf, string methods) {
    this->bucketSize = bucketSize;
    this->rtssleaf = ratiotssleaf;
    this->methods = methods;
}

void GraphAnalyse::ConstructClassifier(const vector<Rule> &rules) {
    vector<tuple<int, int, double>> edgeList;
    for (int i = 1; i < rules.size(); i++) {
        for (int j = 0; j < i; j++) {
            vector<double> OverlapArea(2,0);   //change 2 to MAXDIMENSIONS will get 5 Fields.
            for (int k = 0; k < 2; k++) {
                OverlapArea[k] = range_intersection(rules[i].range[k],rules[j].range[k]);
            }
            double minOverlapLength = *min_element(OverlapArea.begin(),OverlapArea.end());
            //double minOverlapLength = accumulate(OverlapArea.begin(), OverlapArea.end(),0.0);

            if (OverlapArea[0] > 0 && OverlapArea[1] > 0) {                                 //Original: minOverlapLength > 0;
                edgeList.push_back({ j, i, minOverlapLength });
                //edgeList.push_back({ j, i, 1 });                     //wjs -- edgelist of unweighted graph.
            }
        }
    }
    std::cout << "#\t edgeListSize:" << edgeList.size() << endl;

    int minInterThreshold = 0;
    int minInter = INT_MAX;
    int maxHTreshold = 0;
    double maxQH = INT_MIN;                      //change int type to double;

    for (int i = 0; i <= 32; i++) {
        auto ret = PartitionBenchmarkQ5(edgeList, rules, i);
        std::cout << i << "#\tQH: " << ret.QH << "numInter: " << ret.numInter << endl;
        if (ret.QH > maxQH) {
            maxQH = ret.QH;
            maxHTreshold = i;
        }
        if (ret.numInter < minInter) {
            minInter = ret.numInter;
            minInterThreshold = i;
        }
    }
    std::cout << "#maxHTreshold:\t" << maxHTreshold << endl;

    string CutTSSThreshold = "";
    maxHTreshold = 22;
    if (maxHTreshold < 10) {
        CutTSSThreshold += "0";
        CutTSSThreshold += to_string(maxHTreshold);
        CutTSSThreshold += "0";
        CutTSSThreshold += to_string(maxHTreshold);
    } else {
        CutTSSThreshold += to_string(maxHTreshold);
        CutTSSThreshold += to_string(maxHTreshold);
    }

    // CutTSSThreshold += "000000";
    CutTSSThreshold = "0000000000";

    std::cout << "#Selected CutTSSThreshold:\t" << CutTSSThreshold << endl;
    if (methods == "CutTSS") {
        this->fun = new CutTSS(CutTSSThreshold, bucketSize, rtssleaf);
    } else {
        this->fun = new CutSplit(CutTSSThreshold, bucketSize);
    }
    // this->fun = new CutTSS(CutTSSThreshold);      //invoke CutTSS's private *fun, passing parameters to CutTSS.
    this->fun->ConstructClassifier(rules);        //invoke CutTSS's private *fun, constructClassifier of CutTSS.
}

int GraphAnalyse::ClassifyAPacket(const Packet &packet) {
    return fun->ClassifyAPacket(packet);
}

void GraphAnalyse::DeleteRule(const Rule &rule) {
    fun->DeleteRule(rule);
}

void GraphAnalyse::InsertRule(const Rule &rule) {
    fun->InsertRule(rule);
}

uint32_t GraphAnalyse::MemSizeBytes() const {
    return fun->MemSizeBytes();
}

size_t GraphAnalyse::NumTables() const {
    return 0;
}

size_t GraphAnalyse::RulesInTable(size_t tableIndex) const {
    return 0;
}

int GraphAnalyse::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    return 0;
}
