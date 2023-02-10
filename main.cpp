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

/*-----------------------------------------------------------------------------
 *  
 *  Name:		 Tuple Space Assisted Packet Classification with High Performance on Both Search and Update[1]
 *  Description: Main function of CutTSS, as well as PSTSS[NSDI_2015], PartitionSort[ICNP_2016] and CutSplit[INFOCOM_2018]
 *  Version:	 3.0 (release)
 *  Author:		 Wenjun Li(Peng Cheng Laboratory, Email:wenjunli@pku.edu.cn)	 
 *  Date:		 8/8/2021
 *  Note:		 version 3.0 was modified by Yuxi Liu (under the guidance of Wenjun Li), a graduate student from the Southern University of Science and Technology. The modified CutSplit can avoid previous faults and acheive faster classification performance.  
 *  [1] wenjun Li, Tong Yang, Ori Rottenstreich, Xianfeng Li, Gaogang Xie, Hui Li, Balajee Vamanan, Dagang Li and Huiping Lin, “Tuple Space Assisted Packet Classification with High Performance on Both Search and Update,” In Special Issue on Network Softwarization & Enablers，IEEE Journal on Selected Areas in Communications (JSAC), 2020. 
 *-----------------------------------------------------------------------------*/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <list>
#include <sys/time.h>
#include <string.h>
#include "CutSplit/CutSplit.h"
#include "PartitionSort/PartitionSort.h"
#include "OVS/TupleSpaceSearch.h"
#include "ElementaryClasses.h"
#include "HyperSplit/HyperSplit.h"
#include "CutTSS/CutTSS.h"
#include "HiCuts/HiCuts.h"

using namespace std;

FILE *fpr = fopen("./ipc_1k", "r");           // ruleset file
FILE *fpt = fopen("./ipc_1k_trace", "r");           //  trace file 
int classificationFlag = 1; //0:!run classification; 1:run classification 
int updateFlag = 1; //0:!run update; 1:run update (rand_update[MAXRULES]: ~half insert & half delete)

int bucketSize = 8;   // leaf threashold
int ratiotssleaf = 5; //Assume one TSS lookup takes 5 times than one rule linear search  

int threshold = 12;   // For simplity, assume T_SA=T_DA=threshold=20. These values can be chosen dynamicly by running different thresholds
map<int, int> pri_id;  // rule id <--> rule priority
int rand_update[MAXRULES]; //random generate rule id
int max_pri[4] = {-1, -1, -1, -1}; //the priority of partitioned subsets: priority sorting on subsets

int SIP_Threshold = 0;
int DIP_Threshold = 0;




/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  loadrule(FILE *fp)
 *  Description:  load rules from rule file
 * =====================================================================================
 */
vector<Rule> loadrule(FILE *fp) {
    unsigned int tmp;
    unsigned sip1, sip2, sip3, sip4, smask;
    unsigned dip1, dip2, dip3, dip4, dmask;
    unsigned sport1, sport2;
    unsigned dport1, dport2;
    unsigned protocal, protocol_mask;
    unsigned ht, htmask;
    int number_rule = 0; //number of rules

    vector<Rule> rule;

    while (1) {

        Rule r;
        std::array<Point, 2> points;
        if (fscanf(fp, "@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\n",
                   &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &sport1, &sport2,
                   &dport1, &dport2, &protocal, &protocol_mask, &ht, &htmask) != 18)
            break;

        if (smask == 0) {
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        } else if (smask > 0 && smask <= 8) {
            tmp = sip1 << 24;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 8 && smask <= 16) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 16 && smask <= 24) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            tmp += sip3 << 8;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 24 && smask <= 32) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            tmp += sip3 << 8;
            tmp += sip4;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else {
            printf("Src IP length exceeds 32\n");
            exit(-1);
        }
        r.range[0] = points;

        if (dmask == 0) {
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        } else if (dmask > 0 && dmask <= 8) {
            tmp = dip1 << 24;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 8 && dmask <= 16) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 16 && dmask <= 24) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            tmp += dip3 << 8;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 24 && dmask <= 32) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            tmp += dip3 << 8;
            tmp += dip4;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else {
            printf("Dest IP length exceeds 32\n");
            exit(-1);
        }
        r.range[1] = points;

        points[0] = sport1;
        points[1] = sport2;
        r.range[2] = points;

        points[0] = dport1;
        points[1] = dport2;
        r.range[3] = points;

        for (int i = 15; i >= 0; i--) {
            unsigned int Bit = 1 << i;
            unsigned int sp = sport1 ^ sport2;
            if (sp & Bit) {
                break;
            }
            r.prefix_length[2]++;
        }

        for (int i = 15; i >= 0; i--) {
            unsigned int Bit = 1 << i;
            unsigned int dp = dport1 ^ dport2;
            if (dp & Bit) {
                break;
            }
            r.prefix_length[3]++;
        }

        if (protocol_mask == 0xFF) {
            points[0] = protocal;
            points[1] = protocal;
            r.prefix_length[4] = 8;
        } else if (protocol_mask == 0) {
            points[0] = 0;
            points[1] = 0xFF;
        } else {
            printf("Protocol mask error\n");
            exit(-1);
        }
        r.range[4] = points;

        r.prefix_length[0] = smask;
        r.prefix_length[1] = dmask;
        r.id = number_rule;

        rule.push_back(r);
        number_rule++;
    }

    //printf("the number of rules = %d\n", number_rule);
    int max_pri = number_rule - 1;
    for (int i = 0; i < number_rule; i++) {
        rule[i].priority = max_pri - i;
        pri_id.insert(pair<int, int>(rule[i].priority, rule[i].id));
        /*printf("%u: %u:%u %u:%u %u:%u %u:%u %u:%u %d\n", i,
          rule[i].range[0][0], rule[i].range[0][1],
          rule[i].range[1][0], rule[i].range[1][1],
          rule[i].range[2][0], rule[i].range[2][1],
          rule[i].range[3][0], rule[i].range[3][1],
          rule[i].range[4][0], rule[i].range[4][1],
          rule[i].priority);*/
    }
    pri_id.insert(pair<int, int>(-1, -1));
    return rule;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  loadpacket(FILE *fp)
 *  Description:  load packets from trace file generated from ClassBench[INFOCOM2005]
 * =====================================================================================
 */
std::vector<Packet> loadpacket(FILE *fp) {
    unsigned int header[MAXDIMENSIONS];
    unsigned int proto_mask, fid;
    int number_pkt = 0; //number of packets
    std::vector<Packet> packets;
    while (1) {
        if (fscanf(fp, "%u %u %d %d %d %u %d\n", &header[0], &header[1], &header[2], &header[3], &header[4],
                   &proto_mask, &fid) == Null)
            break;
        Packet p;
        p.push_back(header[0]);
        p.push_back(header[1]);
        p.push_back(header[2]);
        p.push_back(header[3]);
        p.push_back(header[4]);
        p.push_back(fid);

        packets.push_back(p);
        number_pkt++;
    }

    /*printf("the number of packets = %d\n", number_pkt);
    for(int i=0;i<number_pkt;i++){
        printf("%u: %u %u %u %u %u %u\n", i,
               packets[i][0],
               packets[i][1],
               packets[i][2],
               packets[i][3],
               packets[i][4],
               packets[i][5]);
			   }*/

    return packets;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  parseargs(int argc, char *argv[])
 *  Description:  Parse arguments from the console
 * =====================================================================================
 */

void parseargs(int argc, char *argv[]) {
    int c;
    bool ok = 1;
    while ((c = getopt(argc, argv, "b:s:d:t:r:e:c:u:h")) != -1) {
        switch (c) {
            case 'b':  //bucketsize1 of leaf node
                bucketSize = atoi(optarg);
                break;
            case 't':  //threshold for small fields
                threshold = atoi(optarg);
                break;
            case 'r':  //rule set
                fpr = fopen(optarg, "r");
                break;
            case 'e':  //trace packets for simulations
                fpt = fopen(optarg, "r");
                break;
            case 'c':  //classification simulation				
                classificationFlag = atoi(optarg);
                break;
            case 'u':  //update simulation
                updateFlag = atoi(optarg);
                break;
            case 's': // Sip Threshold
                SIP_Threshold = atoi(optarg);
                break;
            case 'd':
                DIP_Threshold = atoi(optarg);
                break;
            case 'h': //help
                printf("./main [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace][-c (1:classification)][-u (1:update)]\n");
                printf("e.g., ./main -b 8 -t 20 -r ./ruleset/ipc1_10k -e ./ruleset/ipc1_10k_trace -c 1 -u 1\n");
                printf("mail me: wenjunli@pku.edu.cn\n");
                exit(1);
                break;
            default:
                ok = 0;
        }
    }

    if (bucketSize <= 0 || bucketSize > MAXBUCKETS) {
        printf("bucketSize should be greater than 0 and less than %d\n", MAXBUCKETS);
        ok = 0;
    }
    if (threshold < 0 || threshold > 32) {
        printf("threshold should be greater than 0 and less than 32\n");
        ok = 0;
    }
    if (fpr == NULL) {
        printf("can't open ruleset file\n");
        ok = 0;
    }
    if (classificationFlag != 1 && classificationFlag != 0) {
        printf("0:!run classification simulation; 1:run classification simulation\n");
        ok = 0;
    }
    if (updateFlag != 1 && updateFlag != 0) {
        printf("0:!run update simulation; 1:run update simulation\n");
        ok = 0;
    }
    if (!ok || optind < argc) {
        fprintf(stderr,
                "./main [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace][-c (1:classification)][-u (1:run update)]\n");
        fprintf(stderr, "Type \"./main -h\" for help\n");
        exit(1);
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  main function for {CutTSS,PSTSS,PartitionSort,CutSplit}
 *  Description:  loadrule->construction-->classification-->update
 * =====================================================================================
 */
int main(int argc, char *argv[]) {
    parseargs(argc, argv);
    vector<Rule> rule;
    vector<Packet> packets;
    vector<int> results;
    FILE *output = fopen("./result.csv", "a+");
    fprintf(output, "%d,%d,", SIP_Threshold, DIP_Threshold);

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;
    std::chrono::duration<double, std::milli> elapsed_milliseconds;

    rule = loadrule(fpr);
    int number_rule = int(rule.size());
    packets = loadpacket(fpt);
    int number_pkt = packets.size();

    // CutTSS *CT = new CutTSS(SIP_Threshold, DIP_Threshold, bucketSize, ratiotssleaf);
    // CT->ConstructClassifier(rule);
    const int trials = 100; // run 100 times curcularly;
    int match_miss = 0;
//---CutTSS---Classification---			
    std::chrono::duration<double> sum_timeCS(0);
    int match_pri = -2;
    int matchid[number_pkt];
    Packet p;
    match_miss = 0;
    // for (int i = 0; i < trials; i++) {
    //     start = std::chrono::steady_clock::now();
    //     for (int j = 0; j < number_pkt; j++) {
    //         matchid[j] = number_rule - 1 - CT->ClassifyAPacket(packets[j]);
    //     }
    //     end = std::chrono::steady_clock::now();
    //     elapsed_seconds = end - start;
    //     sum_timeCS += elapsed_seconds;
    //     for (int j = 0; j < number_pkt; j++) {
    //         if (matchid[j] == -1 || packets[j][5] < matchid[j]) {
    //             match_miss++;
    //         }
    //     }
    // }
    // double CutTSSThroughputResult = 1 / (sum_timeCS.count() * 1e6 / double(trials * packets.size()));
    // fprintf(output, "%f\n", CutTSSThroughputResult);

//---HiCuts---
    cout << "Construct HiCuts" << endl;
    HiCuts *HC = new HiCuts(8, 16, 4.0);
    HC->ConstructClassifier(rule);
    cout << "Construct HiCuts finish" << endl;

//---HiCuts---Classification---
    std::chrono::duration<double> sum_timeHC(0);

    for (int i = 0; i < trials; i++) {
        start = std::chrono::steady_clock::now();
        for (int j = 0; j < number_pkt; j++) {
            matchid[j] = number_rule - 1 - HC->ClassifyAPacket(packets[j]);
        }
        end = std::chrono::steady_clock::now();
        elapsed_seconds = end - start;
        sum_timeHC += elapsed_seconds;
        for (int j = 0; j < number_pkt; j++) {
            if (matchid[j] == -1 || packets[j][5] < matchid[j]) {
                match_miss++;
            }
        }
    }
    double HiCutsThroughputResult = 1.0 / (sum_timeHC.count() * 1e6 / static_cast<double>(trials * packets.size()));
    cout << match_miss << endl;
    cout << "Throughput:" << HiCutsThroughputResult << "Mpps" << endl;

    return 0;
}


