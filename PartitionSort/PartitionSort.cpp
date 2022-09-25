#include "PartitionSort.h"

int PartitionSort::ClassifyAPacket(const Packet& packet) {
    int result = -1;
    uint64_t Query = 0;
    for (const auto& t : mitrees) {
        if (result > t->MaxPriority()){
            break;
        }
        Query ++;
        result = std::max(t->ClassifyAPacket(packet,Query), result);
    }
    QueryUpdate(Query);
    return result;

}

int PartitionSort::ClassifyAPacket(const Packet &packet, uint64_t &Query) {
    int result = -1;
    for (const auto& t : mitrees) {
        if (result > t->MaxPriority()){
            break;
        }
        Query ++;
        result = std::max(t->ClassifyAPacket(packet,Query), result);
    }
    QueryUpdate(Query);
    return result;
}

void PartitionSort::InsertRule(const Rule& one_rule) {

 
	for (auto mitree : mitrees)
	{
		bool prioritychange = false;
		
		bool success = mitree->TryInsertion(one_rule, prioritychange);
		if (success) {
			
			if (prioritychange) {
				InsertionSortMITrees();
			}
			mitree->ReconstructIfNumRulesLessThanOrEqualTo(10);
			rules.emplace_back(one_rule, mitree);
			return;
		}
	}
	bool priority_change = false;

	auto tree_ptr = new OptimizedMITree(one_rule);
	tree_ptr->TryInsertion(one_rule, priority_change);
	rules.emplace_back(one_rule, tree_ptr);
	mitrees.push_back(tree_ptr);
	InsertionSortMITrees();
}


void PartitionSort::DeleteRule1(size_t i){
	if (i < 0 || i >= rules.size()) {
		//printf("Warning index delete rule out of bound: do nothing here\n");
		//printf("%lu vs. size: %lu", i, rules.size());
		return;
	}
	bool prioritychange = false;

	OptimizedMITree * mitree = rules[i].second;
	mitree->Deletion(rules[i].first, prioritychange);

	if (prioritychange) {
		InsertionSortMITrees();
	}


	if (mitree->Empty()) {
		mitrees.pop_back();
		delete mitree;
	}


	if (i != rules.size() - 1) {
		rules[i] = std::move(rules[rules.size() - 1]);
	}
	rules.pop_back();


}

void PartitionSort::DeleteRule(const Rule& one_rule){
	//TODO
	printf("delete rule\n");
}

