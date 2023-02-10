CSPATH = CutSplit/
CTPATH = CutTSS/
OVSPATH = OVS/
PSPATH = PartitionSort/
HSPATH = HyperSplit/
GAPATH = GraphAnalyse/
HCPATH = HiCuts/
VPATH = $(CSPATH) $(CTPATH) $(OVSPATH) $(PSPATH) $(HSPATH) $(GAPATH) $(HCPATH)

CPP=g++
CFLAGS = -g -w -std=c++14 -fpermissive -O3 $(INCLUDE)

# Targets needed to bring the executable up to date

main: main.o CutSplit.o CutTSS.o OVS.o PartitionSort.o HyperSplit.o GA.o HiCuts.o
	$(CPP) $(CFLAGS) -o main *.o $(LIBS)
# ---------------------------------------------------------------------------------------------------------

HiCuts.o: HiCuts.cpp HiCuts.h ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(HCPATH)HiCuts.cpp

HyperSplit.o: HyperSplit.h HyperSplit.cpp ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(HSPATH)HyperSplit.cpp

CutSplit.o: CutSplit.h CutSplit.cpp ElementaryClasses.h HyperSplit.h HyperSplit.cpp
	$(CPP) $(CFLAGS) -c $(CSPATH)CutSplit.cpp

CutTSS.o: CutTSS.cpp CutTSS.h TupleSpaceSearch.h TupleSpaceSearch.cpp ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(CTPATH)CutTSS.cpp

# ** TupleSpace **
OVS.o: $(wildcard $(OVSPATH)*.cpp) ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(OVSPATH)*.cpp

# ** PartitionSort **
PartitionSort.o: $(wildcard $(PSPATH)*.cpp) ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(PSPATH)*.cpp

GA.o: $(wildcard $(GAPATH)*.cpp) ElementaryClasses.h
	$(CPP) $(CFLAGS) -c $(GAPATH)*.cpp

main.o: main.cpp CutTSS.h CutSplit.h TupleSpaceSearch.h ElementaryClasses.h GraphAnalyse.h
	$(CPP) $(CFLAGS) -c main.cpp


all:main
clean:
	rm -rf *.o main
