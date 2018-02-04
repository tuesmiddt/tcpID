include ../PcapPlusPlus/Dist/mk/PcapPlusPlus.mk

appname := tcpID

CXX := g++ $(PCAPPP_INCLUDES)
CXXFLAGS := -std=c++11 -g
LDFLAGS := $(PCAPPP_LIBS_DIR) -static-libstdc++
LDLIBS := $(PCAPPP_LIBS) -lwolfssl


srcfiles := $(shell find . -name "*.cpp")
objects  := $(patsubst %.cpp, %.o, $(srcfiles))

all: $(appname)

$(appname): $(objects)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(appname) $(objects) $(LDLIBS)

depend: .depend

.depend: $(srcfiles)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	rm -f $(objects)
	rm -f $(appname)

dist-clean: clean
	rm -f *~ .depend

include .depend