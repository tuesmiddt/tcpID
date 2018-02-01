#include "caai.hpp"
#include "session.hpp"
#include "pktutil.hpp"

CAAITest::CAAITest(TestSession* testSession) {
  std::cout << "New CAAITest created";
  session = testSession;
}

void CAAITest::testCallBack(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* token) {
  CAAITest *curTest = (CAAITest *)token;

  pcpp::Packet* parsedPacket = new pcpp::Packet(packet);

  curTest->session->addToHistory(parsedPacket);

  PktUtil::printPktInfo(parsedPacket);
}
