#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  std::cout << "New CAAITest created";
  session = testSession;
}

void CaaiTest::testCallBack(pcpp::Packet* packet) {
  std::cout << "BLAH\n";

  pcpp::TcpLayer* tcpLayer = packet
      ->getLayerOfType<pcpp::TcpLayer>();

  session->updateMaxSeen(tcpLayer);

  if (testState == ESTABLISH_SESSION) {
    handleEstablishSession(tcpLayer);
  } else if (testState == SSH_HANDSHAKE) {
    handleSshHandshake(tcpLayer);
  } else if (testState == PRE_DROP) {
    handlePreDrop(tcpLayer);
  } else if (testState == POST_DROP) {
    handlePostDrop(tcpLayer);
  } else if (testState == DONE) {
    handleDone(tcpLayer);
  }

  delete packet;
}

void CaaiTest::handleEstablishSession(pcpp::TcpLayer* prev) {
  pcpp::tcphdr* prevHeader = prev->getTcpHeader();
  if (prevHeader->synFlag && prevHeader->ackFlag) {
    sendAck(prev);
    testState++;
  }
}

void CaaiTest::handleSshHandshake(pcpp::TcpLayer* prev) {
    testState++;
}

void CaaiTest::handlePreDrop(pcpp::TcpLayer* prev) {
    testState++;
}

void CaaiTest::handlePostDrop(pcpp::TcpLayer* prev) {
    testState++;
}

void CaaiTest::handleDone(pcpp::TcpLayer* prev) {
    return;
}

void CaaiTest::sendAck(pcpp::TcpLayer* prev) {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  std::cout << prev->getTcpHeader()->sequenceNumber;

  header->ackNumber = htonl(
      ntohl(prev->getTcpHeader()->sequenceNumber) +
      prev->getLayerPayloadSize()) +
      prev->getTcpHeader()->synFlag;
  header->ackFlag = 1;

  session->sendTcp(tcpLayer);
}

void CaaiTest::sendSyn() {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->synFlag = 1;
  session->seq += 1;

  session->sendTcp(tcpLayer);
}

void CaaiTest::startTest() {
  sendSyn();
}

bool CaaiTest::checkRestartTest() {
  return testState == 1 ? true : false;
}

bool CaaiTest::getTestDone() {
  return testState >= DONE;
}
