#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  std::cout << "New CAAITest created";
  session = testSession;
  tcpOptMss = htons(200);
  tcpOptWscale = 14;
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
    sendRequest(prev);
    testState++;
  }
}

void CaaiTest::handleSshHandshake(pcpp::TcpLayer* prev) {
    testState++;
}

void CaaiTest::handlePreDrop(pcpp::TcpLayer* prev) {
  sendAck(prev);
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
  header->windowSize = htons(200);

  header->ackNumber = htonl(
      ntohl(prev->getTcpHeader()->sequenceNumber) +
      prev->getLayerPayloadSize() +
      prev->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  session->sendTcp(tcpLayer, NULL);
}

void CaaiTest::sendRequest(pcpp::TcpLayer* prev) {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(200);

  header->ackNumber = htonl(
      ntohl(prev->getTcpHeader()->sequenceNumber) +
      prev->getLayerPayloadSize() +
      prev->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  char reqStr[200];

  std::snprintf(reqStr, sizeof(reqStr),
    "GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
    session->dstName.c_str());

  pcpp::PayloadLayer* req = new pcpp::PayloadLayer(
    reinterpret_cast<std::uint8_t*>(reqStr), std::strlen(reqStr), true);

  session->seq += req->getDataLen();

  session->sendTcp(tcpLayer, req);
}

void CaaiTest::sendSyn() {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  setInitialOpt(tcpLayer);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->synFlag = 1;
  header->windowSize = htons(200);
  session->seq += 1;

  tcpLayer->computeCalculateFields();

  session->sendTcp(tcpLayer, NULL);
}

void CaaiTest::setInitialOpt(pcpp::TcpLayer* synTcpLayer) {
  pcpp::tcphdr* header = synTcpLayer->getTcpHeader();
  synTcpLayer->addTcpOption(pcpp::TCPOPT_MSS, 4,
      reinterpret_cast<std::uint8_t*>(&tcpOptMss));
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_WINDOW, 3,
      reinterpret_cast<std::uint8_t*>(&tcpOptWscale));

  std::uint16_t* zero = new std::uint16_t(0);
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1,
      reinterpret_cast<std::uint8_t*>(&zero));
  delete zero;
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
