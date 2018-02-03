#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  session = testSession;
  tcpOptMss = htons(200);
  tcpOptWscale = 14;
}

void CaaiTest::startWorker() {
  sendWorker = new std::thread(&CaaiTest::sendPacketQueue, this);
}

void CaaiTest::sendPacketQueue() {
  std::unique_lock<std::mutex> lock(sendMutex, std::defer_lock);

  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepInterval));
    sleepCount++;
    if (sleepCount * sleepInterval >= sendDelay) {
      sleepCount = 0;
      lock.lock();
      unsigned toSend = sendQueue.size();
      lock.unlock();

      for (unsigned i = 0; i < toSend; i++) {
        session->sendTcp(sendQueue.front().first, sendQueue.front().second);
        sendQueue.pop();
      }
    }
  }
}

void CaaiTest::enqueuePacket(pcpp::TcpLayer* tcpLayer,
    pcpp::Layer* payloadLayer) {
  std::pair <pcpp::TcpLayer*, pcpp::Layer*> wrapper(tcpLayer, payloadLayer);
  sendQueue.push(wrapper);
}

void CaaiTest::testCallBack(pcpp::Packet* packet) {
  pcpp::TcpLayer* tcpLayer = packet
      ->getLayerOfType<pcpp::TcpLayer>();

  session->updateMaxSeen(tcpLayer);

  if (tcpLayer->getTcpHeader()->finFlag || tcpLayer->getTcpHeader()->rstFlag) {
    testState = DONE;
  }

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
    testState = SSH_HANDSHAKE;
  }
}

void CaaiTest::handleSshHandshake(pcpp::TcpLayer* prev) {
    testState = PRE_DROP;
}

void CaaiTest::handlePreDrop(pcpp::TcpLayer* prev) {
  sendAck(prev);
}

void CaaiTest::handlePostDrop(pcpp::TcpLayer* prev) {
    testState = DONE;
}

void CaaiTest::handleDone(pcpp::TcpLayer* prev) {
    return;
}

void CaaiTest::sendAck(pcpp::TcpLayer* prev) {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  setTSOpt(tcpLayer, prev);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(200);

  header->ackNumber = htonl(
      ntohl(prev->getTcpHeader()->sequenceNumber) +
      prev->getLayerPayloadSize() +
      prev->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  enqueuePacket(tcpLayer, NULL);
}

void CaaiTest::sendRequest(pcpp::TcpLayer* prev) {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  setTSOpt(tcpLayer, prev);
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

  enqueuePacket(tcpLayer, req);
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

  enqueuePacket(tcpLayer, NULL);
}

void CaaiTest::setInitialOpt(pcpp::TcpLayer* synTcpLayer) {
  pcpp::tcphdr* header = synTcpLayer->getTcpHeader();
  setTSOpt(synTcpLayer, NULL);
  synTcpLayer->addTcpOption(pcpp::TCPOPT_MSS, 4,
      reinterpret_cast<std::uint8_t*>(&tcpOptMss));
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_WINDOW, 3,
      reinterpret_cast<std::uint8_t*>(&tcpOptWscale));


  std::uint16_t* zero = new std::uint16_t(0);
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1,
      reinterpret_cast<std::uint8_t*>(&zero));
  delete zero;
}

void CaaiTest::setTSOpt(pcpp::TcpLayer* targetTcpLayer,
    pcpp::TcpLayer* prevTcpLayer) {
  pcpp::TcpOptionData* prevTSOpt;
  // Set TSval
  pcpp::TcpOptionData* tsOption = targetTcpLayer->addTcpOption(
      pcpp::PCPP_TCPOPT_TIMESTAMP, 10, NULL);
  tsOption->setValue<std::uint32_t>(htonl(static_cast<std::uint32_t>(
      std::time(NULL))), 0);

  if ((prevTcpLayer != NULL) && (prevTcpLayer->getTcpHeader()->ackFlag) &&
        ((prevTSOpt = prevTcpLayer->
            getTcpOptionData(pcpp::PCPP_TCPOPT_TIMESTAMP)) != NULL)) {
    // Set TSecr
    tsOption->setValue<std::uint32_t>(
        prevTSOpt->getValueAs<std::uint32_t>(4), 4);
  }
}

void CaaiTest::startTest() {
  startWorker();
  sendSyn();
}

bool CaaiTest::checkRestartTest() {
  return testState == ESTABLISH_SESSION ? true : false;
}

bool CaaiTest::getTestDone() {
  return testState == DONE;
}
