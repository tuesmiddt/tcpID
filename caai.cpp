#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  session = testSession;
  tcpOptMss = htons(200);
  tcpOptWscale = 14;
  streamReassembly = new pcpp::TcpReassembly(CaaiTest::reassemblyCallback,
    this, NULL, NULL);
}

void CaaiTest::reassemblyCallback(
    int side, pcpp::TcpStreamData data, void* cookie) {
  CaaiTest* curTest = static_cast<CaaiTest*>(cookie);
  if (data.getConnectionData().dstIP.toString().compare(
        curTest->session->srcIP) == 0) {
    char* dataPtr = reinterpret_cast<char*>(data.getData());
    curTest->rcvBuffer.write(dataPtr, data.getDataLength());
  }
}

// return no. of bytes written
int CaaiTest::sslWriteCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
  // REMEMBER TO use wolfSSL_SetIOWriteCtx(ssl, buffer_data) if ctx needed
  CaaiTest* curTest = static_cast<CaaiTest*>(ctx);
  int written = 0;
  std::stringstream writeStream;
  writeStream.write(buf, sz);

  for (unsigned i = 0; i < (sz / (curTest->tcpOptMss)) + 1; i++) {
    int toSend = (sz - written) > curTest->tcpOptMss ?
        curTest->tcpOptMss : (sz - written);
    char* sendBuf = new char[toSend];
    int sending = writeStream.readsome(sendBuf, toSend);
    if (sending != toSend) {
      std::cerr << "ERROR WRITING SSL DATA";
      exit(-1);
    }

    curTest->sendData(sendBuf, sending);
    written += sending;
  }

  return written;
}

// return no. of bytes read
int CaaiTest::sslReadCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
  // REMEMBER TO use wolfSSL_SetIOReadCtx(ssl, buffer_data) if ctx needed
  CaaiTest* curTest = static_cast<CaaiTest*>(ctx);
  int read = curTest->rcvBuffer.readsome(buf, sz);
  return read;
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

  streamReassembly->ReassemblePacket(*packet);

  if (tcpLayer->getTcpHeader()->finFlag || tcpLayer->getTcpHeader()->rstFlag) {
    testState = DONE;
    std::cout << "======TEST DONE=====";
    //
    unsigned read = 10;
    char printer[200];
    while (read != 0){
      bzero(printer, sizeof(printer));
      read = rcvBuffer.readsome(printer, 199);
      std::printf("%s", printer);
    }

    // std::cout << rcvBuffer.str();
    std::cout << "\n\n";
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

// send data datalen bytes of data from buf. Will use last received packet for info
void CaaiTest::sendData(char* buf, int dataLen) {
  if (dataLen > tcpOptMss) {
    std::cerr << "TRIED TO SEND TOO MUCH DATA";
    exit(-1);
  }

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  // pcpp::TcpLayer* prev = SOME_WAY_TO_GET_LAST_RECEIVED_PACKAET!!!
  pcpp::TcpLayer* prev = tcpLayer;

  setTSOpt(tcpLayer, prev);

  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(200);

  header->ackNumber = htonl(
      ntohl(prev->getTcpHeader()->sequenceNumber) +
      prev->getLayerPayloadSize() +
      prev->getTcpHeader()->synFlag);

  header->ackFlag = 1;
  header->pshFlag = 1;

  char data[tcpOptMss] = {0};
  memcpy(data, buf, dataLen);

  pcpp::PayloadLayer* req = new pcpp::PayloadLayer(
    reinterpret_cast<std::uint8_t*>(data), std::strlen(data), true);

  session->seq += req->getDataLen();

  enqueuePacket(tcpLayer, req);
  delete buf;
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
