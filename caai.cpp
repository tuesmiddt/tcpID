#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  session = testSession;
  mss = 200;
  emuDelay = envB ? 800 : 1000;
  tcpOptMss = htons(mss);
  tcpOptWscale = 14;
  streamReassembly = new pcpp::TcpReassembly(CaaiTest::reassemblyCallback,
    this, NULL, NULL);
}

void CaaiTest::setupWolfSsl() {
  wolfSSL_Init();
  if ((sslCtx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
    std::cerr << "ERROR: failed to create WOLFSSL_CTX\n";
    exit(-1);
  }

  if (wolfSSL_CTX_load_verify_locations(sslCtx, caCert.c_str(), NULL) !=
      SSL_SUCCESS) {
    std::cerr << "ERROR: failed to load cert file at " << caCert << "\n";
    exit(-1);
  }

  wolfSSL_SetIORecv(sslCtx, CaaiTest::sslReadCallback);
  wolfSSL_SetIOSend(sslCtx, CaaiTest::sslWriteCallback);

  if ((ssl = wolfSSL_new(sslCtx)) == NULL) {
    std::cerr << "ERROR: failed to create WOLFSSL object\n";
    exit(-1);
  }

  wolfSSL_SetIOWriteCtx(ssl, this);
  wolfSSL_SetIOReadCtx(ssl, this);
}

void CaaiTest::connectSsl() {
  char errorString[80];
  std::this_thread::sleep_for(std::chrono::milliseconds(2000));
  int err;
  if ((err = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
    std::cerr << "ERROR: failed to connect to wolfSSL\n";
    wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, err), errorString);
    std::cerr << "ERROR: " << errorString << "\n";
    // exit(-1);
    return;
  }

  testState = PRE_DROP;

  std::string reqStr = makeGetStr();

  resetRttCount();

  if (wolfSSL_write(ssl, reqStr.c_str(), reqStr.length()) != reqStr.length()) {
    std::cerr << "ERROR: failed to write ssl";
    exit(-1);
  }
}

std::string CaaiTest::makeGetStr() {
  char reqStr[500];

  std::snprintf(reqStr, sizeof(reqStr),
      // "GET /~stevenha/database/Art_of_Programming_Contest_SE_for_uva.pdf HTTP/1.1\r\nHost: %s\r\n\r\n",
      // "GET /sites/default/files/2018-01/2018_Hacker_Report.pdf HTTP/1.1\r\n"
      "GET /test.txt HTTP/1.1\r\n"
      // "GET /~stevenha/database/Art_of_Programming_Contest_SE_for_uva.pdf HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0\r\n"
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
      "Accept-Language: en-US,en;q=0.5\r\n"
      "Cache-Control: max-age=0\r\n"
      "\r\n",
      session->dstName.c_str());
  // std::cout << reqStr;
  return std::string(reqStr);
}

void CaaiTest::reassemblyCallback(
    int side, pcpp::TcpStreamData data, void* cookie) {
  CaaiTest* curTest = static_cast<CaaiTest*>(cookie);
  if (data.getConnectionData().dstIP->toString().compare(
        curTest->session->srcIP) == 0) {
    char* dataPtr = reinterpret_cast<char*>(data.getData());
    curTest->rcvBuffer.write(dataPtr, data.getDataLength());
  }

  // std::cout << "readbuf position after write: " << curTest->rcvBuffer.tellp() << "\n";
}

// return no. of bytes written
int CaaiTest::sslWriteCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
  // REMEMBER TO use wolfSSL_SetIOWriteCtx(ssl, buffer_data) if ctx needed
  CaaiTest* curTest = static_cast<CaaiTest*>(ctx);
  int written = 0;
  std::stringstream writeStream("");
  writeStream.write(buf, sz);
  writeStream.seekg(0, writeStream.beg);

  for (int i = 0; i < (sz / (curTest->mss)) + 1; i++) {
    int toSend = (sz - written) > curTest->mss ?
        curTest->mss : (sz - written);
    char* sendBuf = new char[toSend];
    int sending = writeStream.readsome(sendBuf, toSend);
    if (sending != toSend) {
      std::cerr << "ERROR WRITING SSL DATA\n";
      exit(-1);
    }

    curTest->sendData(sendBuf, sending);
    written += sending;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(2000));

  return written;
}

// return no. of bytes read
int CaaiTest::sslReadCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
  // REMEMBER TO use wolfSSL_SetIOReadCtx(ssl, buffer_data) if ctx needed

  // std::cout << "trying to read " << sz << "\n";
  CaaiTest* curTest = static_cast<CaaiTest*>(ctx);
  // std::cout << "readbuf position before read: " << curTest->rcvBuffer.tellg() << "\n";

  int read = 0;

  while (read == 0) {
    read = curTest->rcvBuffer.readsome(buf, sz);
  }
  // std::cout << "readbuf position after read: " << curTest->rcvBuffer.tellg() << "\n";\
  // std::cout << "read bytes count: " << read << "\n";


  return read > 0 ? read : -2;
}

void CaaiTest::startWorker() {
  workQueue = true;
  resetRttCount();
  sendWorker = new std::thread(&CaaiTest::sendPacketQueue, this);
}

void CaaiTest::stopWorker() {
  workQueue = false;
}

void CaaiTest::resetRttCount() {
  startTime = std::chrono::high_resolution_clock::now()
      - std::chrono::milliseconds(500);  // Offset by half a second for window splitting
  curRttCount = 0;
}

void CaaiTest::sendPacketQueue() {
  while (true) {
    if (!workQueue) return;

    std::this_thread::sleep_for(std::chrono::milliseconds(sleepInterval));
    sleepCount++;
    if (sleepCount * sleepInterval >= emuDelay) {
      sleepCount = 0;
      unsigned toSend = sendQueue.size();

      for (unsigned i = 0; i < toSend; i++) {
        // not sure why acking every other packet is problematic with nus servers
        // if ((toSend % 2 && i % 2 == 0) || (toSend % 2 == 0 && i % 2)) {
        // if (i % 2 || i + 1 == toSend) {
        if (true) {
          session->sendTcp(sendQueue.front().first, sendQueue.front().second);
          sendQueue.pop();
        } else {
          delete sendQueue.front().first;
          delete sendQueue.front().second;
          sendQueue.pop();
        }
      }
    }
  }
}

void CaaiTest::enqueuePacket(pcpp::TcpLayer* tcpLayer,
    pcpp::Layer* payloadLayer) {

  std::uint32_t ackNumber = ntohl(tcpLayer->getTcpHeader()->ackNumber);
  if (ackNumber > session->maxAcked)
    session->maxAcked = ackNumber;

  std::pair <pcpp::TcpLayer*, pcpp::Layer*> wrapper(tcpLayer, payloadLayer);
  sendQueue.push(wrapper);
}

void CaaiTest::testCallBack(pcpp::Packet* packet) {
  pcpp::TcpLayer* tcpLayer = packet
      ->getLayerOfType<pcpp::TcpLayer>();

  session->updateMaxSeen(tcpLayer);

  streamReassembly->reassemblePacket(*packet);

  if (tcpLayer->getTcpHeader()->finFlag || tcpLayer->getTcpHeader()->rstFlag) {
    testState = DONE;
    printResults();
    std::cout << "\n\n";
  }

  int pktRtt = (std::chrono::high_resolution_clock::now() - startTime) /
      std::chrono::seconds(1);

  if (testState != DROP_WAIT) {
    if (pktRtt > curRttCount) {
      std::cout << pktRtt << ": " << curCwnd << "\n";
      testResults.push_back(std::pair<int, int>(pktRtt, curCwnd));

      if (testState == PRE_DROP && pktRtt == 4) {
        emuDelay = 1000;
      }

      if (testState == POST_DROP && pktRtt == 13) {
        emuDelay = 1000;
      }

      if (curCwnd >= cwndThresh && testState < DROP_WAIT) {
        // std::printf("DROPPING\n");
        testResults.push_back(std::pair<int, int>(0, 0));  // Mark drop
        testState = DROP_WAIT;
        dropSeq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
        maxSeenAfterRto = dropSeq;
        // std::printf("\n%llu\n", dropSeq);
        stopWorker();
        curCwnd = 1;
      } else {
        curCwnd = 1;
        curRttCount = pktRtt;
      }
    } else {
      curCwnd++;
    }
  } else if (resent < 1 &&
      ntohl(tcpLayer->getTcpHeader()->sequenceNumber) == dropSeq) {
    resent++;
    session->resendLastPacket();  // described in paper to deal with f-rto but wonky
  } else if (ntohl(tcpLayer->getTcpHeader()->sequenceNumber) == dropSeq) {
    testState = POST_DROP;
    startWorker();
    // return;
  }

  handlePacket(packet);
}

void CaaiTest::handlePacket(pcpp::Packet* prev) {
  if (testState == ESTABLISH_SESSION) {
    handleEstablishSession(prev);
  } else if (testState == SSL_HANDSHAKE) {
    handleSslHandshake(prev);
  } else if (testState == PRE_DROP) {
    handlePreDrop(prev);
  } else if (testState == POST_DROP) {
    handlePostDrop(prev);
  } else if (testState == DONE) {
    handleDone(prev);
  }
}

void CaaiTest::handleEstablishSession(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();
  pcpp::tcphdr* prevHeader = prevTcp->getTcpHeader();

  for (pcpp::TcpOptionData* tcpOption = prevTcp->getFirstTcpOptionData();
      tcpOption != NULL;
      tcpOption = prevTcp->getNextTcpOptionData(tcpOption)) {
    if (tcpOption->getType() == pcpp::PCPP_TCPOPT_TIMESTAMP) {
      tsEnabled = true;
    }
  }

  if (prevHeader->synFlag && prevHeader->ackFlag) {
    // sendRequest(prev);
    sendAck(prev);
    std::thread* sslConn = new std::thread(&CaaiTest::connectSsl, this);
    sslConn-> detach();
    testState = SSL_HANDSHAKE;
  }
}

void CaaiTest::handleSslHandshake(pcpp::Packet* prev) {
  sendAck(prev);
  // testState = PRE_DROP;
}

void CaaiTest::handlePreDrop(pcpp::Packet* prev) {
  sendAck(prev);
}

void CaaiTest::handlePostDrop(pcpp::Packet* prev) {
  std::uint32_t pktSeq = ntohl(prev->getLayerOfType<pcpp::TcpLayer>()
    ->getTcpHeader()->sequenceNumber);

  if ((maxSeenAfterRto + 10 * mss < pktSeq) && curRttCount < 3) {
    sendDupAck(prev);
  } else {
    maxSeenAfterRto = pktSeq;
    sendAck(prev);
  }
}

void CaaiTest::handleDone(pcpp::Packet* prev) {
  return;
}

void CaaiTest::sendAck(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);

  if (tsEnabled) {
    setTSOpt(tcpLayer, prevTcp);
    addNopOpt(tcpLayer);
    tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
  }

  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(tcpOptWSize);

  int prevDataLen = getDataLen(prev);
  if (prevDataLen == 0) {
    delete tcpLayer;
    return;
  }

  header->ackNumber = htonl(
      ntohl(prevTcp->getTcpHeader()->sequenceNumber) +
      prevDataLen + prevTcp->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  enqueuePacket(tcpLayer, NULL);
}

void CaaiTest::sendDupAck(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);

  if (tsEnabled) {
    setTSOpt(tcpLayer, prevTcp);
    addNopOpt(tcpLayer);
    tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
  }

  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(tcpOptWSize);

  int prevDataLen = getDataLen(prev);
  if (prevDataLen == 0) {
    delete tcpLayer;
    return;
  }

  header->ackNumber = htonl(session->maxAcked);
  header->ackFlag = 1;

  enqueuePacket(tcpLayer, NULL);
}

// send data datalen bytes of data from buf. Will use last received packet for info
void CaaiTest::sendData(char* buf, int dataLen) {
  if (dataLen > mss) {
    std::cerr << "TRIED TO SEND TOO MUCH DATA";
    exit(-1);
  }

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  pcpp::Packet* prev = session->getLastReceivedPacket();
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();

  if (tsEnabled) {
    setTSOpt(tcpLayer, prevTcp);
    addNopOpt(tcpLayer);
    tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
  }

  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(tcpOptWSize);

  int prevDataLen = getDataLen(prev);
  header->ackNumber = htonl(
      ntohl(prevTcp->getTcpHeader()->sequenceNumber) +
      prevDataLen + prevTcp->getTcpHeader()->synFlag);

  header->ackFlag = 1;
  header->pshFlag = 1;

  char data[mss+1] = {0};
  memcpy(data, buf, dataLen);

  pcpp::PayloadLayer* req = new pcpp::PayloadLayer(
    reinterpret_cast<std::uint8_t*>(data), dataLen, true);

  session->seq += req->getDataLen();

  enqueuePacket(tcpLayer, req);
  delete buf;
}

void CaaiTest::sendRequest(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  if (tsEnabled) {
    setTSOpt(tcpLayer, prevTcp);
    addNopOpt(tcpLayer);
    tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
  }
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(tcpOptWSize);

  int prevDataLen = getDataLen(prev);
  header->ackNumber = htonl(
      ntohl(prevTcp->getTcpHeader()->sequenceNumber) +
      prevDataLen + prevTcp->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  char reqStr[200];

  std::snprintf(reqStr, sizeof(reqStr),
    "GET /~stevenha/database/Art_of_Programming_Contest_SE_for_uva.pdf HTTP/1.1\r\nHost: %s\r\n\r\n",
    session->dstName.c_str());

  pcpp::PayloadLayer* req = new pcpp::PayloadLayer(
    reinterpret_cast<std::uint8_t*>(reqStr), std::strlen(reqStr), true);

  session->seq += req->getDataLen();

  enqueuePacket(tcpLayer, req);
  // enqueuePacket(tcpLayer, NULL);
}

void CaaiTest::sendSyn() {
  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);
  setInitialOpt(tcpLayer);
  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->synFlag = 1;
  header->windowSize = htons(tcpOptWSize);
  session->seq += 1;

  tcpLayer->computeCalculateFields();

  enqueuePacket(tcpLayer, NULL);
}

void CaaiTest::setInitialOpt(pcpp::TcpLayer* synTcpLayer) {
  setTSOpt(synTcpLayer, NULL);
  synTcpLayer->addTcpOption(pcpp::TCPOPT_MSS, 4,
      reinterpret_cast<std::uint8_t*>(&tcpOptMss));
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_WINDOW, 3,
      reinterpret_cast<std::uint8_t*>(&tcpOptWscale));

  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
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

int CaaiTest::getDataLen(pcpp::Packet* p) {
  pcpp::TcpLayer* tcpLayer = p->getLayerOfType<pcpp::TcpLayer>();
  pcpp::IPv4Layer* ipLayer = p->getLayerOfType<pcpp::IPv4Layer>();

  return ntohs(ipLayer->getIPv4Header()->totalLength) -
      ipLayer->getIPv4Header()->internetHeaderLength * 4 -
      tcpLayer->getTcpHeader()->dataOffset * 4;
}

void CaaiTest::addNopOpt(pcpp::TcpLayer* tcpLayer) {
  std::uint8_t* one = new std::uint8_t(1);
  tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_NOP, 1, one);
  delete one;
}

void CaaiTest::startTest() {
  startWorker();
  setupWolfSsl();
  sendSyn();
}

bool CaaiTest::checkRestartTest() {
  return testState == ESTABLISH_SESSION ? true : false;
}

bool CaaiTest::getTestDone() {
  return testState == DONE;
}

void CaaiTest::printResults() {
  std::cout << "======TEST DONE=====\n";
  //
  // unsigned read = 10;
  // char printer[200];
  // while (read != 0){
  //   bzero(printer, sizeof(printer));
  //   read = rcvBuffer.readsome(printer, 199);
  //   std::printf("%s", printer);
  // }

  for (std::pair<int, int> p : testResults) {
    std::printf("RTT: %d, CWND: %d\n", p.first, p.second);
  }
}
