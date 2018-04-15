#include "caai.hpp"
#include "session.hpp"

CaaiTest::CaaiTest(TestSession* testSession) {
  session = testSession;
  https = session->dport == 443 ? true : false;
  mss = 200;
  dropCounter.mss = mss;
  // Not used right now.
  emuDelay = envB ? 800 : 1000;
  tcpOptMss = htons(mss);
  tcpOptWscale = 14;

  // PCPP built in stream reassembly logic.
  streamReassembly = new pcpp::TcpReassembly(CaaiTest::reassemblyCallback,
    this, NULL, NULL);
}


/**
 * WolfSSL setup.
 */
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

  // set ctx for write/read callbacks to point to this CAAI instance.
  wolfSSL_SetIOWriteCtx(ssl, this);
  wolfSSL_SetIOReadCtx(ssl, this);
}

/**
 * Initialise SSL connection.
 */
void CaaiTest::connectSsl() {
  char errorString[80];

  // I don't remember why i did this.
  // std::this_thread::sleep_for(std::chrono::milliseconds(2000));

  int err;
  if ((err = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
    std::cerr << "ERROR: failed to connect to wolfSSL\n";
    wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, err), errorString);
    std::cerr << "ERROR: " << errorString << "\n";
    exit(-1);
  }

  testState = PRE_DROP;

  std::string reqStr = makeGetStr();

  // Optional: uncomment to restart counting for actual data transfer
  // resetRttCount();

  // Send GET string over ssl connection.
  if (wolfSSL_write(ssl, reqStr.c_str(), reqStr.length()) != reqStr.length()) {
    std::cerr << "ERROR: failed to write ssl";
    exit(-1);
  }
}

/**
 * Create GET request string.
 * @return std::string containing get request.
 */
std::string CaaiTest::makeGetStr() {
  char reqStr[500];

  std::snprintf(reqStr, sizeof(reqStr),
      "GET /%s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0\r\n"
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
      "Accept-Language: en-US,en;q=0.5\r\n"
      "Cache-Control: max-age=0\r\n"
      "\r\n",
      session->dstFile.c_str(),
      session->dstName.c_str());
  return std::string(reqStr);
}


/**
 * Callback for pcpp reassembly engine. pcpp reassembly will call this method
 * when a segment of data transfer is complete. This stores data received into
 * a buffer.
 * @param size   Size of data to be written in bytes.
 * @param data   Pointer to data.
 * @param cookie Pointer to CAAI test object.
 */
void CaaiTest::reassemblyCallback(
    int size, pcpp::TcpStreamData data, void* cookie) {
  CaaiTest* curTest = static_cast<CaaiTest*>(cookie);
  if (data.getConnectionData().dstIP->toString().compare(
        curTest->session->srcIP) == 0) {
    char* dataPtr = reinterpret_cast<char*>(data.getData());
    curTest->rcvBuffer.write(dataPtr, data.getDataLength());
  }
}


/**
 * Callback for WolfSSL to write data. WolfSSL gives a pointer to a some buffer
 * that stores the data to be written. We then write this data by writing raw
 * packets to send this data in blocks.
 * @param  ssl Pointer to WOLFSSL object.
 * @param  buf Pointer to data to be sent.
 * @param  sz  Number of bytes to be sent.
 * @param  ctx Pointer to CAAI test instance.
 * @return     Number of bytes sent.
 */
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

  // I don't remember why i did this.
  // std::this_thread::sleep_for(std::chrono::milliseconds(2000));

  return written;
}

/**
 * Callback for WolfSSL to read data.
 * @param  ssl Pointer to WOLFSSL object
 * @param  buf Pointer to buffer where data is to be stored.
 * @param  sz  Number of bytes requested by WolfSSL
 * @param  ctx Pointer to CAAI test instance.
 * @return     Number of bytes read.
 */
int CaaiTest::sslReadCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
  // REMEMBER TO use wolfSSL_SetIOReadCtx(ssl, buffer_data) if ctx needed

  CaaiTest* curTest = static_cast<CaaiTest*>(ctx);
  int read = 0;

  // Block until data is available.s
  while (read == 0) {
    read = curTest->rcvBuffer.readsome(buf, sz);
  }

  return read > 0 ? read : -2;
}

/**
 * Start worker thread that consumes packet queue.
 */
void CaaiTest::startWorker() {
  workQueue = true;

  // Reset for convenience and in case RTO is not a multiple of RTT
  resetRttCount();
  sendWorker = new std::thread(&CaaiTest::sendPacketQueue, this);
}

/**
 * Sets flag that will cause worker thread to terminate itself the next time it
 * wakes up.
 */
void CaaiTest::stopWorker() {
  workQueue = false;
}

/**
 * Set startTime from which rtt counts are calculated. Reset curRttCount to 0.
 */
void CaaiTest::resetRttCount() {
  startTime = std::chrono::high_resolution_clock::now()
      - std::chrono::milliseconds(500);  // Offset by half a second for window splitting
  curRttCount = 0;
}

/**
 * This is the primary method used by the worker thread to send the packet queue.
 * It wakes up every _sleepInterval_ milliseconds and check if it should shut
 * down or send packets. This is to facilitate mid-test changing of emulated
 * RTT.
 */
void CaaiTest::sendPacketQueue() {
  while (true) {
    // check shutdown flag
    if (!workQueue) return;

    // Count number of times slept.
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepInterval));
    sleepCount++;

    if (sleepCount * sleepInterval >= emuDelay) {
      sleepCount = 0;
      unsigned toSend = sendQueue.size();

      for (unsigned i = 0; i < toSend; i++) {
        pcpp::TcpLayer* tcpLayer = sendQueue.front().first;
        pcpp::Layer* payloadLayer = sendQueue.front().second;

        // not sure why but acking every other packet is problematic with
        // comp.nus.edu.sg homepage. works fine for everything else.

        if (testState <= SSL_HANDSHAKE || payloadLayer != NULL || // Send every packet if establishing connection or there is data to send
            (toSend % 2 && i % 2 == 0) || (toSend % 2 == 0 && i % 2) // Send every other packet if no data
          ) {
        // if (true) {
          session->sendTcp(tcpLayer, payloadLayer);
        } else {
          /**
           * Deletes are commented out due to some problem with freeing null
           * pointers. I'm not sure where/when pcpp frees memory internally.
           */
          // delete tcpLayer;
          // delete payloadLayer;
        }

        sendQueue.pop();
      }
    }
  }
}

/**
 * Enqueue tcp header information and payload to be sent by worker.
 * @param tcpLayer     Pointer to TcpLayer to be used when constructing packet.
 * @param payloadLayer Pointer to layer containing data to be sent.
 */
void CaaiTest::enqueuePacket(pcpp::TcpLayer* tcpLayer,
    pcpp::Layer* payloadLayer) {

  std::uint32_t ackNumber = ntohl(tcpLayer->getTcpHeader()->ackNumber);

  if (ackNumber > session->maxAcked) {
    session->maxAcked = ackNumber;
  }

  std::pair <pcpp::TcpLayer*, pcpp::Layer*> wrapper(tcpLayer, payloadLayer);
  sendQueue.push(wrapper);
}


/**
 * Callback that is used whenever an incoming packet belonging to our experiment
 * is captured.
 *
 * @param packet Parsed packet that was captured.
 */
void CaaiTest::testCallBack(pcpp::Packet* packet) {
  pcpp::TcpLayer* tcpLayer = packet
      ->getLayerOfType<pcpp::TcpLayer>();

  session->updateMaxSeen(tcpLayer);

  // Always present packet to reassembly engine.
  streamReassembly->reassemblePacket(*packet);

  // Exit test if fin or rst received.
  if (tcpLayer->getTcpHeader()->finFlag || tcpLayer->getTcpHeader()->rstFlag) {
    testState = DONE;
  }

  // Crude rtt counting assuming each RTT is ~1
  int pktRtt = (std::chrono::high_resolution_clock::now() - startTime) /
      std::chrono::seconds(1);

  // Record packet information
  // dropCounter is defined in caai.hpp
  dropCounter.record(ntohl(tcpLayer->getTcpHeader()->sequenceNumber), getDataLen(packet));

  // If not waiting for retransmission
  if (testState != DROP_WAIT) {
    // Packet belongs to next RTT
    if (pktRtt > curRttCount) {
      std::cout << pktRtt << ": " << curCwnd << "\n";
      Result res = {
        pktRtt,
        curCwnd,
        dropCounter.totalDropped,
        dropCounter.totalReordered
      };
      testResults.push_back(res);

      if (testState == PRE_DROP && pktRtt == 4) {
        emuDelay = 1000;
      }

      if (testState == POST_DROP && pktRtt == 13) {
        emuDelay = 1000;
      }

      // If number of packets received in this cwnd >= cwndThreshold and no drop
      // has been emulated, do not ack any of the packets in this cwnd and reset
      // counter.
      if (curCwnd >= cwndThresh && testState < DROP_WAIT) {
        // std::printf("DROPPING\n");
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
      // Count packet
      curCwnd++;
    }
  } else if (resent < 1 && // Number of times to wait for packet to be retransmitted.
      ntohl(tcpLayer->getTcpHeader()->sequenceNumber) == dropSeq) {
    dropCounter.totalReordered--; //RTOs get counted as reordering
    std::cout << pktRtt << ": " << curCwnd << "\n";
      Result res = {
        pktRtt,
        curCwnd,
        dropCounter.totalDropped,
        dropCounter.totalReordered
      };
    testResults.push_back(res);
    resent++;
    session->resendLastPacket();  // described in paper to deal with f-rto but wonky
  } else if (ntohl(tcpLayer->getTcpHeader()->sequenceNumber) == dropSeq) {
    std::cout << pktRtt << ": " << curCwnd << "\n";
    Result res = {
      pktRtt,
      curCwnd,
      dropCounter.totalDropped,
      dropCounter.totalReordered
    };
    testResults.push_back(res);
    testState = POST_DROP;
    curCwnd = 1;
    dropCounter.totalReordered--; //RTOs get counted as reordering
    dropCounter.reset(ntohl(tcpLayer->getTcpHeader()->sequenceNumber), getDataLen(packet));

    Result rtoMarker = { 0, 0, 0, 0 };
    testResults.push_back(rtoMarker);
    startWorker();
  } else {
    curCwnd++;
  }

  if (testState == POST_DROP && pktRtt >= 36 && curCwnd != 1) {
    testState = DONE;
    return;
  }

  // Forward packet to correct method depending on test state.
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

/**
 * Responod to SYN/ACK packet while establishing session.
 * @param prev SYN/ACK packet received.
 */
void CaaiTest::handleEstablishSession(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();
  pcpp::tcphdr* prevHeader = prevTcp->getTcpHeader();

  // Check if remote target replied with timestamp set.
  for (pcpp::TcpOptionData* tcpOption = prevTcp->getFirstTcpOptionData();
      tcpOption != NULL;
      tcpOption = prevTcp->getNextTcpOptionData(tcpOption)) {
    if (tcpOption->getType() == pcpp::PCPP_TCPOPT_TIMESTAMP) {
      tsEnabled = true;
    }
  }

  if (prevHeader->synFlag && prevHeader->ackFlag) {
    // Send request via http or https.
    if (https) {
      sendAck(prev);
      std::thread* sslConn = new std::thread(&CaaiTest::connectSsl, this);
      sslConn-> detach();
    } else {
      sendRequest(prev);
    }
    testState = SSL_HANDSHAKE;
  }
}

/**
 * Ack packet received during SSL handshake.
 * @param prev Packet received.
 */
void CaaiTest::handleSslHandshake(pcpp::Packet* prev) {
  sendAck(prev);
  if (!https) {
    testState = PRE_DROP;
  }
}

/**
 * Ack every data packet received.
 * @param prev Packet received.
 */
void CaaiTest::handlePreDrop(pcpp::Packet* prev) {
  sendAck(prev);
}

/**
 * Respond to packets received after RTO.
 * @param prev Packet received.
 */
void CaaiTest::handlePostDrop(pcpp::Packet* prev) {
  std::uint32_t pktSeq = ntohl(prev->getLayerOfType<pcpp::TcpLayer>()
    ->getTcpHeader()->sequenceNumber);

  // Send dup ack in first 3 RTTs after RTO if remote attempts to advance window
  // instead of retransmit "lost" packets
  if ((maxSeenAfterRto + 10 * mss < pktSeq) && curRttCount < 3) {
    sendDupAck(prev);
  } else {
    maxSeenAfterRto = pktSeq;
    sendAck(prev);
  }
}

/**
 * Test done. Do nothing.
 * @param prev Packet received.
 */
void CaaiTest::handleDone(pcpp::Packet* prev) {
  return;
}

/**
 * Construct and enqueue tcpLayer to ack previous packet received.
 * @param prev Packet to be acked.
 */
void CaaiTest::sendAck(pcpp::Packet* prev) {
  pcpp::TcpLayer* prevTcp = prev->getLayerOfType<pcpp::TcpLayer>();

  pcpp::TcpLayer* tcpLayer = new pcpp::TcpLayer(session->sport, session->dport);

  // Sets TimeStamp opt. pcpp does not automatically pad it to fill complete octets
  // so we have to do it ourselves.
  if (tsEnabled) {
    setTSOpt(tcpLayer, prevTcp);
    addNopOpt(tcpLayer);
    tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
  }

  pcpp::tcphdr* header = tcpLayer->getTcpHeader();
  header->sequenceNumber = htonl(session->seq);
  header->windowSize = htons(tcpOptWSize);

  int prevDataLen = getDataLen(prev);
  // No data sent, nothing to ack.
  if (prevDataLen == 0) {
    // delete tcpLayer;
    return;
  }

  // Set ack number and flag.
  header->ackNumber = htonl(
      ntohl(prevTcp->getTcpHeader()->sequenceNumber) +
      prevDataLen + prevTcp->getTcpHeader()->synFlag);
  header->ackFlag = 1;

  enqueuePacket(tcpLayer, NULL);
}

/**
 * Enqueue a duplicate ack packet for sending. The ack number for this packet
 * will be the highest ack number that we have sent before this.
 * @param prev Packet to be acked.
 */
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
    // delete tcpLayer;
    return;
  }

  header->ackNumber = htonl(session->maxAcked);
  header->ackFlag = 1;

  enqueuePacket(tcpLayer, NULL);
}


/**
 * Enqueue packet to send data (used by WolfSSL) from some buffer. Packet info
 * such as Timestamps and ack number will be based on last received packet.
 * @param buf     Pointer to data to be sent
 * @param dataLen Length of data to be sent
 */
void CaaiTest::sendData(char* buf, int dataLen) {
  if (dataLen > mss) {
    // This should never happen
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
  // delete buf;
}

/**
 * Enqueue request string to be sent. This is only used for plain HTTP requests.
 * This is typically sent in response to SYN/ACK packet.
 * @param prev Prev SYN/ACK packet.
 */
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

  std::string reqStr = makeGetStr();
  char* reqCStr = strdup(reqStr.c_str());

  pcpp::PayloadLayer* req = new pcpp::PayloadLayer(
    reinterpret_cast<std::uint8_t*>(reqCStr), std::strlen(reqCStr), true);

  session->seq += req->getDataLen();

  enqueuePacket(tcpLayer, req);
}

/**
 * Construct and enqueue SYN packet for sending.
 */
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

/**
 * Writes tcp option data for initial syn packet.
 * @param synTcpLayer Pointer to tcp layer of syn packet.
 */
void CaaiTest::setInitialOpt(pcpp::TcpLayer* synTcpLayer) {
  setTSOpt(synTcpLayer, NULL);
  synTcpLayer->addTcpOption(pcpp::TCPOPT_MSS, 4,
      reinterpret_cast<std::uint8_t*>(&tcpOptMss));
  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_WINDOW, 3,
      reinterpret_cast<std::uint8_t*>(&tcpOptWscale));

  synTcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_EOL, 1, 0);
}

/**
 * Write tcp timestamp option data to a tcp layer based on tcp layer of previous
 * packet (if present).
 * @param targetTcpLayer Pointer to tcp layer to write timestamp option data.
 * @param prevTcpLayer   Pointer to tcp layer of previous received packet.
 */
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

/**
 * Calculate datalen of previous packet.
 * @param  p Pointer to previous (raw) packet.
 * @return   Number of bytes of data in packet.
 */
int CaaiTest::getDataLen(pcpp::Packet* p) {
  pcpp::TcpLayer* tcpLayer = p->getLayerOfType<pcpp::TcpLayer>();
  pcpp::IPv4Layer* ipLayer = p->getLayerOfType<pcpp::IPv4Layer>();

  return ntohs(ipLayer->getIPv4Header()->totalLength) -
      ipLayer->getIPv4Header()->internetHeaderLength * 4 -
      tcpLayer->getTcpHeader()->dataOffset * 4;
}

/**
 * Add NOP option to tcpLayer for padding purposes.
 * @param tcpLayer Pointer to tcp layer to add NOP opt.
 */
void CaaiTest::addNopOpt(pcpp::TcpLayer* tcpLayer) {
  std::uint8_t* one = new std::uint8_t(1);
  tcpLayer->addTcpOption(pcpp::PCPP_TCPOPT_NOP, 1, one);
  // delete one;
}

/**
 * Start test.
 */
void CaaiTest::startTest() {
  startWorker();
  setupWolfSsl();
  sendSyn();
}

/**
 * Stops packet queue worker.
 */
void CaaiTest::cleanUp() {
  stopWorker();
}

/**
 * Return whether the test needs to be restarted.
 * Not used right now.
 * @return Whether test should be restarted.
 */
bool CaaiTest::checkRestartTest() {
  return testState == ESTABLISH_SESSION ? true : false;
}

/**
 * Return whether test is complete.
 * @return Whether test is complete.
 */
bool CaaiTest::getTestDone() {
  return testState == DONE;
}

/**
 * Print test results to std::cout.
 */
void CaaiTest::printResults() {
  std::cout << "\n======TEST DONE=====\n";
  /**
   * This block of code prints the data received.
   */
  // unsigned read = 10;
  // char printer[200];
  // while (read != 0){
  //   bzero(printer, sizeof(printer));
  //   read = rcvBuffer.readsome(printer, 199);
  //   std::printf("%s", printer);
  // }

  for (Result r : testResults) {
    std::cout << "RTT: " << std::left << std::setw(5) << r.rtt << ", "
              << "CWND: " << std::left << std::setw(5) << r.cwnd << ", "
              << "CUMULATIVE LOST: " << std::left << std::setw(5) << r.dropped << ", "
              << "CUMULATIVE REORDERED: " << std::left << std::setw(5) << r.reordered << "\n";
  }
}
