#ifndef IOSTREAM
#define IOSTREAM
#include <iostream>
#endif

#ifndef CSTDINT
#define CSTDINT
#include <cstdint>
#endif

#ifndef CTIME
#define CTIME
#include <ctime>
#endif

#ifndef VECTOR
#define VECTOR
#include <vector>
#endif

#ifndef THREAD
#define THREAD
#include <thread>
#endif

#ifndef QUEUE
#define QUEUE
#include <queue>
#endif

#ifndef CHRONO
#define CHRONO
#include <chrono>
#endif

#ifndef CMATH
#define CMATH
#include <cmath>
#endif

#ifndef UTILITY
#define UTILITY
#include <utility>
#endif

#ifndef CLIMITS
#define CLIMITS
#include <climits>
#endif

#ifndef SSTREAM
#define SSTREAM
#include <sstream>
#endif

#ifndef ISTREAM
#define ISTREAM
#include <istream>
#endif

#ifndef ARPA_INET_H
#define ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef PCAP_LIVE_DEVICE_LIST_H
#define PCAP_LIVE_DEVICE_LIST_H
#include "PcapLiveDeviceList.h"
#endif

#ifndef PACKET_H
#define PACKET_H
#include "Packet.h"
#endif

#ifndef ETH_LAYER_H
#define ETH_LAYER_H
#include "EthLayer.h"
#endif

#ifndef IPV4_LAYER_H
#define IPV4_LAYER_H
#include "IPv4Layer.h"
#endif

#ifndef TCP_LAYER_H
#define TCP_LAYER_H
#include "TcpLayer.h"
#endif

#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H
#include "TcpReassembly.h"
#endif

#ifndef PAYLOAD_LAYER_H
#define PAYLOAD_LAYER_H
#include "PayloadLayer.h"
#endif

#ifndef CMATH
#define CMATH
#include <cmath>
#endif

#ifndef IOMANIP
#define IOMANIP
#include <iomanip>
#endif

#ifndef STRINGH
#define STRINGH
#include <string.h>
#endif

// #ifndef SAFE_QUEUE
// #define SAFE_QUEUE

// #ifndef MUTEX
// #define MUTEX
// #include <mutex>
// #endif

// #ifndef QUEUE
// #define QUEUE
// #include <queue>
// #endif

// #ifndef CONDITION_VARIABLE
// #define CONDITION_VARIABLE
// #include <condition_variable>
// #endif

// template <class T> class SafeQueue {
//  public:
//   SafeQueue(): q(), m(), c() {}

//   void enqueue(T ) {
//     std::unique_lock<std::mutex> lock(m);
//     q.push(t);
//   }

//   void dequeue() {

//   }


//  private:
//   std::queue<T> q;
//   mutable std::mutex m;
//   std::condition_variable c;
// };

// #endif  // SAFE_QUEUE_

#ifndef CAAI_HPP
#define CAAI_HPP

// Include guards work really weirdly with wolfssl for some reason
#include <wolfssl/ssl.h>

struct Result {
  int rtt;
  int cwnd;
  int dropped;
  int reordered;
};

struct DropCounter {
  std::uint32_t next;
  int totalReordered;
  int totalDropped;
  int prevDataLen;
  int mss;

  void reset(std::uint32_t seq, int datalen) {
    next = seq + datalen;
    prevDataLen = datalen;
  }

  void record(std::uint32_t seq, int datalen) {
    if (next == 0) {
      next = seq;
      prevDataLen = datalen;
    } else if (seq < next) {
      totalReordered++;
    } else if (seq == next) {
      next += datalen;
      prevDataLen = datalen;
    } else {
      int segSize = prevDataLen > 0 ? prevDataLen : mss;
      totalDropped += std::ceil((seq-next)/segSize);
      next = seq + datalen;
      prevDataLen = datalen;
    }
    // if (maxSeen == 0) {
    //   maxSeen = seq;
    // } else if (seq < maxSeen) {
    //   totalReordered++;
    // } else if (seq - maxSeen <= datalen || seq-maxSeen == 1) {
    //   maxSeen = seq;
    // } else {
    //   int segSize = datalen > 0 ? datalen : mss;
    //   totalReordered += std::ceil((seq-maxSeen)/datalen);
    // }
  };
};

class TestSession;
class CaaiTest {
 public:
  int testState = 1;

  std::uint16_t tcpOptMss;
  std::uint16_t tcpOptWscale;

  explicit CaaiTest(TestSession *);
  void testCallBack(pcpp::Packet* packet);
  void startTest();
  bool checkRestartTest();
  bool getTestDone();
  void cleanUp();
  void printResults();

  // SSL CALLBACKS
  static int sslWriteCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx);
  static int sslReadCallback(WOLFSSL* ssl, char* buf, int sz, void* ctx);

 private:
  DropCounter dropCounter = {};
  int connectionAttempts = 0;
  int emuDelay = 1000;  // send Delay in milliseconds
  int sleepCount = 0;
  int sleepInterval = 100;  // check for changes to send delay every 100 milliseconds
  int curRttCount = 0;
  int curCwnd = 0;
  int mss;
  int resent = 0;
  bool envB = false;
  bool tsEnabled = false;
  bool https = false;
  std::uint32_t dropSeq;
  std::uint32_t maxSeenAfterRto;
  int cwndThresh = 256;
  bool workQueue;
  std::uint16_t tcpOptWSize = 65535;
  std::chrono::time_point<std::chrono::high_resolution_clock> startTime;
  std::vector<Result> testResults;

  std::queue<std::pair <pcpp::TcpLayer*, pcpp::Layer*>> sendQueue;
  std::thread* sendWorker;
  pcpp::TcpReassembly* streamReassembly;
  std::stringstream rcvBuffer;

  WOLFSSL_CTX* sslCtx = NULL;
  WOLFSSL* ssl = NULL;
  std::string caCert = "tls-ca-bundle.pem";

  TestSession* session;
  static const int ESTABLISH_SESSION = 1;
  static const int SSL_HANDSHAKE = 2;
  static const int PRE_DROP = 3;
  static const int DROP_WAIT = 4;
  static const int POST_DROP = 5;
  static const int DONE = 6;

  static void reassemblyCallback(
      int side, pcpp::TcpStreamData data, void* cookie);
  // void makeRcvBuffer();
  void sendPacketQueue();
  void startWorker();
  void stopWorker();
  void enqueuePacket(pcpp::TcpLayer* tcpLayer, pcpp::Layer* payloadLayer);
  void sendSyn();
  std::string makeGetStr();
  void resetRttCount();
  int getDataLen(pcpp::Packet* p);
  void setInitialOpt(pcpp::TcpLayer* synTcpLayer);
  void setTSOpt(pcpp::TcpLayer* targetTcpLayer, pcpp::TcpLayer* prevTcpLayer);
  void addNopOpt(pcpp::TcpLayer* tcpLayer);
  void sendAck(pcpp::Packet* prev);
  void sendDupAck(pcpp::Packet* prev);
  void sendData(char* buf, int dataLen);
  void sendRequest(pcpp::Packet* prev);
  void handlePacket(pcpp::Packet* prev);
  void handleEstablishSession(pcpp::Packet* prev);
  void handleSslHandshake(pcpp::Packet* prev);
  void handlePreDrop(pcpp::Packet* prev);
  void handlePostDrop(pcpp::Packet* prev);
  void handleDone(pcpp::Packet* prev);
  void setupWolfSsl();
  void connectSsl();
};

#endif  // CAAI_HPP_
