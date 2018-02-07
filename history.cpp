#include "history.hpp"

#include <iostream>

History::History() { }

int History::push(pcpp::Packet* packet) {
  std::uint32_t key = ntohl(packet
      ->getLayerOfType<pcpp::TcpLayer>()
      ->getTcpHeader()
      ->sequenceNumber);
  auto res = store.find(key);
  if (res != store.end()) {
    res->second.first = packet;
    res->second.second++;
    return res->second.second;
  } else {
    store.emplace_hint(store.end(), key,
        std::pair<pcpp::Packet*, int>(packet, 0));
    return 0;
  }
}

pcpp::Packet* History::getMax() {
  if (store.empty()) {
    return NULL;
  }

  return store.rbegin()->second.first;
}

