#include "history.hpp"

#include <iostream>

History::History() { }

int History::push(pcpp::Packet* packet) {
  pcpp::Packet* copy = new pcpp::Packet(*packet);
  std::uint32_t key = ntohl(copy
      ->getLayerOfType<pcpp::TcpLayer>()
      ->getTcpHeader()
      ->sequenceNumber);
  auto res = store.find(key);
  if (res != store.end()) {
    std::get<0>(res->second) = copy;
    std::get<2>(res->second)++;
    // res->second.first = copy;
    // res->second.second++;
    return std::get<2>(res->second);
  } else {
    auto entry = std::make_tuple(copy,
        std::chrono::high_resolution_clock::now(), 0);
    store.emplace_hint(store.end(), key, entry);
    return 0;
  }
}

pcpp::Packet* History::getMax() {
  if (store.empty()) {
    return NULL;
  }

  return std::get<0>(store.rbegin()->second);
}



std::chrono::time_point<std::chrono::high_resolution_clock>
    History::getTimeBySeq(std::uint32_t key) {
  auto res = store.find(key);
  if (res != store.end()) {
    return std::get<1>(res->second);
  }
  return std::chrono::system_clock::from_time_t(0);
}

std::chrono::time_point<std::chrono::high_resolution_clock>
    History::getTimeByAck(std::uint32_t key) {
  auto iter = store.rbegin();
  int i = 0;

  while (i < 3000 && iter != store.rend()) {
    if (ntohl(std::get<0>(iter->second)
        ->getLayerOfType<pcpp::TcpLayer>()
        ->getTcpHeader()
        ->ackNumber) == key) {
      return std::get<1>(iter->second);
    }

    iter++;
  }

  return std::chrono::system_clock::from_time_t(0);
}
