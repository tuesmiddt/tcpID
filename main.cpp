#include "main.hpp"
#include "session.hpp"

int main() {
  struct TestSession Session;

  std::cout << Session.srcIP;
  std::cout << Session.dstIP;
  std::cout << Session.dstName;
  return 0;
}

