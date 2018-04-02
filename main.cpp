#include "main.hpp"
#include "session.hpp"

int main() {
  char target[] = "www.gearbest.com";
  TestSession session(target, 443);

  std::cout << session.srcIP;
  std::cout << "\n";
  std::cout << session.dstIP;
  std::cout << "\n";
  std::cout << session.dstName;
  std::cout << "\n";

  session.cleanUp();
  return 0;
}