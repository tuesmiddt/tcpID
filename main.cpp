#include "main.hpp"
#include "session.hpp"

int main() {
  char target[] = "www.comp.nus.edu.sg";
  TestSession Session(target, 80);

  std::cout << Session.srcIP;
  std::cout << "\n";
  std::cout << Session.dstIP;
  std::cout << "\n";
  std::cout << Session.dstName;
  std::cout << "\n";

  Session.cleanUp();
  return 0;
}

