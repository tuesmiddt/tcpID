#include "main.hpp"
#include "session.hpp"
#include "unistd.h"
#include <string.h>

/**
 * Parse command line options and executes test.
 * Example formats:
 * tcpID https://www.hostname.com/path/to/file -d
 * tcpID http://www.hostname.com
 */
int main(int argc, char **argv) {
  char *target = NULL;
  bool dumpTCP = false;
  int c;


/* Parse command line arguments. */
  while ((c = getopt(argc, argv, ":ds")) != -1)
      switch (c) {
          case 'd':
              dumpTCP = true;
              break;
          default:
              abort();
      }

  if (argc - optind == 1)
      target = argv[optind];
  else
      abort();

  TestSession session(target, dumpTCP);

  std::cout << session.srcIP;
  std::cout << "\n";
  std::cout << session.dstIP;
  std::cout << "\n";
  std::cout << session.dstName;
  std::cout << "\n";

  session.cleanUp();
  return 0;
}
