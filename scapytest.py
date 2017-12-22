from scapy.all import *
import socket
import fwutil
import capture
import processpkt
import history
import pktutil
import time
import CAAI
from scapy.layers import http
from multiprocessing import Queue

def getsrcIP():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        srcIP = s.getsockname()[0]
        s.close()
        return srcIP
    except:
        raise Exception("Could not get Source IP")


def runTest():
    dstHostname = "www.comp.nus.edu.sg"
    dstIP = "137.132.80.57"
    iface = "enp0s31f6"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))

    sport = s.getsockname()[1]
    dport = 80

    sessionParams = {}

    sessionParams["iface"] = iface
    sessionParams["sport"] = sport
    sessionParams["dport"] = dport
    sessionParams["dstHostname"] = dstHostname
    sessionParams["dstIP"] = dstIP
    sessionParams["srcIP"] = getsrcIP()
    sessionParams["seq"] = random.getrandbits(32)
    sessionParams["ipHdr"] = IP(src = sessionParams["srcIP"], dst = sessionParams["dstIP"])
    sessionParams["filterQueue"] = Queue()
    sessionParams["sendQueue"] = Queue()
    sessionParams["history"] = history.makeHistory()
    sessionParams["testParams"] = CAAI.setup()
    sessionParams["mss"] = 1480
    sessionParams["rcvNext"] = 0
    sessionParams["iss"] = sessionParams["seq"]
    sessionParams["irs"] = 0
    sessionParams["startTime"] = 0


    # Start Capture
    capture.spawnFilter(sessionParams)
    processpkt.spawnFilterWatcher(sessionParams)

    time.sleep(2)

    initTCPOptions = [pktutil.makeTS()]

    syn = TCP(
            sport = sessionParams["sport"],
            dport = sessionParams["dport"],
            flags = "S",
            options = initTCPOptions,
            seq = sessionParams["seq"])


    fwutil.blockRSTOut(sessionParams)
    fwutil.disableSegOL(sessionParams)

    synack = sr1(sessionParams["ipHdr"]/syn)

    # synack.show()

    # ack = TCP(
    #         sport = sessionParams["sport"],
    #         dport = sessionParams["dport"],
    #         flags = "A",
    #         seq = sessionParams["seq"] + 1,
    #         ack = synack.seq + 1)

    # send(sessionParams["ipHdr"]/ack)

    getStr = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % sessionParams["dstHostname"]

    request = sessionParams["ipHdr"] / TCP(
            sport = sessionParams["sport"],
            dport = sessionParams["dport"],
            flags = "A",
            seq = sessionParams["seq"] + 1,
            options = [pktutil.makeTS(synack)],
            ack = synack.seq + 1) / getStr


    request.show()

    ans, unans = sr(request, multi = 1, timeout=1)

    processpkt.killFilterWatcher()
    capture.killFilter()
    fwutil.enableSegOL(sessionParams)
    fwutil.clearRules()


if __name__ == "__main__":
    runTest()