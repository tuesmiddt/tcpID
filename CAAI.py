from scapy.all import *
import testutil
import time

ESTABLISHSESSION = 1
SSHHANDSHAKE = 2
PREDROP = 3
POSTDROP = 4

def setup():
    testParams = {}
    testParams["testState"] = 1
    testParams["rtt"] = 0
    testParams["runTime"] = 0
    testParams["rttCount"] = 0
    testParams["sendDelay"] = 0
    testParams["sentRequest"] = 1

    return testParams

def runTest(sessionParams):
    syn = testutil.makeSynPkt(sessionParams)
    sessionParams["startTime"] = time.time()
    enqueuePkt(syn, sessionParams)

    while True:
        if sessionParams["testParams"]["testState"] = 0:
            break

        if time.time() - sessionParams["startTime"] > 40:
            break

        time.sleep(1)
        sessionParams["testParams"]["runTime"] += 1

def CAAIRespond(pkt, sessionParams):
    testParams = sessionParams["testParams"]

    if not testutil.isValid(pkt, sessionParams):
        return

    if testParams["testState"] == ESTABLISHSESSION:
        handleEstablishSession(pkt, sessionParams)

    if testParams["testState"] == SSHHANDSHAKE:
        handleSSHHandshake(pkt, sessionParams)

    if testParams["testState"] == PREDROP:
        handlePreDrop(pkt, sessionParams)

    if testParams["testState"] == POSTDROP:
        handlePostDrop(pkt, sessionParams)

def handlePreDrop(pkt, sessionParams):
    if testutil.isRTO(pkt, sessionParams):
        return

    ackPkt = testutil.makeAckPkt(pkt, sessionParams)

    if sessionParams["testParams"]["sendRequest"]:
        ackPkt = ackPkt/testutil.makePayload("GET", sessionParams)

    enqueuePkt(ackPkt, sessionParams)


def handleSSHHandshake(pkt, sessionParams):
    sessionParams["testParams"]["testState"] += 1


def handleEstablishSession(pkt, sessionParams):
    if testutil.isRTO(pkt, sessionParams):
        # TODO: HANDLE RTO BEHAVIOUR
        return

    if pkt[TCP].flags == "SA":
        ackPkt = testutil.makeAckPkt(pkt, sessionParams)
        enqueuePkt(ackPkt, sessionParams)
    elif pkt[TCP].flags == "A":
        sessionParams["testParams"]["testState"] += 1

def enqueuePkt(p, sessionParams):
    sessionParams["sendQueue"].put(p)


def updateRTT(pkt, sessionParams):
    testParams = sessionParams["testParams"]

    if testParams["rtt"] == 0:
        testParams["rtt"] = testutil.calcRTT(pkt, sessionParams)

    testParams["rtt"] = 0.8 * testParams["rtt"] + 0.2 * testutil.calcRTT(pkt, sessionParams)
