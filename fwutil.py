from subprocess import call
import re

rules = []

segmentationTypes = ["gro", "tso", "gso"]

def blockRSTOut(sessionParams):
    rule = "iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport %d -d %s --dport %d -j DROP" % \
        (sessionParams["sport"], sessionParams["dstIP"], sessionParams["dport"])
    if call(rule.split()) == 0:
        rules.append(rule)


def printRules():
    call("iptables -L".split())


def disableSegOL(sessionParams):
    for t in segmentationTypes:
        cmd = "ethtool -K %s %s off" % (sessionParams["iface"], t)
        call(cmd.split())


def clearRules():
    for rule in rules:
        cmd = re.sub(r"iptables -A", r"iptables -D", rule)
        if cmd == rule or call(cmd.split()) != 0:
            raise Exception("Failed to remove iptables rule %s" % rule)


def enableSegOL(sessionParams):
    for t in segmentationTypes:
        cmd = "ethtool -K %s %s on" % (sessionParams["iface"], t)
        call(cmd.split())