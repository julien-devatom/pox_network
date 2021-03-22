'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''
import csv

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

''' Add your imports here ... '''

log = core.getLogger()
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
policyFile = "./firewall-policies.csv"

''' Add your global variables here ... '''

class Firewall(EventMixin):

    def __init__(self):
        self.deny = []
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")
        with open(policyFile, 'rb') as f:
            myfile = csv.DictReader(f)
            for l in myfile:
                self.deny.append((EthAddr(l['mac_0']), EthAddr(l['mac_1'])))
                self.deny.append((EthAddr(l['mac_1']), EthAddr(l['mac_0'])))


    def _handle_ConnectionUp(self, event):
        """
        Create a flow to drop all packets
        with src & dst not allowed by the firewall
        """
        for (u, v) in self.deny:
            match = of.ofp_match()
            match.dl_src = u
            match.dl_dst = v
            msg = of.ofp_flow_mod()
            msg.match = match
            msg.idle_timeout = 0
            msg.hard_timeout = 0
            event.connection.send(u)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))


def launch():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
