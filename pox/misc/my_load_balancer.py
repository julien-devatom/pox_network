from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()
IDLE_TIMEOUT = 60
HARD_TIMEOUT = 0
LOAD_BALANCER_IP = IPAddr('10.0.0.254')
LOAD_BALANCER_MAC = EthAddr('00:00:00:00:00:FE')


class LoadBalancer(EventMixin):
    class Server:
        def __init__(self, ip, mac, port):
            self.ip = IPAddr(ip)
            self.mac = EthAddr(mac)
            self.port = port

        def __str__(self):
            return ', '.join[str(self.ip), str(self.mac), str(self.port)]

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.servers = [
            self.Server('10.0.0.1', '00:00:00:00:00:01', 1),
            self.Server('10.0.0.2', '00:00:00:00:00:02', 2)
        ]
        self.last_server = 0

    def get_next_server(self):
        self.last_server = (self.last_server + 1) % len(self.servers)
        return self.servers[self.last_server]

    def handle_request(self, packet, event):

        server = self.get_next_server()

        # ----------- Server to Client ---------------------------
        # Set packet matching
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.match.in_port = server.port
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.dl_src = server.mac
        msg.match.dl_dst = server.mac
        msg.match.nw_src = server.ip
        msg.match.nw_dst = packet.next.srcip
        log.debug("The server for %s is %s" % (packet.next.srcip, server.ip))

        # Append actions
        msg.actions.append(of.ofp_action_dl_addr.set_src(LOAD_BALANCER_MAC))
        msg.actions.append(of.ofp_action_nw_addr.set_src(LOAD_BALANCER_IP))
        # Forward the packet
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)

        # ----------- Client to Server ---------------------------
        # Forward the incoming packet

        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.data = event.ofp

        # Set packet matching
        msg.match.in_port = event.port
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.dl_dst = LOAD_BALANCER_MAC
        msg.match.nw_src = packet.next.srcip
        msg.match.nw_dst = LOAD_BALANCER_IP

        # - Forward to the chosen server

        msg.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
        msg.actions.append(of.ofp_action_output(port=server.port))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):

        packet = event.parse()
        if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
            # Drop
            msg = of.ofp_packet_out()
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)
        elif packet.type == packet.ARP_TYPE:
            if packet.next.protodst != LOAD_BALANCER_IP:
                # Flood
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = event.port
                self.connection.send(msg)
                return
            log.debug("Recieve an ARP request from %s for %s" % (str(packet.next.protosrc), packet.next.protodst))
            self.handle_arp(packet, event.port)
        elif packet.type == packet.IP_TYPE:
            print('ip packet')
            if packet.next.dstip != LOAD_BALANCER_IP:
                return
            log.debug('Recieve an IPv4 packet from %s' % packet.next.srcip)
            self.handle_request(packet, event)

    def handle_arp(self, packet, port):
        arp_req = packet.next
        arp_rep = arp()
        arp_rep.opcode = arp.REPLY
        arp_rep.hwsrc = LOAD_BALANCER_MAC
        arp_rep.hwdst = arp_req.hwsrc
        arp_rep.protosrc = LOAD_BALANCER_IP

        eth_rep = ethernet()
        eth_rep.type = ethernet.ARP_TYPE
        eth_rep.dst = packet.src
        eth_rep.src = LOAD_BALANCER_MAC
        eth_rep.set_payload(arp_rep)

        msg = of.ofp_packet_out()
        msg.data = eth_rep.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = port
        log.debug("Sending ARP Packet Out" % ())
        self.connection.send(msg)
        return


class load_balancer(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % event.connection)
        LoadBalancer(event.connection)


def launch():
    core.registerNew(load_balancer)
