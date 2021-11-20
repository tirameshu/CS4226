'''
Please add your name: Wang Xinman
Please add your matric number: A0180257E
'''

import datetime

from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

TTL = 30
IDLE_TTL = TTL
HARD_TTL = TTL

REGULAR = 0
PREMIUM = 1

FIREWALL_PRIORITY = 200
QOS_PRIORITY = 100

class Controller(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)
        # Used to store MAC address and ports (Task 2)
        self.mac_port = {}
        self.mac_port_ttl = {}

        # For Premium Service Class (Task 4)
        self.premium = []

    # You can write other functions as you need.
    def _handle_PacketIn (self, event):
        # For local variable reference
        packet = event.parsed
        dpid = event.dpid
        in_port = event.port
        src_mac = packet.src
        dst_mac = packet.dst

        log.info("=== Entry: At s%s, src_mac=%s, dst_mac=%s ===", dpid, src_mac, dst_mac)


        # install entries to the route table (Task 2/4)
        def install_enqueue(event, packet, out_port, qid):
            log.info("Installing flow for %s:%i -> %s:%i", src_mac, in_port, dst_mac, out_port)
            message = of.ofp_flow_mod()
            message.match = of.ofp_match.from_packet(packet, in_port)
            message.actions.append(of.ofp_action_enqueue(port = out_port, queue_id = qid))
            message.data = event.ofp

            # Add TTL (Task 3)
            message.idle_timeout = IDLE_TTL
            message.hard_timeout = HARD_TTL
            # Set to Premium Service Channel priority (Task 4)
            message.priority = qid * QOS_PRIORITY
            event.connection.send(message)
            log.info("Packet with queue ID %i sent via out_port %i\n", qid, out_port)
            return

        def clear_expired():
            '''
            Remove expired entries in mac port table
            '''
            assert(dpid in self.mac_port_ttl)
            if dst_mac in self.mac_port_ttl[dpid] and self.mac_port_ttl[dpid][dst_mac] + datetime.timedelta(
                    seconds=TTL) <= datetime.datetime.now():
                    log.debug("** Switch %i: Timeout!... Unlearn MAC: %s, Port: %s" % (
                    dpid, dst_mac, self.mac_port[dpid][dst_mac]))
                    self.mac_port[dpid].pop(dst_mac)
                    self.mac_port_ttl[dpid].pop(dst_mac)

                    # get the queue it should go into

        # Check the packet and decide how to route the packet
        def forward(message = None):

            # Store the in_port from where the packet comes from if empty
            if dpid not in self.mac_port:
                self.mac_port[dpid] = {}
                self.mac_port_ttl[dpid] = {}

            if self.mac_port[dpid].get(src_mac) == None:
                self.mac_port[dpid][src_mac] = in_port
                self.mac_port_ttl[dpid][src_mac] = datetime.datetime.now()


            # Get src_mac and dst_mac IP address from the packet
            src_ip = None
            dst_ip = None

            # Checks the packet type to determine where to send the packet (Task 3/4)
            if packet.type == packet.IP_TYPE:
                log.info("Packet is IP type %s", packet.type)
                ip_packet = packet.payload
                src_ip = ip_packet.srcip
                dst_ip = ip_packet.dstip
            elif packet.type == packet.ARP_TYPE:
                log.info("Packet is ARP type %s", packet.type)
                arppacket = packet.payload
                src_ip = arppacket.protosrc
                dst_ip = arppacket.protodst
            else:
                log.info("Packet is Unknown type %s", packet.type)
                src_ip = None
                dst_ip = None

            qid = REGULAR
            if src_ip and dst_ip in self.premium:
                qid = PREMIUM

            # If packet dst_mac indicates it is a multicast, packet is flooded (Task 2)
            if dst_mac.is_multicast:
                return flood("Multicast to dst_mac %s -- flooding" % (dst_mac))

            # If port to reach dst_mac is not found, packet is flooded (Task 2)
            if dst_mac not in self.mac_port[dpid]:
                return flood("Destination dst_mac %s unknown -- flooding" % (dst_mac))

            # Add the node in_port to the route table for learning switch (Task 2)
            out_port = self.mac_port[dpid][dst_mac]
            install_enqueue(event, packet, out_port, qid)

        # When it knows nothing about the dst_mac, flood but don't install the rule (Task 2)
        def flood (message = None):
            log.debug(message)
            floodmsg = of.ofp_packet_out()
            floodmsg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            floodmsg.data = event.ofp
            floodmsg.in_port = in_port
            event.connection.send(floodmsg)
            log.info("Flooding...")
            return

        forward()
        clear_expired()
        return


    def _handle_ConnectionUp(self, event):
        # Local variable for reference
        dpid = event.dpid
        log.debug("Switch %s has come up.", dpid)

        def readPoliciesFromFile(file):
            fw_policies = []

            with open(file) as fd:
                N, M = fd.readline().split()
                for i in range(int(N)):
                    params = [x.strip() for x in fd.readline().split(",")]
                    if len(params) == 1:
                        fw_policies.append((params[0], None, None))
                    elif len(params) == 2:
                        fw_policies.append((None, params[0], params[1]))
                    else:
                        fw_policies.append(params)

                for i in range(int(M)):
                    ip = fd.readline().strip()
                    self.premium.append(ip)

            return fw_policies

        # Send the firewall policies to the switch (Task 3)
        # Send the firewall policies to the switch
        def sendFirewallPolicy(connection, policy):
            from_IP, to_IP, to_port = policy
            log.debug("** Switch %s: Adding Firewall Rule Src: %s, Dst: %s:%s" % (dpid, from_IP, to_IP, to_port))

            msg = of.ofp_flow_mod()

            msg.priority = FIREWALL_PRIORITY

            # Set flow to send to no where
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

            # ethernet type should be ipv4 (0x800)
            msg.match.dl_type = 0x800

            # IP header protocol number should be TCP (6)
            #   ICMP - 1, UDP - 17
            msg.match.nw_proto = 6

            # Source IP Address
            if from_IP: msg.match.nw_src = IPAddr(from_IP)
            if to_IP:
                # Destination IP Address:Port Number
                msg.match.nw_dst = IPAddr(to_IP)
                msg.match.tp_dst = int(to_port)

            connection.send(msg)
            log.debug("** Switch %s: Firewall Rule added!" % (dpid,))

        fw_policies = readPoliciesFromFile("policy.in")
        for fw_policy in fw_policies:
            sendFirewallPolicy(event.connection, fw_policy)


def launch():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(Controller)