'''
Please add your name: Wang Xinman
Please add your matric number: A0180257E
'''

import os
import sys
import atexit

from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import Link
from mininet.node import RemoteController

net = None
interface_bw = {}

class TreeTopo(Topo):

    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Gets the names and number of hosts, switches and links from topology.in (Task 1)
        filename = "topology.in"
        with open(filename, "r") as topo_input:
            firstline = topo_input.readline().split(' ')

            # Number of hosts, switches and links are stored in the first line of topology.in (Task 1)
            num_hosts = int(firstline[0])
            num_switches = int(firstline[1])
            num_links = int(firstline[2])

            # Add hosts to the mininet
            # > self.addHost('h%d' % [HOST NUMBER])
            for i in range(num_hosts):
                host = self.addHost('h%d' % (i+1))

            # Add switches to the mininet
            # > sconfig = {'dpid': "%016x" % [SWITCH NUMBER]}
            # > self.addSwitch('s%d' % [SWITCH NUMBER], **sconfig)
            for j in range(num_switches):
                sconfig = {'dpid': "%016x" % (j+1)}
                switch = self.addSwitch('s%d' % (j+1), **sconfig)

            # Add links to the mininet
            # > self.addLink([HOST1], [HOST2])
            for k in range(num_links):
                link = topo_input.readline().strip().split(',')
                node1 = link[0]
                node2 = link[1]
                bw = int(link[2]) * 1000000

                self.addLink(node1, node2, bw=bw)

                # for qos
                port = self.port(node2, node1)[0] # src port = port for switch
                interface = "%s-eth%s" % (node2, port) # eg s1-eth1
                interface_bw[interface] = bw


def startNetwork():
    def set_qos():
        for interface in interface_bw:
            bw = interface_bw[interface]
            cmd = 'sudo ovs-vsctl -- set Port %s qos=@newqos \
                        -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1 \
                        -- --id=@q0 create Queue other-config:max-rate=%s \
                        -- --id=@q1 create Queue other-config:min-rate=%s' % (interface, bw, 0.5 * bw, 0.8 * bw)

            os.system(cmd)

    info('** Creating the tree network\n')
    topo = TreeTopo()

    # Changed server IP to 127.0.0.1 for the host-only adaptor
    global net
    net = Mininet(topo=topo, link = Link,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()

    set_qos()

    info('** Running CLI\n')
    CLI(net)

def stopNetwork():
    if net is not None:
        net.stop()
        # Remove QoS and Queues
        os.system('sudo ovs-vsctl --all destroy Qos')
        os.system('sudo ovs-vsctl --all destroy Queue')


if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
