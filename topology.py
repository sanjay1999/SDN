from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.util import dumpNodeConnections


def CustomTopo():

    net = Mininet(controller=RemoteController, link=TCLink)
    
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Adding hosts
    info( '*** Adding hosts ***\n')
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    
    # Adding switches
    info( '*** Adding switches ***\n')
    s1 = net.addSwitch('s1') # s1 = net.addSwitch('s1', cls=UserSwitch) to run CPqD switch
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    s5 = net.addSwitch('s5')
    
    # Adding links
    info( '*** Adding links ***\n')
    net.addLink(h1, s1, delay='10ms', bw=10)
    net.addLink(h2, s5, delay='10ms', bw=10)

    net.addLink(s1, s2, delay='20ms', bw=7)
    net.addLink(s1, s3, delay='30ms', bw=10)
    net.addLink(s2, s4, delay='10ms', bw=5)
    net.addLink(s2, s5, delay='30ms', bw=10)
    net.addLink(s3, s4, delay='20ms', bw=7)
    net.addLink(s4, s5, delay='10ms', bw=6)

    # Start all the devices
    net.start()

    # h1.cmd('python3 send_packet.py {} {} {}'.format('10.0.0.1','10.0.0.2',"Testing Scapy"))
    
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    CustomTopo()
