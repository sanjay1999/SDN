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
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    h5 = net.addHost('h5')
    
    # Adding switches
    info( '*** Adding switches ***\n')
    s1 = net.addSwitch('s1') # s1 = net.addSwitch('s1', cls=UserSwitch) to run CPqD switch
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    s5 = net.addSwitch('s5')
    
    # Adding links
    info( '*** Adding links ***\n')
    net.addLink(h1, s1, delay='10ms')
    net.addLink(h2, s2, delay='10ms')
    net.addLink(h3, s3, delay='10ms')
    net.addLink(h4, s4, delay='20ms')
    net.addLink(h5, s5, delay='20ms')

    net.addLink(s1, s2, delay='100ms')
    net.addLink(s2, s3, delay='10ms')
    net.addLink(s3, s4, delay='10ms')
    net.addLink(s4, s5, delay='10ms')
    net.addLink(s1, s5, delay='10ms')
    
    # Start all the devices
    net.start()
    
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    CustomTopo()
