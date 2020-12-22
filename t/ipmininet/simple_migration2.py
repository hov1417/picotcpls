from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.link import TCIntf
from mininet.log import lg
from ipmininet.router.config import OSPF, RouterConfig

class MyTopology(IPTopo):

    def build(self, *args, **kwargs):
        """
                 -----r2-----
                /             \ 
       c --- r1                r3 --- s
                \             /
                 -----r4------
        """

        r1 = self.addRouter("r1")
        r2 = self.addRouter("r2", use_v6=False)
        r3 = self.addRouter("r3")
        r4 = self.addRouter("r4", use_v4=False)
        c = self.addHost("c")
        s = self.addHost("s")
        r1r2 = self.addLink(r1, r2, delay="10ms", bw=30)
        r2r3 = self.addLink(r2, r3, delay="10ms", bw=30)
        r1r4 = self.addLink(r1, r4, delay="20ms", bw=30)
        r4r3 = self.addLink(r4, r3, delay="20ms", bw=30)
        
        self.addLinks((c, r1, {'params1': {'ip':("2001:12::1/64", "134.104.0.1/24")}, 'params2': {'ip':("2001:13::1/1", "134.104.1.1/24")}}), (r3, s, {'params1':{'ip': ("2001:cafe::1/64", "134.205.0.1/24")}, 'params2':{'ip': ("2001:caf::1/64","134.205.1.1/24")}}))

        super().build(*args, **kwargs)

lg.setLogLevel("info")
net = IPNet(topo=MyTopology(), intf=TCIntf)
try:
    net.start()
    #net["c"].cmd("ip -4 route add 134.104.1.1 dev c-eth0")
    #net["c"].cmd("ip -4 route add 134.205.1.1 dev c-eth0")
    #net["r1"].cmd("ip -4 route add 134.104.0.1 dev r1-eth2")
    #net["c"].cmd("ip -6 route add 2001:13::1 dev c-eth0")
    #net["r1"].cmd("ip -6 route add 2001:12::1 dev r1-eth2")
    #net["r1"].cmd("ip -4 route add 134.205.1.1 dev r1-eth0")
    #net["r1"].cmd("ip -6 route add 2001:caf::1 dev r1-eth1")
    #net["r2"].cmd("ip -4 route add 134.104.0.1 dev r2-eth0")
    #net["r2"].cmd("ip -4 route add 134.205.1.1 dev r2-eth1")
    #net["s"].cmd("ip -4 route add 134.104.0.1 dev s-eth0")
    #net["r3"].cmd("ip -4 route add 134.204.1.1 dev r3-eth2")
    #net["r3"].cmd("ip -4 route add 134.104.0.1 dev r3-eth0")
    IPCLI(net)
finally:
    net.stop()

