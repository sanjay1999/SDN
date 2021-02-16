from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
# from ryu.lib import hub

from ryu.topology import event #, switches
# from ryu.topology.api import get_switch, get_link, get_all_switch

import networkx as nx
import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switches = {}
        self.graph = nx.DiGraph()
        self.switch_intime = {}
        self.switch_outtime = {}
        self.sin = {}
        self.sout = {}
        # self.discover_thread = hub.spawn(self._discover)
        
    # def _discover(self):
    #     while True:
    #         self.get_topology_data(None)
    #         hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        self.sin[datapath.id] = time.time()
        
        self.logger.info("Registered switch with dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.sout[dpid] = time.time()
        delay = self.sout[dpid] - self.sin[dpid]
        print("s" + str(dpid) + " to controller = " + str(delay))

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    buffer_id=buffer_id,
                                    priority=priority, 
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, 
                                    instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(event.EventSwitchEnter)
    def get_switch_enter(self, ev):
        switch = ev.switch
        # print(switch.to_dict())
        dp = switch.dp
        dpid = switch.dp.id
        self.graph.add_node(dpid, data=dp)
        print("Switch added with dpid=" + str(switch.dp.id))
        # print(list(self.graph.nodes(data=True)))
    
    def send_packet(self, dp, src, dst, out_port):
        ethertype = 0x08fc
        # dst = self.macaddr(i)
        # src = self.macaddr(l) 
        e = ethernet.ethernet(src='00:00:00:00:00:0'+str(src), dst='00:00:00:00:00:0'+str(dst), ethertype=ethertype)
        # u = udp.udp(src_port=src, dst_port=dst, total_length=0, csum=0)                
        pkt = packet.Packet()
        pkt.add_protocol(e)
        # pkt.add_protocol(u)
        pkt.add_protocol(time.time())
        pkt.serialize()

        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        action = [parser.OFPActionOutput(port=out_port)]

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=pkt.data)
        # print("Sending packet out")
        # print(dp)
        dp.send_msg(out)
        print("Packet out sent for (" + str(src) + "," + str(dst) +") via port " + str(out_port))
        self.switch_intime[(src, dst)] = time.time()

    @set_ev_cls(event.EventLinkAdd)
    def get_link_add(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        print("Link added: {" + str(src_dpid) + " -> " + str(dst_dpid) + " from port:" + str(src_port) + "}")
        self.graph.add_edge(src_dpid, dst_dpid, data={'port': src_port})
        # print(self.graph.edges(data=True))
        datapath = self.graph.node[src_dpid]['data']
        # print("Datapath = ", datapath)
        # if src_dpid == 2 and dst_dpid == 1:
        self.send_packet(dp=datapath, src=src_dpid, dst=dst_dpid, out_port=src_port)

        # switch_list = get_switch(self, None)
        # switches = [switch.dp.id for switch in switch_list]
        # links_list = get_link(self, None)
        # links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        # print(switches)
        # print(links)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # print("DATAPATH")
        # print(datapath)
        
        self.logger.info("Packet in %s %s %s %s %s", dpid, src, dst, in_port, eth.ethertype)
        if eth.ethertype == 0x08fc:
            src_dpid = int(src[-1:])
            dst_dpid = int(dst[-1:])
            self.switch_outtime[(src_dpid, dst_dpid)] = time.time()
            d1 = self.sout[src_dpid] - self.sin[src_dpid]
            d2 = self.sout[dst_dpid] - self.sin[dst_dpid]
            print(self.switch_outtime[(src_dpid, dst_dpid)] - self.switch_intime[(src_dpid, dst_dpid)])
            delay = (self.switch_outtime[(src_dpid, dst_dpid)] - self.switch_intime[(src_dpid, dst_dpid)] - (d1/2) - (d2/2)) * 1000
            print("delay " + str(src_dpid) + " -> " + str(dst_dpid) + " = " + str(delay))
            return

        # print(pkt.get_protocols(time))
        # learn a mac address to avoid FLOOD next time.
        # if not src in self.mac_to_port[dpid]:
        #     self.mac_to_port[dpid][src] = in_port
        #     out_port = ofproto.OFPP_FLOOD
        #     actions = [parser.OFPActionOutput(out_port)]
        # else:
        #     if self.mac_to_port[dpid][src] != in_port:
        #         out_port = -1;
        #         actions = []
        #     else:
        #         out_port = ofproto.OFPP_FLOOD
        #         actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)

        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data

        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)
