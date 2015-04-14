from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

import random
import threading
import time

from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()
class iplb (object):
    def __init__ (self, connection, svc_ip, servers = []):
        self.connection = connection
        self.mac = self.connection.eth_addr
        self.svc_ip = svc_ip
        self.servers = servers
        self.server_state = {}
        self.flow_state = {}
        self.flow_cache = {}
        self.client_mac = {}
        self.last_server = 0;
        #self.config_switch()
        log.debug("add new connection: mac %s " %self.mac )
        log.debug("add new connection: svc ip%s " %self.svc_ip)
        connection.addListeners(self)
        self.probe_server()
    def config_switch(self):
        log.debug("config switch: svc ip%s " %self.svc_ip)
        self.connection.send(of.ofp_flow_mod(
            command = of.OFPFC_ADD,
            priority = 15,
            idle_timeout = of.OFP_FLOW_PERMANENT,
            hard_timeout = of.OFP_FLOW_PERMANENT,
            match = of.ofp_match(
                dl_type = pkt.ethernet.ARP_TYPE,
                nw_dst = self.svc_ip),
            action = of.ofp_action_output(port = of.OFPP_CONTROLLER)))
    def probe_server(self):
        for server in self.servers:
            self.send_server_arp(server)
            for server in self.server_state.keys():
                if self.server_state[server]['last_reply']<(time.time() - 20):
                    log.debug("server %s dead " %server);
                    key = self.flow_state.keys()
                    if server in key:
                        self.connection.send(of.ofp_flow_mod(
                            command = of.OFPFC_DELETE,
                            match = of.ofp_match(
                                dl_type = pkt.ethernet.IP_TYPE,
                                nw_dst = server)))
                        del self.flow_state[key]
                del self.server_state[server]
        for flow in self.flow_cache.keys():
            cur_time = time.time()
            if self.flow_cache[flow]['time'] < cur_time:
                log.debug("flow timeout, delete  " );
                del self.flow_cache[flow]
        threading.Timer(10, self.probe_server).start()

    def send_server_arp(self, server):
        arppkt = pkt.ethernet(
                type = pkt.ethernet.ARP_TYPE,
                src = self.mac,
                dst = pkt.ETHER_BROADCAST)
        arppkt.payload = pkt.arp(
                opcode = pkt.arp.REQUEST,
                hwtype = pkt.arp.HW_TYPE_ETHERNET,
                prototype = pkt.arp.PROTO_TYPE_IP,
                hwsrc = self.mac,
                protodst = server,
                protosrc = self.svc_ip)
        msg = of.ofp_packet_out(
                data = arppkt.pack(),
                action = of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)
    def _handle_PacketIn(self, event):
        packet_in = event.ofp;
        packet = event.parsed;
        inport = event.port
        if self.handle_svc_arp(packet, packet_in):
            return
        if self.handle_ip(packet, packet_in, inport):
            return
    def handle_ip(self, packet, packet_in, inport):
        #log.debug("recieve ip packet %s " % packet.dump());
        ippkt = packet.find('ipv4')
        tcppkt = packet.find('tcp')
        if not ippkt :
            return False;
        if ippkt.dstip == self.svc_ip: 
            key = ippkt.srcip,tcppkt.srcport
            flow = self.flow_cache.get(key)
            if flow :
                #print("found flow %s %s " %(ippkt.srcip, tcppkt.srcport))
                newServer = flow['server']
                timeout = flow['time']
                if timeout > time.time()+10-1:
                    #print("duplicate")
                    return True
                
            else:
                epkt = packet.find('ethernet')
                client = epkt.src
                self.last_server = (self.last_server)%len(self.servers)
                newServer = self.servers[self.last_server]
                self.flow_cache[key]={
                        'server':newServer,
                        'port':inport,
                        'time': time.time()}
                #print("create new flow %s %s" %(ippkt.srcip, tcppkt.srcport));

                self.last_server += 1
            server_mac = self.server_state[newServer]['mac']
            timeout = time.time()+10
            flow = self.flow_cache.get(key)
            flow['time']=timeout
            #log.debug("server mac %s " %server_mac);
            #log.debug("server ip %s " %newServer);
            print "receive new IP packet",ippkt.srcip, "send to server", newServer
            self.flow_state[newServer] = {
                    'server': newServer
                    }

            self.connection.send(of.ofp_flow_mod(
                command = of.OFPFC_ADD,
                idle_timeout = 5,
                hard_timeout = of.OFP_FLOW_PERMANENT,
                data = packet_in,
                match = of.ofp_match.from_packet(
                    packet),
                action = [of.ofp_action_dl_addr.set_dst(server_mac),
                    of.ofp_action_nw_addr.set_dst(newServer),
                    of.ofp_action_output(port = of.OFPP_NORMAL)]))

        if ippkt.srcip in self.servers:
            #log.debug("ip packet from server %s " %ippkt.srcip);
            key = ippkt.dstip,tcppkt.dstport
            flow = self.flow_cache.get(key)
            if flow is None:
                #log.debug("no flow found " );
                return True

            timeout = flow['time']
            if timeout > time.time()+10-1:
                #print("duplicate")
                return True
            timeout = time.time()+10
            flow['time']=timeout
            '''
            #client = flow['port']
            #log.debug("inport %s " %inport);
            epkt = packet.find('ethernet')
            #c_mac= self.client_mac[ippkt.dstip]['mac'] 
            '''
            self.connection.send(of.ofp_flow_mod(
                command = of.OFPFC_ADD,
                idle_timeout = 5,
                hard_timeout = of.OFP_FLOW_PERMANENT,
                data = packet_in,
                match = of.ofp_match.from_packet(
                    packet),
                action = [of.ofp_action_dl_addr.set_src(self.mac),
                    #of.ofp_action_dl_addr.set_dst(c_mac),
                    of.ofp_action_nw_addr.set_src(self.svc_ip),
                    of.ofp_action_output(port = of.OFPP_NORMAL)]))
        return True

    def handle_svc_arp(self, packet, packet_in):
        arp = packet.find("arp")
        if not arp:
            return False
        if(arp.prototype != pkt.arp.PROTO_TYPE_IP or
           arp.hwtype != pkt.arp.HW_TYPE_ETHERNET or
           arp.protodst != self.svc_ip):
            #log.debug("recieve arp for non svc ip%s " % packet.dump());
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = packet_in
            self.connection.send(msg)
            self.client_mac[arp.protosrc] = {
                    'mac': arp.hwsrc
                    
                    }
            return True
        if arp.protosrc in self.servers:
            #log.debug("Server ARP reply ");
            self.server_state[arp.protosrc] = {
                    'mac': arp.hwsrc,
                    'last_reply': time.time()
                    }
        if arp.opcode == arp.REQUEST:
            #log.debug("recieve arp request %s " % packet.dump());
            rpl = pkt.ethernet(
                    type = pkt.ethernet.ARP_TYPE,
                    src = self.mac,
                    dst = arp.hwsrc)
            rpl.payload = pkt.arp(
                    opcode = pkt.arp.REPLY,
                    hwtype = pkt.arp.HW_TYPE_ETHERNET,
                    prototype = pkt.arp.PROTO_TYPE_IP,
                    hwdst = arp.hwsrc,
                    hwsrc = self.mac,
                    protodst = arp.protosrc,
                    protosrc = self.svc_ip)
            msg = of.ofp_packet_out(
                    data = rpl.pack(),
                    action = of.ofp_action_output(port = of.OFPP_NORMAL))
            self.connection.send(msg)
            return True




def launch (svc_ip, servers):
    servers = [IPAddr(x) for x in servers.split(",")]
    svc_ip = IPAddr(svc_ip)
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        core.registerNew(iplb,event.connection,svc_ip, servers)
        event.connection.addListeners(core.iplb)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
