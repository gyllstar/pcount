# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""  As of 9/17/13 this module is NO LONGER BEING USED!! Code has been refactored all this functionality has been moved
     to the applseed.py module

This module is our controller for running PCount sessions.

Some of this module code was copied from "pox/forwarding/l3_learning.py", which had the following comments:

    A stupid L3 switch
    
    For each switch:
    1) Keep a table that maps IP addresses to MAC addresses and switch ports.
       Stock this table using information from ARP and IP packets.
    2) When you see an ARP query, try to answer it using information in the table
       from step 1.  If the info in the table is old, just flood the query.
    3) Flood all other ARPs.
    4) When you see an IP packet, if you know the destination port (because it's
       in the table from step 1), install a flow for it.
"""

from pox.core import core
import pcount
import pox
#log = core.getLogger("l3_arp_pcount")
log = core.getLogger()
from pox.lib.recoco import Timer
import csv
import os,sys
import utils
from pox.lib.util import dpidToStr

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr,EthAddr

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time



#measure_pnts_file_str="measure-6s-2d-2p.csv"
#measure_pnts_file_str="measure-4s-3d-1p.csv"
#measure_pnts_file_str="measure-4s-2d-1p.csv"
#measure_pnts_file_str="measure-4s-1p.csv"
#measure_pnts_file_str="measure-3s-2p.csv"
#measure_pnts_file_str="measure-3s-1p.csv"
#measure_pnts_file_str="measure-3s-2d-1p.csv"
#measure_pnts_file_str="measure-2s-2p.csv"
measure_pnts_file_str="measure-2s-1p.csv"

mtree_file_str="mtree-6s-2t.csv"
#mtree_file_str="mtree-4s-1t.csv"


installed_mtrees=[] #list of multicast addresses with an mtree already installed

# Timeout for ARP entries
ARP_TIMEOUT = 6000 * 2


# in seconds
PCOUNT_WINDOW_SIZE=10  
PCOUNT_CALL_FREQUENCY=PCOUNT_WINDOW_SIZE+5
PROPOGATION_DELAY=1 #seconds

h1 = IPAddr("10.0.0.1")
h2 = IPAddr("10.0.0.2")
h3 = IPAddr("10.0.0.3")
h4 = IPAddr("10.0.0.4")
h5 = IPAddr("10.0.0.5")
h6 = IPAddr("10.0.0.6")
h7 = IPAddr("10.0.0.7")
h8 = IPAddr("10.0.0.8")
h9 = IPAddr("10.0.0.9")
mcast_ip_addr1 = IPAddr("10.10.10.10")
mcast_mac_addr = EthAddr("10:10:10:10:10:10")

mcast_ip_addr2 = IPAddr("10.11.11.11")
mcast_mac_addr2 = EthAddr("11:11:11:11:11:11")

# this count is supposed to correspond for (what is asssumed) to be the single outgoing link of the upsttream tagging switch
actual_total_pkt_dropped = 0
detect_total_pkt_dropped = 0
actual_pkt_dropped_gt_threshold_time=-1
detect_pkt_dropped_gt_threshold_time=-1

pkt_dropped_curr_sampling_window = 0
packets_dropped_threshold = 15

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port    #DPG: this could be a list of ports because we support Layer 3 multicast
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return False #DPG: modified this because for our application (power grid) the IP addresses will not change and therefore will not expire
    #return time.time() > self.timeout





class l3_arp_pcount_switch (EventMixin):
  """
  This is the controller application.  Implements an L3 learning switch, ARP, and PCount.  
  
  The flow tables are populated by implementing the behavior of an L3 learning switch.  Supporting ARP is a necessary to do so.  
  The PCount sessions are triggered, using a timer, after the first flow entries are installed (as part of the L3 learning phase).
  Currently flows are specified using the source IP address and destination address tuple.  
  
  TODO: Flows should be refactored to match packets using only the destination address, rather than (src_ip,dst_up) pair.  
  
  """
  
  def __init__ (self):
    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    self.listenTo(core)
    
    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} #this is a hack that saves us from queries each switch for their flow table)
    
    # dict.  d_switch_id1 --> list w/ entries (d_switch_id2, d_switch_id3, .... , u_switch_id,nw_src,nw_dst)
    self.flow_measure_points={}  # note this really ought to be (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id)
    
    #multicast address -> [src,dest1,dest2,...]
    self.mcast_groups = {}
    
    # (src-ip,dst-ip) -> [switch_id1, switch_id2, ...]
    self.flow_strip_vlan_switch_ids = {}
    
    # (src-ip,dst-ip,switch_id) -> [dstream_host1,dstream_host2, ...] 
    self.mtree_dstream_hosts = {}
    
    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    self.pcount_results = dict()
    
    self._read_flow_measure_points_file()
    
    self._read_mtree_file()
    
    
  def _read_mtree_file(self):
    """
    reads in a file specifying the nodes in a multicast tree (or trees)
    
    TODO: the location of the file is hard-coded and should be read for the command line, or improved in some way
    
    """
    mtree_file = "ext/topos/mtree/%s" %(mtree_file_str)
    
    # check if we need to load the mtree file
    num_switches = measure_pnts_file_str.split("-")[1]
    num_switches2 = mtree_file_str.split("-")[1]
    
    if num_switches != num_switches2:
      log.info("did not load mtree file ('%s') because not using a valid matching measurement points file (loaded '%s')" %(mtree_file_str,measure_pnts_file_str))
      return
    
    #file structure: multicast address,src,dest1,dest2,...
    for line_list in csv.reader(open(mtree_file)):
      val_list = list()
      
      # check if it's a comment line
      if "#" in line_list[0]:
        continue
      
      val_list.insert(0, IPAddr(line_list[1])) #src ip
      
      i = 2
      while i < len(line_list): #2<4
        val_list.insert(i-1, IPAddr(line_list[i]))
        i+=1
      
      key = IPAddr(line_list[0])
      
      if self.mcast_groups.has_key(key):
        entry = self.mcast_groups[key]
        entry.append(val_list)
      else:
        entry = list()
        entry.append(val_list)
        self.mcast_groups[key] = entry
      
  def _read_flow_measure_points_file(self):
    """
    read and parse a file specifying which switches are tagging and those that are downstream nodes counting tagged packets
    
    The file is assumed to have the following format: 'downstream-switch1,downstream-switch2, ..., upstream_switch,src-ip,dest-ip'
    
    TODO: the location of the file is hard-coded, as our the IP addresses of the switches
    """
    # file format: downstream-switch1,downstream-switch2, ..., upstream_switch,src-ip,dest-ip

    measure_file = "ext/topos/%s" %(measure_pnts_file_str)
    log.debug("using measure points file: %s" %(measure_file))
    
    for line_list in csv.reader(open(measure_file)):
      val_list = list()
      
      # check if it's a comment line
      if "#" in line_list[0]:
        continue
      
      key = int(line_list[0])
      cnt=1 # skip the first entry
      src_index = len(line_list) - 2 # the src-ip address starts at the at the 2nd to last position
      
      # (d_switch_id2, d_switch_id3, .... , u_switch_id,nw_src,nw_dst)
      while cnt < src_index:
        val_list.insert(cnt-1, int(line_list[cnt]))
        cnt+=1
        
      src_ip = IPAddr(line_list[cnt])
      dst_ip = IPAddr(line_list[cnt+1])
      val_list.insert(cnt-1, src_ip)
      val_list.insert(cnt, dst_ip) 
      
      # egregious hard-coding of the most downstream node 
      if src_ip == h3 and dst_ip == mcast_ip_addr1 and key<10:
        self.flow_strip_vlan_switch_ids[(src_ip,dst_ip)] = [4,5]   # should be h1 and h2 adjacent switches
      elif src_ip == h3 and dst_ip == mcast_ip_addr1 and key>10:
        self.flow_strip_vlan_switch_ids[(src_ip,dst_ip)] = [12,13]   
      elif src_ip == h4 and dst_ip == mcast_ip_addr2:
        self.flow_strip_vlan_switch_ids[(src_ip,dst_ip)] = [14,15]
      elif src_ip == h3:
        self.flow_strip_vlan_switch_ids[(src_ip,dst_ip)] = [4]
      else:
        log.error("something wrong with parsing measurement file %s when finding which switch_id should strip the VLAN tag.  Exiting program." %(measure_file))
        os._exit(0)
        
      
      if self.flow_measure_points.has_key(key):
        entry = self.flow_measure_points[key]
        entry.append(val_list)
      else:
        entry = list()
        entry.append(val_list)
        self.flow_measure_points[key] = entry
    
    
  def _cache_flow_table_entry(self,dpid,flow_entry):
    """ For the given switch, adds the flow entry. This flow table mirrors the table stored at the switch
    
    Keyword arguments:
    dpid -- the switch id
    flow_entry -- a modify state message (i.e., libopenflow_01.ofp_flow_mod object)
    
    """
    if not self.flowTables.has_key(dpid):
      flow_table = list()
      flow_table.append(flow_entry)
      self.flowTables[dpid] = flow_table
    else:
      self.flowTables[dpid].append(flow_entry)

   
  def _start_pcount_thread(self,u_switch_id, d_switch_ids, nw_src, nw_dst):
    """ Sets a timer to start a PCount session
    
    Keyword Arguments:
    u_switch_id -- upstream switch id
    d_switch_id -- downstream switch id
    nw_src -- IP address of the source node, used to recognize the flow
    nw_dst -- IP address of destination node, used to recognize the flow
    
    """
    pcounter = pcount.PCountSession()
    
    strip_vlan_switch_ids = self.flow_strip_vlan_switch_ids[(nw_src,nw_dst)]
    
    Timer(PCOUNT_CALL_FREQUENCY,pcounter.pcount_session, args = [u_switch_id, d_switch_ids,strip_vlan_switch_ids,self.mtree_dstream_hosts,nw_src, nw_dst, self.flowTables,self.arpTable, PCOUNT_WINDOW_SIZE],recurring=True)

    
  def _check_start_pcount(self,d_switch_id,nw_src,nw_dst):
    """ Checks if the given switch for flow (nw_src,nw_dst) is the downstream switch in which we want to trigger a PCount session
    
    Keyword Arguments:
    d_switch_id -- downstream switch id
    nw_src -- IP address of the source node, used to recognize the flow
    nw_dst -- IP address of destination node, used to recognize the flow
    
    """
    if not self.flow_measure_points.has_key(d_switch_id):
      return False,-1,-1
    
    
    for measure_pnt in self.flow_measure_points[d_switch_id]:
      last_indx = len(measure_pnt) -1
      
      if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
        dstream_switches = list()
        dstream_switches.append(d_switch_id)
        dstream_switches = dstream_switches + measure_pnt[0:last_indx-2]
        
        return True,measure_pnt[last_indx-2],dstream_switches  #returns the upstream switch id 
      
    return False,-1,-1
  
  


  # TODO: refactor this mess by changing the structure of flow_measure_points to (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id) b/c no longer will need to search
  #       the entire dict for a match
  def _is_flow_counting_switch(self,switch_id,nw_src,nw_dst):
    """ Checks if this switch is a downstream counting node for the (nw_src,nw_dst) flow
     
     TODO: refactor this mess by changing the structure of flow_measure_points to (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id) b/c no longer will need to search
          the entire dict for a match 
    """
    # could be the key
    if self.flow_measure_points.has_key(switch_id):
      for measure_pnt in self.flow_measure_points[switch_id]:
        last_indx = len(measure_pnt) -1
        if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
          return True
     
    # could also be one of the first few values in the value list
    for measure_pnts in self.flow_measure_points.values():
      for measure_pnt in measure_pnts:
        last_indx = len(measure_pnt) -1
        if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
          if switch_id in measure_pnt[0:last_indx-2]:  # the list "subset" or slice is not inclusive on the upper index
            return True
    
    return False
     
  
  
  # tagging takes place at the upstream node
  def _is_flow_tagging_switch(self,switch_id,nw_src,nw_dst):
    """ is this an upstream tagging switch for flow (nw_src,nw_dst) """
    
    for measure_pnts in self.flow_measure_points.values():
      for measure_pnt in measure_pnts:
        last_indx = len(measure_pnt) -1
        if measure_pnt[last_indx-2] == switch_id and measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
          return True
    
    
    return False
  
  
  def _total_tag_and_cnt_switches(self, nw_src, nw_dst):
    """ returns the total number of measurement nodes (taggers and counters) for flow (nw_src,nw_dst)"""
    for measure_pnts in self.flow_measure_points.values():
      for measure_pnt in measure_pnts:
        last_indx = len(measure_pnt) -1
        if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
          return len(measure_pnt) -2 + 1  # minus two because don't want to count the nw_src, nw_dst, and plus one because one counting switch is not in teh measure_pnt list (it is the hash key)
    
    return -1
        
  
  def _handle_ipv4_PacketIn(self,event,packet,dpid,inport):
    """ All IP packets from switches are processed here.  This is the meat of the controller, or at least where all processing is started.
    
    This function:
      (1) populates an ARP table w/ MAC address to IP Address mappings
      (2) starts a PCount session if the basic flow entries for forwarding are installed at all switches a part of the PCount session
    
    Keyword Arguments:
    event -- object with connection state between controller and the switch that sent us the IP packet
    packet -- IP packet
    dpid -- the switch id that sent us the packets
    inport -- the port the packet arrived 
    
    """
    log.debug("%i %i IP %s => %s", dpid,inport,str(packet.next.srcip),str(packet.next.dstip))

    # Learn or update port/MAC info for the SRC-IP (not dest!!)
    if packet.next.srcip in self.arpTable[dpid]:
      if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
        log.info("%i %i RE-learned %s", dpid,inport,str(packet.next.srcip))
    else:
      log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
    self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

    # Try to forward
    dstaddr = packet.next.dstip
    srcaddr = packet.next.srcip
    
    
    if self._is_mcast_address(dstaddr):
      if dstaddr in installed_mtrees:
        # should never reach here because mcast tree is setup when switch closest to root receives a msg destined for a multicast address 
        print "already setup mcast tree for s%s, inport=%s,dest=%s." %(dpid,inport,dstaddr)
        return
      
      log.info("special handling IP Packet in for multicast address %s" %(str(dstaddr)))
      u_switch_id, d_switch_ids = self._setup_mtree(srcaddr,dstaddr,inport)
      
      self._start_pcount_thread(u_switch_id, d_switch_ids, srcaddr, dstaddr)

      
    elif dstaddr in self.arpTable[dpid]:
      # We have info about what port to send it out on...

      prt = self.arpTable[dpid][dstaddr].port
      if prt == inport:
        log.warning("%i %i not sending packet for %s back out of the input port" % (
          dpid, inport, str(dstaddr)))
      else:
        log.debug("%i %i installing flow for %s => %s out port %i" % (dpid,
            inport, str(packet.next.srcip), str(dstaddr), prt))


        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                buffer_id=event.ofp.buffer_id,
                                action=of.ofp_action_output(port = prt)) 
        
        match = of.ofp_match.from_packet(packet,inport) 
        
        msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=match._nw_src, nw_dst = match._nw_dst) #DPG: match using L3 address
        
        self._cache_flow_table_entry(dpid, msg)
        
        event.connection.send(msg.pack())
        
        start_pcount,u_switch_id,d_switch_ids = self._check_start_pcount(dpid,match.nw_src,match.nw_dst)
        
        if start_pcount:
          self._start_pcount_thread(u_switch_id, d_switch_ids, match.nw_src, match.nw_dst)
    else:
      log.error("no ARP entry at switch s%s for dst=%s" %(dpid,dstaddr))
        
  def _is_mcast_address(self,dst_ip_address):
    return self.mcast_groups.has_key(dst_ip_address)
  
  def _install_rewrite_dst_mcast_flow(self,switch_id,nw_src,ports,nw_mcast_dst,new_dst):
    """ Creates a flow table rule that rewrites the multicast address in the packet to the IP address of a downstream host.  """
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
    
    if isinstance(new_dst,list):
      
      # this part is only executed if multiple addresses need to be rewriteen (works because OF switches execute actions in order, meaning that each copy of the packet
      # is output before the next destination address rewrite takes place)
      for dst in new_dst:
        action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
        msg.actions.append(action)
        
        new_mac_addr = self.arpTable[switch_id][dst].mac
        l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
        msg.actions.append(l2_action)
        
        for prt in ports[dst]:
          msg.actions.append(of.ofp_action_output(port = prt))
        
    else:
      action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
      msg.actions.append(action)
      
      new_mac_addr = self.arpTable[switch_id][new_dst].mac
      l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
      msg.actions.append(l2_action)
          
      for prt in ports:
        msg.actions.append(of.ofp_action_output(port = prt))
      
    utils.send_msg_to_switch(msg, switch_id)
    self._cache_flow_table_entry(switch_id, msg)
    
    
  def _install_basic_mcast_flow(self,switch_id,nw_src,ports,nw_mcast_dst):
    """ Install a flow table rule using the multicast destination address  """
  
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
    
    for prt in ports:
      msg.actions.append(of.ofp_action_output(port = prt))
    
    utils.send_msg_to_switch(msg, switch_id)
    self._cache_flow_table_entry(switch_id, msg)
    
  
  def _send_arp_reply(self,eth_packet,arp_packet,switch_id,inport,mcast_mac_addr,outport):
    """ Create an ARP reply packet and send to the requesting switch"""
    r = arp()
    r.hwtype = arp_packet.hwtype
    r.prototype = arp_packet.prototype
    r.hwlen = arp_packet.hwlen
    r.protolen = arp_packet.protolen
    r.opcode = arp.REPLY
    
    r.protodst = arp_packet.protosrc
    r.protosrc = arp_packet.protodst
    r.hwdst = arp_packet.hwsrc  
    r.hwsrc = mcast_mac_addr
    
    e = ethernet(type=eth_packet.type, src=r.hwsrc, dst=arp_packet.hwsrc)
    e.set_payload(r)
    log.debug("%i %i answering ARP request from src=%s to dst=%s" % (switch_id,inport,str(r.protosrc),str(r.protodst)))
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.in_port = inport
    
    utils.send_msg_to_switch(msg, switch_id)
    
    
  
    # dpg defined method #arp_packet,switch_id, nw_mcast_dst, prt, mcast_mac_addr
    # 6/17/13: don't think this function is ever called
  def _update_arp_table_for_mtree(self,eth_packet,arp_packet,switch_id,inport,mcast_dst_ip_addr,outport,mcast_mac_addr):
    
    self.arpTable[switch_id][mcast_dst_ip_addr] = Entry(outport,mcast_mac_addr)
    #self.arpTable[switch_id][mcast_dst_ip_addr] = Entry(inport,mcast_mac_addr)
    
    #dpg: for debugging, only want to reply if its the first hop switch
    if switch_id ==7:
      self._send_arp_reply(eth_packet,arp_packet,switch_id,inport,mcast_mac_addr,outport)
    
    # send ARP table entry to switch?
  
  
  def _setup_mtree(self,nw_src,nw_mcast_dst,inport):
    """ Hard-coded setup of mutlicast trees using the switch_id numbers. """
    if nw_mcast_dst == mcast_ip_addr1:
      mtree1_switches = []
      if len(self.mcast_groups.keys()) == 2:
        mtree1_switches = [10,11,13,12]
      else:
        mtree1_switches = [7,6,5,4]
        
      return self._setup_mtree1(nw_src, nw_mcast_dst, inport,mtree1_switches)
    elif nw_mcast_dst == mcast_ip_addr2:
      mtree2_switches = []
      if len(self.mcast_groups.keys()) == 2:
        mtree2_switches = [10,14,15]
        
      return self._setup_mtree2(nw_src, nw_mcast_dst, inport,mtree2_switches)
    
  
  # should really use self.mcast_groups to determine which hosts are a part of the multicast group and tree
  # should have some way to determine which hosts are downstream from a given switch, rather than hard coding this  
  def _setup_mtree1(self,nw_src,nw_mcast_dst,inport,mtree_switches):
    """ More hard-coding of the multicast trees.  Here we install the flow entries at each switch node """
    # mcast address = 10.10.10.10, src = 10.0.0.3, dst1=10.0.0.1, dst2 = 10.0.0.2
    # tree: 
    #       h1 -- s4
    #                \ s6 --- s7 --- h3              
    #       h2 -- s5 /
    
    
    # s7: install (src=10.0.0.3, dst = 10.10.10.10, outport)
    switch_id = mtree_switches[0]
    s7_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    self._install_basic_mcast_flow(switch_id, nw_src,s7_ports,nw_mcast_dst)
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s7_ports,mcast_mac_addr)
    
    
    # s6: install (src=10.0.0.3, dst = 10.10.10.10, outport_list) or
    # s6: install (src=10.0.0.3, dst = 10.0.0.1, outport),  (src=10.0.0.3, dst = 10.0.0.6, outport) 
    switch_id = mtree_switches[1]
    h1_prts = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    h2_prts = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h2)
    s6_ports = h1_prts + h2_prts
    self._install_basic_mcast_flow(switch_id, nw_src, s6_ports, nw_mcast_dst)
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s6_ports,mcast_mac_addr)
    
    
    
    # s5: rewrite destination address from 10.10.10.10 to h2 (10.0.0.2)
    switch_id = mtree_switches[2]
    s5_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h2)
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s5_ports, nw_mcast_dst, h2)
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s5_ports,mcast_mac_addr)
    self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h2]
    
    # s4: rewrite destination address from 10.10.10.10 to h1 (10.0.0.1)
    switch_id = mtree_switches[3]
    s4_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s4_ports, nw_mcast_dst, h1)  
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s4_ports,mcast_mac_addr) 
    self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h1]
    
    global installed_mtrees
    installed_mtrees.append(nw_mcast_dst)
    
    u_switch_id,d_switch_ids = self._find_mcast_measure_points(nw_src,mcast_ip_addr1)
    
    return u_switch_id, d_switch_ids
  
  def _setup_mtree2(self,nw_src,nw_mcast_dst,inport,mtree_switches):
    """ More hard-coding of the multicast trees.  Here we install the flow entries at each switch node """
        
    # mcast address = 11.11.11.11, src = 10.0.0.4, dst1=10.0.0.2, dst2 = 10.0.0.7, dst3 = 10.0.0.8, dst4 = 10.0.0.5, dst5 = 10.0.0.6
    # tree: 
    #       h9
    #       h7 - \
    #       h8 -- s15
    #                \ s10 --- h4               
    #       h5 -- s14 /
    #       h6 /
    
    
    # s10: install (src=10.0.0.9, dst = 11.11.11.11, outport_list) 
    switch_id = mtree_switches[0]
    h8_prts = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h8)
    h6_prts = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h6)
    s10_ports = h8_prts + h6_prts
    self._install_basic_mcast_flow(switch_id, nw_src, s10_ports, nw_mcast_dst)
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s10_ports,mcast_mac_addr)
    
    # s14: rewrite destination address from 11.11.11.11 to h5 and h6 
    switch_id = mtree_switches[1]
    #s14_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h5)
    #self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s14_ports, nw_mcast_dst, h5)
    #self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5]
    h5_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h5)
    h6_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h6)
    s14_ports = {h5:h5_ports, h6:h6_ports}
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s14_ports, nw_mcast_dst, [h5,h6])
    self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5,h6]
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s14_ports,mcast_mac_addr)

    
    # s15: rewrite destination address from 11.11.11.11 to h2,h7, and h8 
    switch_id = mtree_switches[2]
    h7_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h7)
    h8_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h8)
    h9_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h9)
    #s15_ports = h7_ports + h8_ports + h9_ports
    s15_ports = {}
    s15_ports[h7] = h7_ports
    s15_ports[h8] = h8_ports
    s15_ports[h9] = h9_ports
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s15_ports, nw_mcast_dst, [h7,h8,h9])  
    #self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s15_ports, nw_mcast_dst, [h7])  
    #self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7]
    self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7,h8,h9]
    self.arpTable[switch_id][nw_mcast_dst] = Entry(s15_ports,mcast_mac_addr) 
    
    global installed_mtrees
    installed_mtrees.append(nw_mcast_dst)
    
    u_switch_id,d_switch_ids = self._find_mcast_measure_points(nw_src,mcast_ip_addr2)
    
    return u_switch_id, d_switch_ids

  
  def _find_mcast_measure_points(self, nw_src,mcast_ip_addr1):
    
    for d_switch_id in self.flow_measure_points.keys():
    
      for measure_pnt in self.flow_measure_points[d_switch_id]:
        last_indx = len(measure_pnt) -1
      
        if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == mcast_ip_addr1:
          dstream_switches = list()
          dstream_switches.append(d_switch_id)
          dstream_switches = dstream_switches + measure_pnt[0:last_indx-2]
          
          return measure_pnt[last_indx-2],dstream_switches  #returns the upstream switch id 
      
    return -1,-1
  
  def _handle_arp_PacketIn(self,event,packet,dpid,inport):
    """ Learns the inport the switch receive packets from the given IP address
    
    Keyword Arguments:
    event -- the event that triggered this function call
    packet -- IP packet
    dpid -- the switch id
    inport -- 
    
    """
    a = packet.next  # 'a' seems to be an IP packet (or actually it's an ARP packet)
    
    log.debug("%i %i ARP %s %s => %s", dpid, inport,{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    
    if a.prototype == arp.PROTO_TYPE_IP:
      if a.hwtype == arp.HW_TYPE_ETHERNET:
        if a.protosrc != 0:
          
          if self._is_mcast_address(a.protodst):
            log.debug("skipping normal ARP Request code because ARP request is for multicast address %s" %(str(a.protodst)))
            
            if a.protodst in installed_mtrees:
              print "already setup mcast tree for s%s, inport=%s,dest=%s, just resending the ARP reply and skipping mcast setup." %(dpid,inport,a.protodst)
              self._send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
            else:
              #getting the outport requires that we have run a "pingall" to setup the flow tables for the non-multicast addreses
              outport = utils.find_nonvlan_flow_outport(self.flowTables,dpid, a.protosrc, h1)
              self.arpTable[dpid][a.protodst] = Entry(outport,mcast_mac_addr)
              self._send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
            
            return

          # Learn or update port/MAC info for the SOURCE address 
          if a.protosrc in self.arpTable[dpid]:
            if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
              log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
          else:
            log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            
          self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

          if a.opcode == arp.REQUEST:
            # Maybe we can answer

            if a.protodst in self.arpTable[dpid]:
              # We have an answer...

              if not self.arpTable[dpid][a.protodst].isExpired():
                # .. and it's relatively current, so we'll reply ourselves
                
                r = arp()
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protodst = a.protosrc #IP address
                r.protosrc = a.protodst #IP address
                r.hwsrc = self.arpTable[dpid][a.protodst].mac
                e = ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
                e.set_payload(r)   # r is the ARP REPLY
                log.debug("%i %i answering ARP for %s" % (dpid, inport,
                 str(r.protosrc)))
                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                msg.in_port = inport
                event.connection.send(msg)
                return

    # Didn't know how to answer or otherwise handle this ARP request, so just flood it
    log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
     {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
     'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

    msg = of.ofp_packet_out(in_port = inport, action = of.ofp_action_output(port = of.OFPP_FLOOD))
    if event.ofp.buffer_id is of.NO_BUFFER:
      # Try sending the (probably incomplete) raw data
      msg.data = event.data
    else:
      msg.buffer_id = event.ofp.buffer_id
    event.connection.send(msg.pack())


  def _handle_FlowRemoved (self, event):
    """ Handles the removal of our special flow entry to drop packets during a PCount session.
    
    Updates and logs the count of the true number of packets dropped, and prints this value to the console 
    
    """
    num_dropped_pkts = event.ofp.packet_count
    
    global actual_total_pkt_dropped,actual_pkt_dropped_gt_threshold_time,pkt_dropped_curr_sampling_window
    
    actual_total_pkt_dropped += num_dropped_pkts
    pkt_dropped_curr_sampling_window = num_dropped_pkts
    
    outStr = "Flow removed on s%s, packets dropped = %s, total packets droppped=%s" %(event.dpid,num_dropped_pkts,actual_total_pkt_dropped)
    print outStr
    
    if actual_total_pkt_dropped > packets_dropped_threshold:
      actual_pkt_dropped_gt_threshold_time = time.clock()
      print "\n-------------------------------------------------------------------------------------------------------------------------------------------------------------"
      print "Total packets ACTUALLY dropped = %s, exceeds threshold of %s.  Timestamp = %s" %(actual_total_pkt_dropped,packets_dropped_threshold,actual_pkt_dropped_gt_threshold_time)
      print "-------------------------------------------------------------------------------------------------------------------------------------------------------------"
    log.debug(outStr) 

  def _handle_PacketIn (self, event):
    """ This is where all packets arriving at the controller received.  This function delegates the processing to sub-functions."""
    
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      self._handle_ipv4_PacketIn(event,packet,dpid,inport)

    elif isinstance(packet.next, arp):
      self._handle_arp_PacketIn(event,packet,dpid,inport)
      
    elif False:
      # this is where i am putting my code to parse the ofp_flow_removed message from the temporary flow entry to drop packets to simulate link loss
      self._handle_flow_removed_msg(event,packet,dpid)
      
    return

  def _log_pcount_results(self):
    
    file_base = measure_pnts_file_str.split(".")[0]
    #w = csv.writer(open("ext/results/current/pcount-output.csv", "w"))
    w = csv.writer(open("ext/results/current/%s-output.csv" %(file_base), "w"))
    for key, val in self.pcount_results.items():
      w.writerow([key, val])
    

  def _record_pcount_value(self,vlan_id,nw_src,nw_dst,switch_id,packet_count,is_upstream,total_tag_count_switches):
    """ Log the Pcount session results and print to console """
    result_list = list()    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    if self.pcount_results.has_key(vlan_id):
      result_list = self.pcount_results[vlan_id]
    else:
      result_list.insert(0,nw_src)
      result_list.insert(1,nw_dst)
      
    # check to make result_list does not already contain an entry for switch_id
    indx = 2
    cnt=0
    #while indx < len(result_list):
    while cnt < total_tag_count_switches:
      
      if indx >= len(result_list):
        cnt+=10000 #some large number so we exit the loop
        continue
      
      if result_list[indx] == switch_id:  #look at 2,4,6,8, ...
        log.debug("received duplicate stat result query for flow (vlan_id=%s,nw_src=%s,nw_dst=%s) at s%s.  Not logging the message." %(vlan_id,nw_src,nw_dst,switch_id))
        return
      
      indx+=2
      cnt+=1  
      
    if is_upstream:
      result_list.insert(2,switch_id)
      global pkt_dropped_curr_sampling_window
      packet_count += pkt_dropped_curr_sampling_window  #count the packets dropped by our flow entry at 'u' that drops packets to simulate a lossy link
      pkt_dropped_curr_sampling_window=0
      result_list.insert(3, packet_count)
    else:
      result_list.append(switch_id)
      result_list.append(packet_count)
    
    self.pcount_results[vlan_id] = result_list
    
    total = 2+ total_tag_count_switches * 2
    if len(result_list) == total: 
      
      updatedTotalDrops = False
      for i in range(0,total_tag_count_switches-1):  
          offset = 3+ (2*i + 2) #5, 7, 9, 11
          diff = result_list[3] - result_list[offset]
          result_list.append(diff)
          
          if not updatedTotalDrops:
            global detect_total_pkt_dropped
            detect_total_pkt_dropped += diff
            #pkt_dropped_curr_sampling_window=0
            
            print "detected tatal packets dropped = %s, actual packets dropped=%s" %(detect_total_pkt_dropped,actual_total_pkt_dropped)
            
            if detect_total_pkt_dropped > packets_dropped_threshold:
              detect_pkt_dropped_gt_threshold_time = time.clock()
              detect_time_lag = detect_pkt_dropped_gt_threshold_time - actual_pkt_dropped_gt_threshold_time
              print "\n*************************************************************************************************************************************************************"
              print "Total detected packets dropped = %s, exceeds threshold of %s.  Actual Time=%s, Detect Time = %s, Detection Time Lag = %s" %(detect_total_pkt_dropped,
                                                                                                                                               packets_dropped_threshold,
                                                                                                                                               actual_pkt_dropped_gt_threshold_time,
                                                                                                                                               detect_pkt_dropped_gt_threshold_time,
                                                                                                                                               detect_time_lag)
              print "*************************************************************************************************************************************************************\n"
              
              updatedTotalDrops = True
              result_list.append(detect_time_lag)
              
          
      self.pcount_results[vlan_id] = result_list
      self._log_pcount_results()

  def handle_flow_stats (self,event):
    """ Process a flow statistics query result from a given switch"""
    switch_id = event.connection.dpid
    
    entry_num=0
    packet_count=-1
    vlan_id = -1
    nw_src=-1
    nw_dst=-1
    
    for flow_stat in event.stats: #note that event stats is a list of flow table entries
      
      nw_src = flow_stat.match.nw_src
      nw_dst = flow_stat.match.nw_dst
      
      #insert something here about if it's a tagging or counting switch for this flow stat
      is_flow_tagging_switch = self._is_flow_tagging_switch(switch_id, nw_src, nw_dst)
      is_flow_counting_switch = self._is_flow_counting_switch(switch_id, nw_src, nw_dst)
      

      if not is_flow_tagging_switch and not is_flow_counting_switch:
        continue
      
      if is_flow_tagging_switch:
        for flow_action in flow_stat.actions:
          if isinstance(flow_action, of.ofp_action_vlan_vid): 
            packet_count = flow_stat.packet_count
            vlan_id = flow_action.vlan_vid
      elif is_flow_counting_switch:
        if flow_stat.match.dl_vlan != of.OFP_VLAN_NONE and flow_stat.match.dl_vlan != None:
          packet_count = flow_stat.packet_count
          vlan_id = flow_stat.match.dl_vlan
          
    
      # if was not set for some reason, then log nothing to output file
      if packet_count > -1:
        total = self._total_tag_and_cnt_switches(nw_src, nw_dst)
        self._record_pcount_value(vlan_id, nw_src, nw_dst, switch_id, packet_count,is_flow_tagging_switch, total)      

        log.debug("flow stat query result -- (s%s,src=%s,dst=%s,vid=%s) = %s; \t is_counter=%s, is_tagger=%s " %(switch_id,nw_src,nw_dst,vlan_id,packet_count,is_flow_counting_switch,is_flow_tagging_switch))
        packet_count=-1
        vlan_id = -1
        nw_src=-1
        nw_dst=-1
      
 
  
  def _handle_GoingUpEvent (self, event):
    """ When the connection to the controller is established, this function is called to register our components and listeners """
    self.listenTo(core.openflow)
    log.debug("Up...")
    
    
    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
    log.debug("Listening to flow stats ...")
    
    log.debug("configuration files -- measurement points file = %s, mtree file=%s" %(measure_pnts_file_str,mtree_file_str))



def launch ():
  
  core.registerNew(l3_arp_pcount_switch)
  
  

