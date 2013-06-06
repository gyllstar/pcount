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

"""
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
import dpg_utils

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr,EthAddr

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 1200

# Timeout for ARP entries
ARP_TIMEOUT = 6000 * 2

# in seconds
PCOUNT_WINDOW_SIZE=10  
PCOUNT_CALL_FREQUENCY=PCOUNT_WINDOW_SIZE+5

#measure_pnts_file_str="measure-4s-1p.csv"
#measure_pnts_file_str="measure-3s-2p.csv"
#measure_pnts_file_str="measure-3s-1p.csv"
#measure_pnts_file_str="measure-2s-2p.csv"
measure_pnts_file_str="measure-2s-1p.csv"

mtree_file_str="mtree-4s-1t.csv"

IS_MTREE_EXPT=False
installed_mtrees=[] #list of multicast addresses with an mtree already installed


# mcast address = 10.10.10.10, src = 10.0.0.3, dst1=10.0.0.1, dst2 = 10.0.0.2
# tree: 
#       h1 -- s4
#                \ s6 --- s7 --- h3              
#       h2 -- s5 /
h1 = IPAddr("10.0.0.1")
h2 = IPAddr("10.0.0.2")
h3 = IPAddr("10.0.0.3")
mcast_mac_addr = EthAddr("10:10:10:10:10:10")




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
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return time.time() > self.timeout





class l3_arp_pcount_switch (EventMixin):
  def __init__ (self):
    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    self.listenTo(core)
    
    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} #this is a hack that saves us from queries each switch for their flow table)
    
    # dict.  d_switch_id --> list w/ entries (nw_src,nw_dst,u_switch_id)
    self.flow_measure_points={}
    
    #multicast address -> [src,dest1,dest2,...]
    self.mtrees = {}

    
    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    self.pcount_results = dict()
    
    self._read_flow_measure_points_file()
    
    self._read_mtree_file()
    
    
  def _read_mtree_file(self):
  
    mtree_file = "ext/topos/mtree/%s" %(mtree_file_str)
    
    # check if we need to load the mtree file
    num_switches = measure_pnts_file_str.split("-")[1]
    num_switches2 = mtree_file_str.split("-")[1]
    
    if num_switches != num_switches2:
      log.info("did not load mtree file ('%s') because not using a valid matching measurement points file (loaded '%s')" %(mtree_file_str,measure_pnts_file_str))
      #print "exiting at _read_mtree_file(), eventually delete this line"
      #os._exit(0)
      return
    
    global IS_MTREE_EXPT
    IS_MTREE_EXPT = True
    
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
      
      if self.mtrees.has_key(key):
        entry = self.mtrees[key]
        entry.append(val_list)
      else:
        entry = list()
        entry.append(val_list)
        self.mtrees[key] = entry
  
  def _read_flow_measure_points_file(self):
    

    measure_file = "ext/topos/%s" %(measure_pnts_file_str)
    
    for line_list in csv.reader(open(measure_file)):
      val_list = list()
      
      # check if it's a comment line
      if "#" in line_list[0]:
        continue
      
      val_list.insert(0, IPAddr(line_list[1]))
      val_list.insert(1, IPAddr(line_list[2]))
      val_list.insert(2, int(line_list[3]))
      key = int(line_list[0])
      
      if self.flow_measure_points.has_key(key):
        entry = self.flow_measure_points[key]
        entry.append(val_list)
      else:
        entry = list()
        entry.append(val_list)
        self.flow_measure_points[key] = entry
    
    #print self.flow_measure_points
    

    
  def _cache_flow_table_entry(self,dpid,flow_entry):
    
    if not self.flowTables.has_key(dpid):
      flow_table = list()
      flow_table.append(flow_entry)
      self.flowTables[dpid] = flow_table
    else:
      self.flowTables[dpid].append(flow_entry)

   
  def _start_pcount_thread(self,u_switch_id, d_switch_id, nw_src, nw_dst):
    
    pcounter = pcount.PCountSession()
    
    #Timer(PCOUNT_CALL_FREQUENCY,pcounter.pcount_session, args = [u_switch_id, d_switch_id,nw_src, nw_dst, self.flowTables, PCOUNT_WINDOW_SIZE])
    Timer(PCOUNT_CALL_FREQUENCY,pcounter.pcount_session, args = [u_switch_id, d_switch_id,nw_src, nw_dst, self.flowTables, PCOUNT_WINDOW_SIZE],recurring=True)
    

    
  def _check_start_pcount(self,d_switch_id,nw_src,nw_dst):
    
    if IS_MTREE_EXPT:
      return False,-1
    
    if not self.flow_measure_points.has_key(d_switch_id):
      return False,-1
    
    for measure_pnt in self.flow_measure_points[d_switch_id]:
      if measure_pnt[0] == nw_src and measure_pnt[1] == nw_dst:
        return True,measure_pnt[2]  #returns the upstream switch id 
      
    return False,-1  
  
  

  # counting means downstream
  def _is_flow_counting_switch(self,switch_id,nw_src,nw_dst):
     
    if self.flow_measure_points.has_key(switch_id):
      for measure_pnt in self.flow_measure_points[switch_id]:
        if measure_pnt[0] == nw_src and measure_pnt[1] == nw_dst:
          return True
     
    return False   
    
     
  
  
  # tagging takes place at the upstream node
  def _is_flow_tagging_switch(self,switch_id,nw_src,nw_dst):
    
    for measure_pnts in self.flow_measure_points.values():
      for measure_pnt in measure_pnts:
        if measure_pnt[2] == switch_id and measure_pnt[0] == nw_src and measure_pnt[1] == nw_dst:
          return True
    
    return False
        
  
  def _handle_ipv4_PacketIn(self,event,packet,dpid,inport):
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
        print "already setup mcast tree for s%s, inport=%s,dest=%s." %(dpid,inport,dstaddr)
        return
      
      log.info("special handling IP Packet in for multicast address %s" %(str(dstaddr)))
      self._setup_mtree(srcaddr,dstaddr,inport)
      self._setup_mtree_measure_pnts(dstaddr)
      #os._exit(0)
      #return
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
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                action=of.ofp_action_output(port = prt)) 
        
        match = of.ofp_match.from_packet(packet,inport) 
        
        msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=match._nw_src, nw_dst = match._nw_dst) #DPG: match using L3 address
        
        self._cache_flow_table_entry(dpid, msg)
        
        event.connection.send(msg.pack())
        
        start_pcount,u_switch_id = self._check_start_pcount(dpid,match.nw_src,match.nw_dst)
        
        if start_pcount:
          self._start_pcount_thread(u_switch_id, dpid, match.nw_src, match.nw_dst)
    else:
      log.error("no ARP entry at switch s%s for dst=%s" %(dpid,dstaddr))
        
  def _is_mcast_address(self,dst_ip_address):
    return self.mtrees.has_key(dst_ip_address)
  
  
  def _install_rewrite_dst_mcast_flow(self,switch_id,nw_src,ports,nw_mcast_dst,new_dst):
  
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,idle_timeout=FLOW_IDLE_TIMEOUT,hard_timeout=of.OFP_FLOW_PERMANENT)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)

    
    
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
    msg.actions.append(action)
    
    new_mac_addr = self.arpTable[switch_id][new_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)
        
    #print "(%s,%s,%s,%s,%s)" %(switch_id,nw_src,ports,nw_mcast_dst,new_dst)
    for prt in ports:
      msg.actions.append(of.ofp_action_output(port = prt))
    
    dpg_utils.send_msg_to_switch(msg, switch_id)
    self._cache_flow_table_entry(switch_id, msg)
    
    #print "sent to s%s the following msg=%s" %(switch_id,msg)
    #print "************************************************************************************** \n"
    
  def _install_basic_mcast_flow(self,switch_id,nw_src,ports,nw_mcast_dst):
  
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,idle_timeout=FLOW_IDLE_TIMEOUT,hard_timeout=of.OFP_FLOW_PERMANENT)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
    
    for prt in ports:
      msg.actions.append(of.ofp_action_output(port = prt))
    
    dpg_utils.send_msg_to_switch(msg, switch_id)
    self._cache_flow_table_entry(switch_id, msg)
    
    #print "sent to s%s the following msg=%s" %(switch_id,msg)
    #print "************************************************************************************** \n"
    
  # dpg defined method
  #def _update_arp_table_and_reply_depracted(self,switch_id,inport,packet):
  def _send_arp_reply(self,eth_packet,arp_packet,switch_id,inport,mcast_mac_addr,outport):
    
                #===============================================================
                #    r = arp()
                # r.hwtype = a.hwtype
                # r.prototype = a.prototype
                # r.hwlen = a.hwlen
                # r.protolen = a.protolen
                # r.opcode = arp.REPLY
                #
                # r.hwdst = a.hwsrc
                # r.protodst = a.protosrc #IP address
                # r.protosrc = a.protodst #IP address
                # r.hwsrc = self.arpTable[dpid][a.protodst].mac
                # e = ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
                # e.set_payload(r)   # r is the ARP REPLY
                # log.debug("%i %i answering ARP for %s" % (dpid, inport,
                # str(r.protosrc)))
                # msg = of.ofp_packet_out()
                # msg.data = e.pack()
                # msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                # msg.in_port = inport
                # event.connection.send(msg)
                #===============================================================
    
    
    r = arp()
    r.hwtype = arp_packet.hwtype
    r.prototype = arp_packet.prototype
    r.hwlen = arp_packet.hwlen
    r.protolen = arp_packet.protolen
    r.opcode = arp.REPLY
    
    r.protodst = arp_packet.protosrc
    r.protosrc = arp_packet.protodst
    #r.protodst = arp_packet.protodst
    #r.protosrc = arp_packet.protosrc  
    r.hwdst = arp_packet.hwsrc  
    r.hwsrc = mcast_mac_addr
    #r.hwdst = mcast_mac_addr
    #r.hwsrc = arp_packet.hwsrc  
    
    e = ethernet(type=eth_packet.type, src=r.hwsrc, dst=arp_packet.hwsrc)
    e.set_payload(r)
    #log.debug("%i %i answering ARP for %s" % (switch_id,inport,str(r.protosrc)))
    log.debug("^^^^^^^\t r.protosrc=%s,r.protodst=%s,r.hwsrc=%s,r.hwdst=%s, outport-param=%s" %(r.protosrc,r.protodst,r.hwsrc,r.hwdst,outport))
    log.debug("%i %i answering ARP request from src=%s to dst=%s" % (switch_id,inport,str(r.protosrc),str(r.protodst)))
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    #msg.actions.append(of.ofp_action_output(port = outport))
    msg.in_port = inport
    
    dpg_utils.send_msg_to_switch(msg, switch_id)
    #event.connection.send(msg)
    
    
  
    # dpg defined method #arp_packet,switch_id, nw_mcast_dst, prt, mcast_mac_addr
  def _update_arp_table_for_mtree(self,eth_packet,arp_packet,switch_id,inport,mcast_dst_ip_addr,outport,mcast_mac_addr):
    
    self.arpTable[switch_id][mcast_dst_ip_addr] = Entry(outport,mcast_mac_addr)
    #self.arpTable[switch_id][mcast_dst_ip_addr] = Entry(inport,mcast_mac_addr)
    
    #dpg: for debugging, only want to reply if its the first hop switch
    if switch_id ==7:
      self._send_arp_reply(eth_packet,arp_packet,switch_id,inport,mcast_mac_addr,outport)
    
    # send ARP table entry to switch?
  
  
  def _setup_mtree(self,nw_src,nw_mcast_dst,inport):
    
    print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    print "start of function call _setup_mtree(nw_src=%s,nw_mcast_dst=%s,inport=%s)" %(nw_src,nw_mcast_dst,inport)
    # mcast address = 10.10.10.10, src = 10.0.0.3, dst1=10.0.0.1, dst2 = 10.0.0.2
    # tree: 
    #       h1 -- s4
    #                \ s6 --- s7 --- h3              
    #       h2 -- s5 /
    #h1 = IPAddr("10.0.0.1")
    #h2 = IPAddr("10.0.0.2")
    #h3 = IPAddr("10.0.0.3")
    #mcast_mac_addr = EthAddr("10:10:10:10:10:10")
    #mcast_mac_addr = EthAddr("10-10-10-10-10-10")
    
    
    # s7: install (src=10.0.0.3, dst = 10.10.10.10, outport)
    switch_id = 7
    prt = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    ports=[]
    ports.append(prt) 
    self._install_basic_mcast_flow(switch_id, nw_src,ports,nw_mcast_dst)
    self.arpTable[switch_id][nw_mcast_dst] = Entry(prt,mcast_mac_addr)
    
    
    # s6: install (src=10.0.0.3, dst = 10.10.10.10, outport_list) or
    # s6: install (src=10.0.0.3, dst = 10.0.0.1, outport),  (src=10.0.0.3, dst = 10.0.0.6, outport) 
    switch_id = 6
    ports[:] = []
    p1 = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    p2 = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h2)
    ports.append(p1)
    ports.append(p2)
    self._install_basic_mcast_flow(switch_id, nw_src, ports, nw_mcast_dst)
    #self._update_arp_table_for_mtree(eth_packet,arp_packet,switch_id, inport,nw_mcast_dst, prt, mcast_mac_addr)
    #find port to s7
    #p3 = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h3)
    #self._update_arp_table_for_mtree(eth_packet,arp_packet,switch_id, inport,nw_mcast_dst, p3, mcast_mac_addr)
    
    # s5: rewrite destination address from 10.10.10.10 to h2 (10.0.0.2)
    switch_id = 5
    ports[:] = []
    p1 = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h2)
    ports.append(p1)
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, ports, nw_mcast_dst, h2)
    
    # s4: rewrite destination address from 10.10.10.10 to h1 (10.0.0.1)
    switch_id = 4
    ports[:] = []
    p1 = dpg_utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h1)
    ports.append(p1)
    self._install_rewrite_dst_mcast_flow(switch_id, nw_src, ports, nw_mcast_dst, h1)   
    
    global installed_mtrees
    installed_mtrees.append(nw_mcast_dst)
    
    print "end of function call  _setup_mtree(nw_src=%s,nw_mcast_dst=%s,inport=%s)" %(nw_src,nw_mcast_dst,inport)
    print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
    #os._exit(0)
    

  def _setup_mtree_measure_pnts(self,mcast_ip_address):
    print "_setup_mtree_measure_pnts()"
  
  def _handle_arp_PacketIn(self,event,packet,dpid,inport):
    a = packet.next  # 'a' seems to be an IP packet (or actually it's an ARP packet)
    
    #dpg code here
   # if a.opcode == arp.REPLY:
   #   log.debug("%i %i ARP %s sent by %s => (IP=%s,MAC=%s)", dpid, inport,{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
   #    'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst),str(a.hwdst))
   # else:
   #   log.debug("%i %i ARP %s %s => %s", dpid, inport,{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
   #    'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    
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
              outport = dpg_utils.find_nonvlan_flow_outport(self.flowTables,dpid, a.protosrc, h1)
              self.arpTable[dpid][a.protodst] = Entry(outport,mcast_mac_addr)
              self._send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
            
            return
          #  if a.protodst in installed_mtrees:
          #    print "already setup mcast tree for s%s, inport=%s,dest=%s, just resending the ARP reply and skipping mcast setup." %(dpid,inport,a.protodst)
          #    self._send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
          #    return
              
          #  log.info("skipping normal ARP Request code because ARP request is for multicast address %s" %(str(a.protodst)))
         #   self._setup_mtree(a.protosrc,a.protodst,inport,a,packet)
         #   self._setup_mtree_measure_pnts(a.protodst)
         #   return

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
                
                #dpg
                #if self.arpTable[dpid][a.protodst].mac.is_multicast():
                #  print "mac is multicast, exiting prematurely from ARP request for debugging purposes."
                  #should create multiple arp replies?
                #  return

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



  def _handle_PacketIn (self, event):
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

    return

  def _log_pcount_results(self):
    
    file_base = measure_pnts_file_str.split(".")[0]
    #w = csv.writer(open("ext/results/current/pcount-output.csv", "w"))
    w = csv.writer(open("ext/results/current/%s-output.csv" %(file_base), "w"))
    for key, val in self.pcount_results.items():
      w.writerow([key, val])
    
    #print self.pcount_results
    
    
#    file = "results/current/pcount-s2.txt" 
#    output = open(file, 'w')
#    output.write("# " + alg + ";" + time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())+ "\n")
#    output.write("# Number Nodes \t Number PMUs \t Number Observed \t Number Unobserved \t Number S2 Rounds \t Placement \n")
#    output.write(outputStr + "\n")
#    print "wrote results to file = %s \n" %(file)
#    output.close()
    
    
  def _record_pcount_value(self,vlan_id,nw_src,nw_dst,switch_id,packet_count,is_upstream):
    # index of 0 is for the upstream value and index of 1 is for the downstream value
    
    result_list = list()    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    if self.pcount_results.has_key(vlan_id):
      result_list = self.pcount_results[vlan_id]
    else:
      result_list.insert(0,nw_src)
      result_list.insert(1,nw_dst)
      
    if is_upstream:
      result_list.insert(2,switch_id)
      result_list.insert(3, packet_count)
    else:
      result_list.insert(4,switch_id)
      result_list.insert(5, packet_count)
    
    self.pcount_results[vlan_id] = result_list
    
    if len(result_list) == 6:
      #print self.pcount_results
      diff = result_list[3] - result_list[5]
      result_list.insert(6,diff)
      self.pcount_results[vlan_id] = result_list
      self._log_pcount_results()

  def handle_flow_stats (self,event):
 
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
          
      #print "result for (s%s,src=%s,dst=%s,vid=%s) = %s; \t is_counter=%s, is_tagger=%s " %(switch_id,nw_src,nw_dst,vlan_id,packet_count,is_flow_counting_switch,is_flow_tagging_switch)
    
      # if was not set for some reason, then log nothing to output file
      if packet_count > -1:
        #log.error("handle_flow_stats did not identify any flows at switch %s as a flow to be counted (by pcount) and should have." %(switch_id)) 
        self._record_pcount_value(vlan_id, nw_src, nw_dst, switch_id, packet_count,is_flow_tagging_switch)       # DPG: XXXXX this should go inside the "for loop"

        #print "\t----------------------------------------------------------"
        #print "\t|  \t\t S%s: VLAN_ID=%s, Count=%s\t\t | " %(switch_id,vlan_id,packet_count) 
        #print "\t----------------------------------------------------------\n"
        #log.debug("flow stat query result -- s%s: VLAN_ID=%s, Count=%s" %(switch_id,vlan_id,packet_count))
        log.debug("flow stat query result -- (s%s,src=%s,dst=%s,vid=%s) = %s; \t is_counter=%s, is_tagger=%s " %(switch_id,nw_src,nw_dst,vlan_id,packet_count,is_flow_counting_switch,is_flow_tagging_switch))
        packet_count=-1
        vlan_id = -1
        nw_src=-1
        nw_dst=-1
      
    #print "\n end of handle_flow_stats for s%s \n" %(switch_id)
 
  
  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")
    
    
    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
    log.debug("Listening to flow stats ...")



def launch ():
  
  core.registerNew(l3_arp_pcount_switch)
  
  

