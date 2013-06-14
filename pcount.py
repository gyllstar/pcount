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
DPG: PCount algorithm

"""

from pox.core import core
from pox.lib.recoco import Timer
import pox
log = core.getLogger("PCount_Session")
#log = core.getLogger()

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import dpg_utils

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows (in seconds)
FLOW_IDLE_TIMEOUT = 1200   #20 minutes

# Timeout for ARP entries
ARP_TIMEOUT = 6000 * 2

PCOUNT_ON=True
PROPOGATION_DELAY=2 #seconds

global_vlan_id=0




class PCountSession (EventMixin):
  
  
  def __init__ (self):

    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} #this is a hack that saves us from queries each switch for their flow table)
 
    self.current_highest_priority_flow_num = of.OFP_DEFAULT_PRIORITY
 
 
 
    
  def pcount_session(self,u_switch_id,d_switch_ids,strip_vlan_switch_ids,nw_src, nw_dst,flow_tables,window_size):
    """
    measure the packet loss for flow, f, between the upstream swtich and downstream for a specified window of time
    
    u_switch_id is the id of the upstream switch, 
    d_switch_ids is a list of ids of the downstream switches,
    flow is the flow in which packet loss is measured,
    window is the length (in time) of the sampling window
    """
    
    
    global global_vlan_id
    global_vlan_id+=1
    self.flowTables = flow_tables

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) started pcount session between switches (s%s,%s) and flow (src=%s,dest=%s,vlan_id=%s) lasting %s seconds" %(current_time,u_switch_id,d_switch_ids,nw_src,nw_dst,global_vlan_id,window_size))    
    self._start_pcount_session(u_switch_id, d_switch_ids,strip_vlan_switch_ids, nw_src, nw_dst,global_vlan_id)

    
    
    Timer(window_size, self._stop_pcount_session_and_query, args = [u_switch_id, d_switch_ids,nw_src,nw_dst,global_vlan_id])



  # note: this function ends up querying the switch for all flow entries that match the (nw_src, nw_dst).  there is nothing unique in the VLAN tagging match structure
  #       to allow us to just query for the tagging flow.  (cannot use priority becasue this is not in the match structure)  
  def _query_tagging_switch(self,switch_id,vlan_id,nw_src,nw_dst):
    
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match,priority= self._find_tagging_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent tagging stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values
    
  def _query_counting_switch(self,switch_id,vlan_id,nw_src,nw_dst):

    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = self._find_counting_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent counting stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values

  def _start_pcount_session(self,u_switch_id,d_switch_ids,strip_vlan_switch_ids,nw_src,nw_dst,vlan_id):
    
    self.current_highest_priority_flow_num+=1
    
    # (1): count and tag all packets at d that match the VLAN tag
    for d_switch_id in d_switch_ids:
      self._start_pcount_downstream(d_switch_id, strip_vlan_switch_ids, vlan_id, nw_src, nw_dst)
    
    # (2): tag and count all packets at upstream switch, u
    self._start_pcount_upstream(u_switch_id,vlan_id, nw_src, nw_dst)  
    
  def _find_orig_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,old_flow_priority):
    
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.priority == old_flow_priority:
          match = flow_entry.match
          self.flowTables[switch_id].remove(flow_entry)
          return match 
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    

  def _find_tagging_flow_match(self,u_switch_id,nw_src,nw_dst,vlan_id):
    
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    
  def _find_counting_flow_match(self,switch_id,nw_src,nw_dst,vlan_id): 
    
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        return flow_entry.match
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  

  def _find_tagging_flow_and_clean_cache(self,u_switch_id,nw_src,nw_dst,vlan_id):
    
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            self.flowTables[u_switch_id].remove(flow_entry)
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    
    
  def _find_vlan_counting_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,vlan_id):
    
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        self.flowTables[switch_id].remove(flow_entry)
        return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  


  def _stop_pcount_session_and_query(self,u_switch_id,d_switch_ids,nw_src,nw_dst,vlan_id):
    """
    measure the packet loss for flow, f, between the upstream swtich and downstream for a specified window of time
    
    u_switch_id is the upstream switch id, 
    d_switch_ids list of the downstream switch ids,
    flow is the flow in which packet loss is measured
    """
    
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) stopped pcount session between switches (s%s,%s) for flow (src=%s,dst=%s,vlan_id=%s)" %(current_time,u_switch_id,d_switch_ids,nw_src,nw_dst,vlan_id))
    
    self.current_highest_priority_flow_num+=1
    new_flow_priority = self.current_highest_priority_flow_num   
    
    # (1): turn tagging off at u (reinstall e with higher priority than e'), 
    self._reinstall_basic_flow_entry(u_switch_id, nw_src, nw_dst, new_flow_priority)

    # (2): wait for time proportional to transit time between u and d to turn counting off at d
    time.sleep(PROPOGATION_DELAY)
    
 #   for d_switch_id in d_switch_ids:
 #     self._reinstall_basic_flow_entry(d_switch_id, nw_src, nw_dst, new_flow_priority)
    
    # (3) query u and d for packet counts
    self._query_tagging_switch(u_switch_id, vlan_id,nw_src,nw_dst)
    for d_switch_id in d_switch_ids:
      self._query_counting_switch(d_switch_id, vlan_id,nw_src,nw_dst)
    
    # (4) delete the original flow entries at u (e and e') and d (e and e'')
    
    # delete the upstream VLAN tagging flow
    u_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
    u_switch_msg.match,u_switch_msg.priority = self._find_tagging_flow_and_clean_cache(u_switch_id,nw_src,nw_dst,vlan_id)
    dpg_utils.send_msg_to_switch(u_switch_msg , u_switch_id)
 
    #delete the original upstream flow
    old_flow_priority = self.current_highest_priority_flow_num - 2
    u_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
    u_switch_msg2.match = self._find_orig_flow_and_clean_cache(u_switch_id,nw_src,nw_dst,old_flow_priority)
    u_switch_msg2.priority = old_flow_priority
    dpg_utils.send_msg_to_switch(u_switch_msg2 , u_switch_id)
 
    for d_switch_id in d_switch_ids:    
      # delete the downstream VLAN counting flow
      d_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      d_switch_msg.match,d_switch_msg.priority = self._find_vlan_counting_flow_and_clean_cache(d_switch_id,nw_src,nw_dst,vlan_id)
      dpg_utils.send_msg_to_switch(d_switch_msg , d_switch_id)
      
      #delete the original downstream flow
 #     d_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
 #     d_switch_msg2.match = self._find_orig_flow_and_clean_cache(d_switch_id,nw_src,nw_dst,old_flow_priority)
 #     d_switch_msg2.priority = old_flow_priority
 #     dpg_utils.send_msg_to_switch(d_switch_msg2 , d_switch_id)

  
  def _reinstall_basic_flow_entry(self,switch_id,nw_src,nw_dst,flow_priority):
    
       
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                               # idle_timeout=FLOW_IDLE_TIMEOUT,
                               # hard_timeout=of.OFP_FLOW_PERMANENT,
                                priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst)
    #prt = self._find_nonvlan_flow_outport(switch_id, nw_src, nw_dst)   #TODO: fix
    
    prts = dpg_utils.find_nonvlan_flow_outport(self.flowTables, switch_id, nw_src, nw_dst)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    dpg_utils.send_msg_to_switch(msg, switch_id)
    
    self._cache_flow_table_entry(switch_id, msg)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) reinstalled basic flow (src=%s,dest=%s,priority=%s) at s%s" % (current_time,nw_src,nw_dst,flow_priority,switch_id))
  
 

  def _start_pcount_downstream(self,d_switch_id,strip_vlan_switch_ids,vlan_id,nw_src,nw_dst):
    """
      start tagging and counting packets at the upstream switch
    """
    # (1): create a copy of the flow entry, e, at switch d.  call this copy e''.  e''  counts packets using the VLAN field
    
    flow_priority = self.current_highest_priority_flow_num
    
    prts = dpg_utils.find_nonvlan_flow_outport(self.flowTables, d_switch_id, nw_src, nw_dst)
      
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                               # idle_timeout=FLOW_IDLE_TIMEOUT,
                               # hard_timeout=of.OFP_FLOW_PERMANENT,
                                priority=flow_priority)
    
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst,dl_vlan=vlan_id) 
    
    if d_switch_id in strip_vlan_switch_ids:
      msg.actions.append(of.ofp_action_header(type=of.OFPAT_STRIP_VLAN))  #DPG: temp for debugging

    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))

    # (2): install e'' at d with a higher priority than e
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) installed counting flow (src=%s,dest=%s,priority=%s,vlan_id=%s) at s%s" % (current_time,nw_src,nw_dst,flow_priority,vlan_id,d_switch_id))
    dpg_utils.send_msg_to_switch(msg, d_switch_id)
    
    self._cache_flow_table_entry(d_switch_id, msg)

  def _start_pcount_upstream(self,u_switch_id,vlan_id,nw_src,nw_dst):
    """
      start tagging and counting packets at the upstream switch
    """
    
  # (1): create a copy of the flow entry, e, at switch u.  call this copy e'. 

    # highest possible value for flow table entry is 2^(16) -1
    #flow_priority= 2**16 - 1 - vlan_id #subtract vlan_id to make sure that the priority number is unique
    flow_priority = self.current_highest_priority_flow_num
    
    #prt = self._find_nonvlan_flow_outport(u_switch_id, nw_src, nw_dst)
    prts = dpg_utils.find_nonvlan_flow_outport(self.flowTables, u_switch_id, nw_src, nw_dst)
      
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                              #  idle_timeout=FLOW_IDLE_TIMEOUT,
                              #  hard_timeout=of.OFP_FLOW_PERMANENT,
                                priority=flow_priority)
                               # action=of.ofp_action_output(port = prt)) 
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst) 
  
  # (2):  e' tags packets using the VLAN field
  
    #msg.actions.append(of.ofp_action_output(port = prt))
    
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug( "\t * (%s) installed tagging flow at s%s (src=%s,dst=%s,set vid = %s)" %(current_time,u_switch_id,nw_src,nw_dst,vlan_id))
    vlan_action = of.ofp_action_vlan_vid()
    vlan_action.vlan_vid = vlan_id
    msg.actions.append(vlan_action)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    
  # (3): install e' at u with a higher priority than e
    dpg_utils.send_msg_to_switch(msg, u_switch_id)
    
    self._cache_flow_table_entry(u_switch_id, msg)
  
    
  def _cache_flow_table_entry(self,dpid,flow_entry):
    
   # print "DPG: called l3_arp_pcount.__cache_flow_table_entry:(%s,%s)" %(dpid,flow_entry) 
    
    if not self.flowTables.has_key(dpid):
      flow_table = list()
      flow_table.append(flow_entry)
      self.flowTables[dpid] = flow_table
    else:
      self.flowTables[dpid].append(flow_entry)


