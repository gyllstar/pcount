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
DPG: Utility functions

"""
from pox.core import core
log = core.getLogger("dpg_utils")
import pox.openflow.libopenflow_01 as of

def send_msg_to_switch(msg,switch_id):
  
  for con in core.openflow._connections.itervalues():
    #print "msg to s%s: \n %s" %(switch_id,msg)
    if con.dpid == switch_id:
      con.send(msg.pack())


def remove_old_flows_UNUSED(u_switch_id,nw_src,nw_dst,vlan_id,d_switch_ids):
  
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
    d_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
    d_switch_msg2.match = self._find_orig_flow_and_clean_cache(d_switch_id,nw_src,nw_dst,old_flow_priority)
    d_switch_msg2.priority = old_flow_priority
    dpg_utils.send_msg_to_switch(d_switch_msg2 , d_switch_id)

def _is_vlan_flow_entry(flow_entry):
  

    
  for flow_entry in self.flowTables[u_switch_id]:
    if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
      for flow_action in flow_entry.actions:
        if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
          return flow_entry.match,flow_entry.priority

  log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
  
  
  for flow_entry in self.flowTables[switch_id]:
    if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
      return flow_entry.match


def find_nonvlan_flow_outport(flowTables,switch_id,nw_src,nw_dst):
  
  if not flowTables.has_key(switch_id):
    log.error("something wrong at dpg_utils.find_nonvlan_flow_outport(): should be a flow entry cached for switch id = %s" %(switch_id))
    return -1
  
  outports = []
  for flow_entry in flowTables[switch_id]:
    
    if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
      for action in flow_entry.actions:
        if isinstance(action, of.ofp_action_output):
          outports.append(action.port)
      
      return outports #DPG: important to return inside the outer for loop because otherwise we append multiple copies of the desired outport
  #print "(switch_id=%s,nw_src=%s,nw_dst=%s) has outport = %s" %(switch_id,nw_src,nw_dst,outport)
  #return outports


