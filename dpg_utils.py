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
    if con.dpid == switch_id:
      con.send(msg.pack())


def find_nonvlan_flow_outport(flowTables,switch_id,nw_src,nw_dst):
  
  if not flowTables.has_key(switch_id):
    log.error("something wrong at dpg_utils.find_nonvlan_flow_outport(): should be a flow entry cached for switch id = %s" %(switch_id))
    return -1
  
  outport = -1
  for flow_entry in flowTables[switch_id]:
    if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and isinstance(flow_entry.actions[0],of.ofp_action_output):
        outport = flow_entry.actions[0].port
  
  return outport