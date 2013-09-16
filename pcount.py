from pox.core import core
from pox.lib.recoco import Timer
import pox
log = core.getLogger("PCount_Session")

from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import utils, l3_arp_pcount

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time, random

global_vlan_id=0




class PCountSession (EventMixin):
  """ Single PCount session: measure the packet loss for flow, f, between an upstream switch and downstream switches, for a specified window of time
  
  """
  
  def __init__ (self):

    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} #this is a hack that saves us from queries each switch for their flow table)
 
    self.current_highest_priority_flow_num = of.OFP_DEFAULT_PRIORITY
    
    self.arpTable = {}
 
 
    
  def pcount_session(self,u_switch_id,d_switch_ids,strip_vlan_switch_ids,mtree_dstream_hosts,nw_src, nw_dst,flow_tables,arpTable,window_size):
    """
    Entry point to running a PCount session. Measure the packet loss for flow, f, between the upstream switch and  and downstream switches, for a specified window of time
    
    Keyword argumetns
    u_switch_id --  the id of the upstream switch, 
    d_switch_ids -- list of ids of the downstream switches
    strip_vlan_switch_ids -- the ids of nodes that should remove the VLAN tag from matched packets
    mtree_dstream_hosts -- the downstream hosts in teh multicast tree
    nw_src -- IP address of the source host (used to identify the flow to run the pcount session over)
    nw_dst -- IP address of the destination host, possibly a multicast address) (used to identify the flow to run the pcount sesssion over)
    flow_tables -- list of all flow tables, copied from l3_arp_pcount
    arpTable -- copy of the ARP table
    window_size -- window is the length (in seconds) of the sampling window
    
    """
    global global_vlan_id
    global_vlan_id+=1
    self.flowTables = flow_tables
    self.arpTable = arpTable

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) started pcount session between switches (s%s,%s) and flow (src=%s,dest=%s,vlan_id=%s) lasting %s seconds" %(current_time,u_switch_id,d_switch_ids,nw_src,nw_dst,global_vlan_id,window_size)) 
    self._start_pcount_session(u_switch_id, d_switch_ids,strip_vlan_switch_ids,mtree_dstream_hosts, nw_src, nw_dst,global_vlan_id)

    
    
    Timer(window_size, self._stop_pcount_session_and_query, args = [u_switch_id, d_switch_ids,nw_src,nw_dst,global_vlan_id])



  def _query_tagging_switch(self,switch_id,vlan_id,nw_src,nw_dst):
    """ Issue a query to the tagging switch, using (vlan_id,nw_src,nw_dst) to identify the flow """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match,priority= self._find_tagging_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent tagging stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values
    
  def _query_counting_switch(self,switch_id,vlan_id,nw_src,nw_dst):
    """ Send a query request to the counting switch """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = self._find_counting_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent counting stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values

  def _start_pcount_session(self,u_switch_id,d_switch_ids,strip_vlan_switch_ids,mtree_dstream_hosts,nw_src,nw_dst,vlan_id):
    """ Install flow entries for PCount session and install rule to drop packets (to simulate packet loss)
    
    Install a flow entry downstream to count tagged packets, then install tag and count rule upstream, and last install a rule to randomly drop packets so as to simulate packet loss
    
    """
    self.current_highest_priority_flow_num+=1
    
    # (1): count and tag all packets at d that match the VLAN tag
    for d_switch_id in d_switch_ids:
      self._start_pcount_downstream(d_switch_id, strip_vlan_switch_ids,mtree_dstream_hosts,vlan_id, nw_src, nw_dst)
    
    # (2): tag and count all packets at upstream switch, u
    self._start_pcount_upstream(u_switch_id,vlan_id, nw_src, nw_dst)  
    
    # (3): start a thread to install a rule which drops packets at u for a short period (this is used to measure time to detect packet loss)
    Timer(1, self._install_drop_pkt_flow, args = [u_switch_id,nw_src,nw_dst])
    
  def _find_orig_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,old_flow_priority):
    """ Find a flow matching (nw_src,nw_dst,old_flow_priority), remove it from the cache, and return this value """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.priority == old_flow_priority:
          match = flow_entry.match
          self.flowTables[switch_id].remove(flow_entry)
          return match 
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    

  def _find_tagging_flow_match(self,u_switch_id,nw_src,nw_dst,vlan_id):
    """ Find a tagging flow matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return this value """    
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    
    
  def _install_drop_pkt_flow(self,u_switch_id,nw_src,nw_dst):
    """ Install a rule to drop packets at the given switch.  Between a random integer between 0 and w/2, where w is window size of the PCount session, are dropped."""
    # highest possible value for flow table entry is 2^(16) -1
    flow_priority= 2**16 - 1
    
    timeout = random.randint(0,l3_arp_pcount.PCOUNT_WINDOW_SIZE/2) # amount of time packets will be dropped
    #timeout = l3_arp_pcount.PCOUNT_WINDOW_SIZE/2   # 5 seconds of dropping packets
                                                          
    send_flow_rem_flag = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
    
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,priority=flow_priority,hard_timeout = timeout)
    msg.flags = send_flow_rem_flag
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug( "\t * (%s) installed drop packet flow at s%s (src=%s,dst=%s)" %(current_time,u_switch_id,nw_src,nw_dst))
    
    #  To drop packet leave actions empty.  From OpenFlow 1.1 specification "There is no explicit action to represent drops. Instead packets whose action sets have 
    #  no output actions should be dropped"
    
    utils.send_msg_to_switch(msg, u_switch_id)
    
    

  def _find_counting_flow_match(self,switch_id,nw_src,nw_dst,vlan_id): 
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id) and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        return flow_entry.match
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  

  def _find_tagging_flow_and_clean_cache(self,u_switch_id,nw_src,nw_dst,vlan_id):
    """ Find a tagging flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            self.flowTables[u_switch_id].remove(flow_entry)
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    
    
  def _find_vlan_counting_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,vlan_id):
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        self.flowTables[switch_id].remove(flow_entry)
        return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  


  def _stop_pcount_session_and_query(self,u_switch_id,d_switch_ids,nw_src,nw_dst,vlan_id):
    """ Stop the PCount session by removing the tagging and counting flows and issuing a query for their corresponding packet counts.
    
    The operations to stop PCount takes place in the following order
      (1)  turn tagging off at the upstream switch by installing a copy of the original flow entry, that matches (nw_src,nw_dst), with higher priority than e' (the tagging flow)
      (2)  wait for time proportional to transit time between u and d to turn counting off at d (to account for in-transit packets after tagging is shut off)
      (3)  query upstream and downstream switches for packet counts
      (4)  delete the upstream tagging flow
      (5)  delete the original upstream flow used upstream to match packets for our flow (nw_src,nw_dst)
      (6)  delete the downstream VLAN counting flow

    """
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) stopped pcount session between switches (s%s,%s) for flow (src=%s,dst=%s,vlan_id=%s)" %(current_time,u_switch_id,d_switch_ids,nw_src,nw_dst,vlan_id))
    
    self.current_highest_priority_flow_num+=1
    new_flow_priority = self.current_highest_priority_flow_num   
    
    # (1): turn tagging off at u (reinstall e with higher priority than e'), 
    self._reinstall_basic_flow_entry(u_switch_id, nw_src, nw_dst, new_flow_priority)

    # (2): wait for time proportional to transit time between u and d to turn counting off at d
    time.sleep(l3_arp_pcount.PROPOGATION_DELAY)
    
    # (3) query u and d for packet counts
    self._query_tagging_switch(u_switch_id, vlan_id,nw_src,nw_dst)
    for d_switch_id in d_switch_ids:
      self._query_counting_switch(d_switch_id, vlan_id,nw_src,nw_dst)
    
    # (4) delete the original flow entries at u (e and e') and d (e and e'')
    
    # delete the upstream VLAN tagging flow
    u_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
    u_switch_msg.match,u_switch_msg.priority = self._find_tagging_flow_and_clean_cache(u_switch_id,nw_src,nw_dst,vlan_id)
    utils.send_msg_to_switch(u_switch_msg , u_switch_id)
 
    #delete the original upstream flow
    old_flow_priority = self.current_highest_priority_flow_num - 2
    u_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
    u_switch_msg2.match = self._find_orig_flow_and_clean_cache(u_switch_id,nw_src,nw_dst,old_flow_priority)
    u_switch_msg2.priority = old_flow_priority
    utils.send_msg_to_switch(u_switch_msg2 , u_switch_id)
 
    for d_switch_id in d_switch_ids:    
      # delete the downstream VLAN counting flow
      d_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      d_switch_msg.match,d_switch_msg.priority = self._find_vlan_counting_flow_and_clean_cache(d_switch_id,nw_src,nw_dst,vlan_id)
      utils.send_msg_to_switch(d_switch_msg , d_switch_id)
      
  
  def _reinstall_basic_flow_entry(self,switch_id,nw_src,nw_dst,flow_priority):
    """ Install a flow entry that only cares about (nw_src,nw_dst), i.e., nothing with vlan_id """
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst)
    
    prts = utils.find_nonvlan_flow_outport(self.flowTables, switch_id, nw_src, nw_dst)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    utils.send_msg_to_switch(msg, switch_id)
    
    self._cache_flow_table_entry(switch_id, msg)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) reinstalled basic flow (src=%s,dest=%s,priority=%s) at s%s" % (current_time,nw_src,nw_dst,flow_priority,switch_id))
  

  def _add_rewrite_single_mcast_dst_action(self,switch_id,msg,nw_mcast_dst,new_ip_dst):
    """ Append to the action list of flow, to rewrite a multicast address to a regular IP address"""
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_ip_dst))
    msg.actions.append(action)
  
    new_mac_addr = self.arpTable[switch_id][new_ip_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)



  def _start_pcount_downstream(self,d_switch_id,strip_vlan_switch_ids,mtree_dstream_hosts,vlan_id,nw_src,nw_dst):
    """ Install a flow entry at each downstream measurement node to count tagged packets. """
    # (1): create a copy of the flow entry, e, at switch d.  call this copy e''.  e''  counts packets using the VLAN field
    
    flow_priority = self.current_highest_priority_flow_num
    
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                priority=flow_priority)
    
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst,dl_vlan=vlan_id) 
    
    # this is where the action list should be sequential (one destination at-a-time) so the correct version of each modified packet is output when for leaf switches with > 1 adjacent downstream switch
    
    if mtree_dstream_hosts.has_key((nw_src,nw_dst,d_switch_id)):
      new_ip_dsts = mtree_dstream_hosts[(nw_src,nw_dst,d_switch_id)]
      
      for new_ip_dst in new_ip_dsts:
        self._add_rewrite_single_mcast_dst_action(d_switch_id, msg, nw_dst, new_ip_dst)
        
    
        if d_switch_id in strip_vlan_switch_ids:
          msg.actions.append(of.ofp_action_header(type=of.OFPAT_STRIP_VLAN))  
        
        prts = utils.find_nonvlan_flow_outport(self.flowTables, d_switch_id, nw_src, new_ip_dst)
        
        for p in prts:
          msg.actions.append(of.ofp_action_output(port = p))

    else:
      if d_switch_id in strip_vlan_switch_ids:
        msg.actions.append(of.ofp_action_header(type=of.OFPAT_STRIP_VLAN))  
        
      prts = utils.find_nonvlan_flow_outport(self.flowTables, d_switch_id, nw_src, nw_dst)
      
      for p in prts:
        msg.actions.append(of.ofp_action_output(port = p))

    # (2): install e'' at d with a higher priority than e
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) installed counting flow (src=%s,dest=%s,priority=%s,vlan_id=%s) at s%s" % (current_time,nw_src,nw_dst,flow_priority,vlan_id,d_switch_id))
    utils.send_msg_to_switch(msg, d_switch_id)
    
    self._cache_flow_table_entry(d_switch_id, msg)

  def _start_pcount_upstream(self,u_switch_id,vlan_id,nw_src,nw_dst):
    """ Start tagging and counting packets at the upstream switch.  Creates a new flow table entry to do so and is set with a higher priority than its non-tagging counterpart
    """
  # (1): create a copy of the flow entry, e, at switch u.  call this copy e'. 

    # highest possible value for flow table entry is 2^(16) -1
    #flow_priority= 2**16 - 1 - vlan_id #subtract vlan_id to make sure that the priority number is unique
    flow_priority = self.current_highest_priority_flow_num
    
    #prt = self._find_nonvlan_flow_outport(u_switch_id, nw_src, nw_dst)
    prts = utils.find_nonvlan_flow_outport(self.flowTables, u_switch_id, nw_src, nw_dst)
      
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst) 
  
  # (2):  e' tags packets using the VLAN field
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug( "\t * (%s) installed tagging flow at s%s (src=%s,dst=%s,set vid = %s)" %(current_time,u_switch_id,nw_src,nw_dst,vlan_id))
    vlan_action = of.ofp_action_vlan_vid()
    vlan_action.vlan_vid = vlan_id
    msg.actions.append(vlan_action)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    
  # (3): install e' at u with a higher priority than e
    utils.send_msg_to_switch(msg, u_switch_id)
    
    self._cache_flow_table_entry(u_switch_id, msg)
  
    
  def _cache_flow_table_entry(self,dpid,flow_entry):
    """ Add the flow table entry to our copy at the controller. """
   # print "DPG: called l3_arp_pcount.__cache_flow_table_entry:(%s,%s)" %(dpid,flow_entry) 
    
    if not self.flowTables.has_key(dpid):
      flow_table = list()
      flow_table.append(flow_entry)
      self.flowTables[dpid] = flow_table
    else:
      self.flowTables[dpid].append(flow_entry)


