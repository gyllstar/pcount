
class Tree ():
  """ Multicast Tree Abstraction """
  
  nodes_and_level_list = [] #list of tuples (node,tree_level)
  edge_list=[] 
  mcast_address = None
  
  def compute_node_levels(self):
    """ Finds the level in the tree each node occupies.  Populates node_and_level_list"""
    
    print "placeholder"

class BackupTreeInstaller ():
  """ TODO document
  
  Note: probably should be a singleton
  
  """
  
  def __init__ (self):

    #self.flowTables = {}  # copy of the flow tables from l3_arp_pcount
    #self.arpTable = {}
    #self.primary_trees = {}
    
     # multicast_dst_address,link -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the backup tree
    self.backup_trees = {}
    
    self.controller = None # l3_arp_pcount instance
 
   
  def preinstall_backup_trees(self,controller):
    
    print "not sure if we need this"
    
  
  def activate_preinstalled_backup_trees(self):
    print "not sure if we need this"
    
  
  def _find_nodes_to_signal(self,primary_tree,backup_tree):
    """ Find the set of edges in the backup tree but not in the primary tree, and return the upstream node of each edge"""
    unique_edges =  [link for link in backup_tree if link not in primary_tree]
    
    upstream_nodes = [link[0] for link in unique_edges] 
    
    return upstream_nodes
    
  def _sort_nodes_bottom_up(self,node_list,root_node):
    
    print "placeholder"
  
  def install_backup_trees(self,failed_link,controller):
    """ Reactive Algorithm: install backup trees bottom-up
    
    Keyword Arguments:
    failed_link -- tuple (u,d) representing a link from upstream_switch_id to the downstream_swtich_id
    controller -- an l3_arp_pcount instance
    """
    self.controller = controller
    
    # (1) T <- find the primary trees using failed_link
    affected_mcast_addresses = self._find_affected_trees(controller.primary_trees, failed_link)
    
    # (2) For each T: U <- the set of switches to signal
    for mcast_addr in affected_mcast_addresses:
      primary_tree = controller.primary_trees[mcast_addr]
      nodes_to_signal = self._find_nodes_to_signal(primary_tree,self.backup_trees[(mcast_addr,failed_link)])
      self._sort_nodes_bottom_up(nodes_to_signal)
      
    
    # (2a) for u \in U determine the flow entry rule
    
    # (3) Signal the switches 

  def _find_affected_trees(self,primary_trees,failed_link):
    """ Find and return the multicast address associated with the primary trees using the failed link 
    
    Keyword Arguments:
    primary_trees -- dictionary: multicast_dst_address -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the primary tree
    failed_link -- tuple (upstream_switch_id,downstream_switch_id)
    
    """
    affected_mcast_addresses = []
    for mcast_addr in primary_trees.keys():
      for link in primary_trees[mcast_addr]:
        if link == failed_link:
          affected_mcast_addresses.append(mcast_addr)
          
    return affected_mcast_addresses

    
  def depracted_find_affected_trees(self,primary_trees,failed_link):
    """ Find and return the multicast address associated with the primary trees using the failed link 
    
    Keyword Arguments:
    primary_trees -- dictionary: multicast_dst_address -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the primary tree
    failed_link -- tuple (upstream_switch_id,downstream_switch_id)
    
    """
    affected_mcast_addresses = []
    for mcast_addr in primary_trees.keys():
      for link in primary_trees[mcast_addr]:
        if link == failed_link:
          affected_mcast_addresses.append(mcast_addr)
          
    return affected_mcast_addresses

          