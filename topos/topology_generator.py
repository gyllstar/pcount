#!/usr/bin/python

"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import random

def emptyNet():

    "Create an empty network and add nodes to it."

    net = Mininet( controller=Controller )

    info( '*** Adding controller\n' )
    net.addController( 'c0' )

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', ip='10.0.0.1' )
    h2 = net.addHost( 'h2', ip='10.0.0.2' )

    info( '*** Adding switch\n' )
    s3 = net.addSwitch( 's3' )

    info( '*** Creating links\n' )
    h1.linkTo( s3 )
    h2.linkTo( s3 )

    info( '*** Starting network\n')
    net.start()

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()


def generate_topology(num_nodes, max_edges):
	
	if num_nodes > 99:
		print "DPG: currently only support less than 100 nodes because as a first pass want to make IP addressing easy"

	# generate a random adjancy matrix
	adjacency_matrix = list()
	switch_id = 0
	while switch_id < num_nodes/2:	#should probably only do 1/2 the switches since we are creating bidirectional links here
		
		num_neighbors = random.randint(1,max_edges)
		
		neigh_cnt = 0
		neighbor_list = list()
		while neigh_cnt < num_neighbors:
			
			neighbor_id = random.randint(0,num_nodes)

		 	#protect against: (1) adding a link to neighbor with lower id b/c this will be added later (birectional links), (2) self-loops, (3) duplicate links
			if neighbor_id < switch_id or neighbor_id == switch_id or any(taken_id == neighbor_id for taken_id in neighbor_list)):
				continue
			
			neighbor_list.add(neighbor_id)

			neigh_cnt+=1
		
		adjacency_matrix.add(neighbor_list)

		switch_id +=1

	print adjancency_matrix

	#

if __name__ == '__main__':
    setLogLevel( 'info' )
    emptyNet()

