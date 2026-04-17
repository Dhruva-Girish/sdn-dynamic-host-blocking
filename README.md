# Dynamic Host Blocking System using SDN

## Overview
This project implements a dynamic host blocking system using Software Defined Networking (SDN). The controller monitors traffic and blocks hosts that generate suspicious activity.

## Tools Used
- Mininet – used to simulate the network topology with hosts and switches.
- POX Controller – acts as the SDN controller that monitors traffic and installs blocking rules.
- OpenFlow – protocol used for communication between the controller and switch to install flow rules.
- Python – programming language used to implement the controller logic.

## Topology
Single switch topology:

h1 = client  
h2 = server  
h3 = attacker  

## Features
- Traffic monitoring
- Suspicious host detection
- Dynamic host blocking
- Flow rule installation
- Logging events

## Demo Commands

Start controller:

cd ~/pox  
./pox.py openflow.of_01 dynamic_block

Start Mininet:

sudo mn --topo single,3 --controller=remote,ip=127.0.0.1,port=6633

Test connectivity:

pingall

Simulate attack:

h3 ping h1

Verify flow rule:

dpctl dump-flows

## Author
Dhruva Girish
