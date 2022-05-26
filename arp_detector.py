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

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 :
		try :
			real_mac = get_mac(packet[scapy.ARP].psrc)
			response_mac = packet[scapy.ARP].hwsrc

			if real_mac != response_mac :
				print("[+] You are being hacked")
		except IndexError :
			pass


sniff("Ethernet")