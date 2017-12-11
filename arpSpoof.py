"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav

ARP spoof detection.
"""

import os
import netifaces
import sys
import logging
import scapy

requests = []
replies_count = {}
notification_issued = []
request_threshold = 10

def checkSpoof (source, source_mac, destination):
    """
    check if its an arp packet.
    :param source: attacker source address
    :param source_mac: attackers hardware source address
    :param destination: destination address given by attacker
    :return:
    """
    if destination == broadcast:
        if not source_mac in replies_count:
            replies_count[source_mac] = 0
    if not source in requests and source != local_ip:
        if not source_mac in replies_count:
            replies_count[source_mac] = 0
        else:
            replies_count[source_mac] += 1
        logging.warning("ARP replies detected from MAC {}. Request count {}".format(source_mac, replies_count[source_mac]))
        if (replies_count[source_mac] > request_threshold) and (not source_mac in notification_issued):
            logging.error("ARP Spoofing Detected from MAC Address {}".format(source_mac))
            print ("ARP Spoofing Detected", "The current network is being attacked.", "ARP Spoofing Attack Detected from {}.".format(source_mac))
    else:
        if source in requests:
            requests.remove(source)

def getAdrress (packet):
    """
    gets attacker addresses and calls the method to check spoof.
    :param packet: packet received by attacker.
    :return:
    """
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if operation == 'is-at':
        return checkSpoof (source, source_mac, dest)


def main():
    global local_ip
    global broadcast

    if os.geteuid() != 0:
        exit("Need root permission")
        sys.exit()

    # log file
    filename = "spoof.log"

    logging.basicConfig(filename=filename, filemode="a", level=logging.DEBUG)

    # interface
    interface = unicode("en0", "utf-8")
    addrs = netifaces.ifaddresses(interface)
    try:
        local_ip = addrs[netifaces.AF_INET][0]["addr"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
    except KeyError:
        sys.exit("Cannot read address/broadcast address on interface {}".format(interface))
    logging.info("ARP Spoofing Detection Started on {}".format(local_ip))
    print("ARP Spoofing Detection Started.")
    scapy.sniff(filter="arp", prn=getAdrress, store=0)

    pass
if __name__=="__main__":
    main()