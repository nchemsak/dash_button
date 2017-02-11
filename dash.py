import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def arp_display(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        if pkt[ARP].psrc:
            if pkt[ARP].hwsrc == '00:25:9c:ec:3b:24':
                print ("You clicked the Dash Button!!!!!!  You are awesome.")
                # note = input("Enter your name > ")

                # if note == "nick":
                #     print("you are awesome")

                # elif note == "Lacey":
                #     print("too bad you aren't nick")
        # print ("ARP Probe from: " + pkt[ARP].hwsrc)

# print (sniff(prn=arp_display, filter="arp", store=0, count=1))
if __name__ == "__main__":
    sniff(prn=arp_display, filter="arp", store=0, count=1)
