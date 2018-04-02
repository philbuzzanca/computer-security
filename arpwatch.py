from scapy.all import *
from argparse import ArgumentParser
from python_arptable import ARPTABLE

def detect_poison(interface):
	arptable_dict = {}
	print("Current arp table on " + interface)
	print("---------------------" + "-"*len(interface))
	for entry in ARPTABLE:
		if entry['Device'] == interface:
			print(entry['HW address'] + " --> " + entry['IP address'])
			arptable_dict[entry['HW address']] = entry['IP address']
	print("---------------------" + "-"*len(interface))

	while True:
		try:
			pkt = sniff(filter='arp', store=1, count=1, iface=interface)
			if pkt[0][ARP].op == 2: # who-has request
				for key, value in arptable_dict.iteritems():
					if pkt[0][ARP].psrc == value and pkt[0][ARP].hwsrc != key:
						print("WARNING: IP address {} changed MAC from {} to {}".format(pkt[0][ARP].psrc, key, pkt[0][ARP].hwsrc))
		except KeyboardInterrupt:
			exit("Process exited by user.\n")

if __name__ == "__main__":
	ap = ArgumentParser(description="ARP poisoning detector")
	ap.add_argument("-i", "--interface", default="wlp2s0", help="Network interface")
	args = vars(ap.parse_args())
	try:
		print("Starting ARP poison detector ...")
		detect_poison(args["interface"])
	except IOError:
		exit("Invalid interface")