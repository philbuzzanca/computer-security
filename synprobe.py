from scapy.all import *
from argparse import ArgumentParser
import sys
import socket

def range_to_list(portrange):
	toReturn = []
	if "-" in portrange:
		num1, num2 = portrange.split('-')
		i = int(num1)
		while(i <= int(num2)):
			toReturn.append(i)
			i += 1
	else:
		toReturn.append(int(portrange))
	return toReturn

ports_to_scan = [20, 21, 22, 23, 80, 443]

ap = ArgumentParser(description="SYN scan probe")
ap.add_argument("-p", "--port_range", default="dflt", help="One port or a range of ports (eg. 40 or 20-55")
ap.add_argument('target', type=str, help="Target IP")
args = vars(ap.parse_args())
if args["port_range"] is not "dflt":
	ports_to_scan = range_to_list(args["port_range"])

open_ports = []
print("Scanning...")
for port in ports_to_scan:
	ans=sr1(IP(dst=args["target"])/TCP(dport=port, flags="S"), verbose=0)
	if str(type(ans)) is not "<type 'NoneType'>" and ans.haslayer(TCP):
		if ans.getlayer(TCP).flags == 0x12:
			open_ports.append(port)
			print(ans.summary())

print("Open ports: " + str(open_ports))

for port in open_ports:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print("Connecting to port " + str(port) + "...")
	s.connect((args["target"], port))
	print("Connected to " + args["target"] + ":" + str(port))
	s.send("abcdefghijklmnopqrstuvwxyz\r\n")
	response = s.recv(1024)
	print(response)
	s.close()
	
