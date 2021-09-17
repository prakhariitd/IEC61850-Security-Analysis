from scapy.all import *
import goose
import hmac
import hashlib
from cryptography.fernet import Fernet
# from time import sleep

your_iface = "wlp2s0"
broad_ip = "224.0.0.0"

prev_stnum = -1
prevt = -1

while(True):
	t = sniff(iface=your_iface, count=1, filter = "udp and host 10.220.64.207 and port 49153")
		          # lfilter=lambda x: x.haslayer(UDP))
		          # and x[IP].src == broad_ip)
	t[0].show()
	# print (len(t[0].load))
	# print (len(t[0][UDP]))
	# print (len(t[0][IP]))
	# print (len(t[0][Ether]))
	# print (type(t))
	packet = t[0]
	i = packet[UDP].payload
	# extension = int(i.load[6:8])
	extension = 1
	apdu = i.load[11:-1*extension]
	mac = i.load[-1*extension:]

	with open('secret.key', 'rb') as my_private_key:
		key = my_private_key.read()

	h = hmac.new(key, apdu, hashlib.sha256)
	if (h.digest()==mac):
		f = Fernet(key)
		apdu_unen = f.decrypt(apdu)
		i = i.load[:11]+apdu_unen
		packet[UDP].remove_payload()
		packet[UDP].add_payload(i)

	else:
		print ("Compromised Data")
		break

	g = goose.GOOSE(packet.load)
	pl1 = packet.load[:39]
	# print (type(pl1))
	# print (repr(g.load))
	gpdu = goose.GOOSEPDU(g.load[31:])
	print (gpdu.__dict__)

	stnum = gpdu.__dict__['stNum'].data
	if (stnum != prev_stnum):
		if (stnum < prev_stnum):
			print ("Discard because smaller state", stnum)
			prevt = gpdu.__dict__['t'].data
			continue

		age = gpdu.__dict__['t'].data - prevt
		if (abs(age) > 640000):
			print ("Discard because old ", age)
			prevt = gpdu.__dict__['t'].data
			continue
		else:
			print ("Accepted Packet. Data is : ", stnum, gpdu.__dict__['allData'])
			prev_stnum = stnum
	else:
		print ("Discard beacuse same state : ", stnum)
	
	prevt = gpdu.__dict__['t'].data
	# print ("Previous time = ", prevt)
	# break
