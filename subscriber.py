from scapy.all import *
import goose
# from time import sleep

your_iface = "enp3s0"
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
	g = goose.GOOSE(t[0].load)
	pl1 = t[0].load[:39]
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
