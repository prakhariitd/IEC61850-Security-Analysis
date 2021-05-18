from scapy.all import *
import goose
from time import sleep
from cryptography.fernet import Fernet
import hmac
import hashlib

packet = None
a = rdpcap("wireshark12.pcap")
for packet in a:
	try:
        # if i.type == 0x88b8:
		# your_iface = "enp3s0"
		# i = sniff(iface=your_iface, count=1, filter = "udp and host 10.220.64.207 and port 49153")

		i = packet # when GOOSE
		# i = packet[UDP].payload #when R-GOOSE
		pl1 = i.load[:11]
		apdu = i.load[11:]
		# print (len(pl1))
		# print (len(i.load[:39]))

		# Encryption
		key = Fernet.generate_key() 
		with open('secret.key', 'wb') as new_key_file:
			new_key_file.write(key)

		# print (apdu)

		f = Fernet(key)
		ciphertext = f.encrypt(apdu)
		# print (ciphertext)
		h = hmac.new(key, ciphertext, hashlib.sha256)
		pl = pl1[:6]+bytes(h.digest_size)+pl1[8:]+bytes(ciphertext)+h.digest()

		#GOOSE
		i.remove_payload()
		i.add_payload(pl)
		i.show()
		packet_send = i

		#R-GOOSE
		# packet[UDP].remove_payload()
		# packet[UDP].add_payload(pl)
		# packet.show()
		# packet_send = packet
		sendp(packet_send, iface="enp3s0")
		# i[UDP].remove_payload()
		# i[UDP].add_payload(pl)

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