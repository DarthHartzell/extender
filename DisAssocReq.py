
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11Disas )
from scapy.utils import wrpcap

from ElementContainer import IEContainer

broadcast	= 'ff:ff:ff:ff:ff:ff'

tim = '\x00\x01\x00\x00'
addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'

broadcom = '\x00\x10\x18\x01\x01\x00'


iec = IEContainer()

iec.addIe('vendor', broadcom)
iec.addIe('Management_MIC', '\x01'*16)

p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11Disas()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('disassocReq.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
