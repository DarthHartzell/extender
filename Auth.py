
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11Auth)
from scapy.utils import wrpcap, raw

from ElementContainer import IEContainer
from DotExtended import Dot11Extended
from binascii import unhexlify

broadcast	= 'ff:ff:ff:ff:ff:ff'
addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'

iface = 'eth0'
broadcom = '\x00\x10\x18\x01\x01\x00'
one = '\x01'
three = '\x01\x02\x03'
five = '\x01\x02\x03\x04\x05'

msoft = '0050f20101000050f20201000050f20201000050f202'

iec = IEContainer()
iec.addIe('challenge', one)
iec.addIe('RSNinfo', unhexlify("0100000fac020200000fac04000fac020100000fac020000"))
iec.addIe('Mobility_Domain', three)
iec.addIe('FTE', one*82)
iec.addIe('TimeoutInterval', five)

iec.addIe('RIC', unhexlify('00000000'))

iec.addIe('Multiband', one*22)
iec.addIe('Neighbor_Rep', one*13)
iec.addIe('vendor', broadcom)

p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11Auth()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('auth.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
