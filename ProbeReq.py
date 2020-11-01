
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11ProbeReq, Dot11Elt)
from scapy.utils import wrpcap, raw

from ElementContainer import IEContainer
from binascii import unhexlify

broadcast	= 'ff:ff:ff:ff:ff:ff'
rates 	= '\x02\x04\x0b\x16\x0c\x12\x18\x24'
esrates 	= '\x30\x48\x60\x6c'

addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'

ssid = 'DarkWeb'
dsset = '\x07'
broadcom = '\x00\x10\x18\x01\x01\x00'
one = '\x01'
three = '\x01\x02\x03'


iec = IEContainer()
iec.addIe("SSID", ssid)
iec.addIe("Rates", rates)
iec.addIe("Request", one)
iec.addIe("ESRates", esrates)
iec.addIe("DSset", dsset)
iec.addIe('SupportedOperatingClasses', three)
iec.addIe('HT_Caps', one*26)
iec.addIe('BSS_Coexist', one)
iec.addIe('Ext_Caps', one*10)
s1 = Dot11Elt(ID='SSID', info='a')

iec.addIe('SSID_List', raw(s1))
iec.addIe('Channel_Usage', one)
iec.addIe('Interworking', one*9)
iec.addIe('Mesh_ID', one)
iec.addIe('Multiband', one*22)
iec.addIe('DMG_Caps', one*22)
iec.addIe('Multi_MAC_Sublayers', one)
iec.addIe('VHT_Caps', one*12)
iec.addIe('Mult_Ele_ID', one)
iec.addIe('vendor', broadcom)

p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11ProbeReq()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('probeReq.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
