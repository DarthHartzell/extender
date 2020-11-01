
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11ReassoReq)
from scapy.utils import wrpcap

from ElementContainer import IEContainer
from binascii import unhexlify

broadcast	= 'ff:ff:ff:ff:ff:ff'
rates 	= '\x02\x04\x0b\x16\x0c\x12\x18\x24'
esrates 	= '\x30\x48\x60\x6c'

addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'

ssid = 'DarkWeb'

broadcom = '\x00\x10\x18\x01\x01\x00'
one = '\x01'
two = '\x01\x02'
three = '\x01\x02\x03'
four = '\x01\x02\x03\x04'
five = '\x01\x02\x03\x04\x05'

iec = IEContainer()
iec.addIe("SSID", ssid)
iec.addIe("Rates", rates)
iec.addIe("ESRates", esrates)
iec.addIe('Pwr_Caps', two)
iec.addIe('Supported_Channels', four)
iec.addIe('RSNinfo', unhexlify("0100000fac020200000fac04000fac020100000fac020000"))
iec.addIe('QoS Capability', one)
iec.addIe('RMEnabledCap', five)
iec.addIe('Mobility_Domain', three)
iec.addIe('FTE', one*82)

iec.addIe('RIC', unhexlify('00000000'))
iec.addIe('SupportedOperatingClasses', three)
iec.addIe('HT_Caps', one*26)
iec.addIe('BSS_Coexist', one)
iec.addIe('Ext_Caps', one*10)
iec.addIe('QoS_Traffic_Cap', one)
iec.addIe('TIM_Broadcast_Req', one)
iec.addIe('FMS_Req', one)
iec.addIe('DMS_Req', one)

iec.addIe('Interworking', one*9)
iec.addIe('Multiband', one*22)
iec.addIe('DMG_Caps', one*22)
iec.addIe('Multi_MAC_Sublayers', one)
iec.addIe('VHT_Caps', one*12)
iec.addIe('Op_Mode_Notify', five)
iec.addIe('vendor', broadcom)


p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11ReassoReq()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('reassocReq.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
