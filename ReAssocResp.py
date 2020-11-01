
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11ReassoResp )
from scapy.utils import wrpcap

from ElementContainer import IEContainer
from binascii import unhexlify

broadcast	= 'ff:ff:ff:ff:ff:ff'
rates 	= '\x02\x04\x0b\x16\x0c\x12\x18\x24'
esrates 	= '\x30\x48\x60\x6c'

addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'

broadcom = '\x00\x10\x18\x01\x01\x00'
one = '\x01'
three = '\x01\x02\x03'
five = '\x01\x02\x03\x04\x05'

iec = IEContainer()
iec.addIe("Rates", rates)
iec.addIe("ESRates", esrates)
iec.addIe('EDCA_Parameter_Set', '\x02'*18)
iec.addIe('RCPI', one)
iec.addIe('RSNI', one)
iec.addIe('RMEnabledCap', five)
iec.addIe('RSNinfo', unhexlify("0100000fac020200000fac04000fac020100000fac020000"))
iec.addIe('Mobility_Domain', three)
iec.addIe('FTE', one*82)

iec.addIe('RIC', unhexlify('00000000'))

iec.addIe('DSE_registered_loc', one)
iec.addIe('TimeoutInterval', five)
iec.addIe('HT_Caps', one*26)
iec.addIe('HT_Ops', one*22)
iec.addIe('BSS_Coexist', one)
iec.addIe('Overlap_BSS_Scan_Param', one*14)
iec.addIe('Ext_Caps', one*10)
iec.addIe('BSS_MaxIdle', three)
iec.addIe('TIM_Broadcast_Resp', one)
iec.addIe('FMS_Resp', one)
iec.addIe('DMS_Resp', one)
iec.addIe('QoS_Map', one*16)
iec.addIe('QMF_Policy', one)
iec.addIe('Multiband', one*22)
iec.addIe('DMG_Caps', one*22)
iec.addIe('DMG_Ops', one*10)
iec.addIe('Multi_MAC_Sublayers', one)
iec.addIe('Neighbor_Rep', one*13)
iec.addIe('VHT_Caps', one*12)
iec.addIe('VHT_Ops', five)
iec.addIe('Op_Mode_Notify', one)
iec.addIe('Mult_Ele_ID', '\x0e'*8)
iec.addIe('vendor', broadcom)


p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11ReassoResp()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('reAssocResp.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
