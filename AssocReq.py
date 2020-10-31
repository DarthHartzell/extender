
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11AssoReq)
from scapy.utils import wrpcap

from ElementContainer import IEContainer
import binascii as ba

def build_containers():

    rates   = '\x02\x04\x0b\x16\x0c\x12\x18\x24'
    esrates = '\x30\x48\x60\x6c'

    # addr1 = 'aa:bb:cc:dd:ee:ff'
    # addr2 = '11:22:33:44:55'
    # broadcast = 'ff:ff:ff:ff:ff:ff'
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
    iec.addIe('RSNinfo', ba.unhexlify("0100000fac020200000fac04000fac020100000fac020000"))
    iec.addIe('QoS Capability', one)
    iec.addIe('RMEnabledCap', five)
    iec.addIe('Mobility_Domain', three)
    iec.addIe('SupportedOperatingClasses', three)
    iec.addIe('HT_Caps', one*26)
    iec.addIe('BSS_Coexist', one)
    iec.addIe('Ext_Caps', one*10)
    iec.addIe('QoS_Traffic_Cap', one)
    iec.addIe('TIM_Broadcast_Req', one)
    iec.addIe('Interworking', one*9)
    iec.addIe('Multiband', one*22)
    iec.addIe('DMG_Caps', one*22)
    iec.addIe('Multi_MAC_Sublayers', one)
    iec.addIe('VHT_Caps', one*12)
    iec.addIe('Op_Mode_Notify', five)
    iec.addIe('vendor', broadcom)

def build_pcap( a1, a2, a3, tag ):
    p = RadioTap()/\
    Dot11( addr1=a1 , addr2=a2 , addr3=a3 )/\
    Dot11AssoReq()
    iec = IEContainer()
    ies = iec.getIes()
    for ie in ies:
        p.add_payload(ie)
    wrpcap('assocReq.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
def build_assoc_req( a1, a2, a3, tag, info ):
    print(a1 + a2 + a3 + tag + info)
    return
