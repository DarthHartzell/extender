
from scapy.layers.dot11 import (Dot11, Dot11Beacon, RadioTap, Dot11Elt)
from scapy.utils import wrpcap, raw

from ElementContainer import IEContainer
from DotExtended import Dot11Extended

import binascii as ba

broadcast	= 'ff:ff:ff:ff:ff:ff'
rates 	= '\x02\x04\x0b\x16\x0c\x12\x18\x24'
esrates 	= '\x30\x48\x60\x6c'
tim = '\x00\x01\x00\x00'
addr1 = 'aa:bb:cc:dd:ee:ff'
addr2 = '11:22:33:44:55'
addr3 = '66:77:88:99:01'
ssid = 'DarkWeb'
dsset = '\x07' #ba.a2b_hex('{:02x}'.format(7))
iface = 'eth0'
broadcom = '\x00\x10\x18\x01\x01\x00'
one = '\x01'
two = '\x01\x02'
three = '\x01\x02\x03'
four = '\x01\x02\x03\x04'
five = '\x01\x02\x03\x04\x05'
six = '\x01\x02\x03\x04\x05\x06'
seven = '\x01\x02\x03\x04\x05\x06\x07'
msoft = ba.unhexlify('0050f20101000050f20201000050f20201000050f202')


iec = IEContainer()
iec.addIe("SSID", ssid)
iec.addIe("Rates", rates)
iec.addIe("DSset", dsset)
iec.addIe('CFset', six)
iec.addIe('IBSSset', two)
iec.addIe('Country', seven)
iec.addIe('TIM', tim)
iec.addIe("ESRates", esrates)
iec.addIe('Power_Constraint', one)
iec.addIe('Channel_Switch_Announcement', three)
iec.addIe('Quiet', six)
iec.addIe('IBSS_DFS', seven)
iec.addIe('TPC_Report', two)
iec.addIe("ERPinfo", one)
iec.addIe("ESRates", rates)
iec.addIe('RSNinfo', ba.unhexlify("0100000fac020200000fac04000fac020100000fac020000"))
iec.addIe('BSS_Load', five)
iec.addIe('EDCA_Parameter_Set', '\x02'*18)
iec.addIe('QoS Capability', one)
iec.addIe('AP_Chan_Rep', two)
iec.addIe('BSS_Avg_Access_Delay', one)
iec.addIe('Antenna', one)
iec.addIe('BSS_Avail_Admission_Cap', '\x00\x00\x00')
iec.addIe('BSS_AC_Access_Delay_or_WAPI', four)

iec.addIe('Meas_Pilot_Trans', ba.unhexlify('01'))

iec.addIe('Mult_BSSID', one)
iec.addIe('RMEnabledCap', five)
iec.addIe('Mobility_Domain', three)
iec.addIe('DSE_registered_loc', one)
iec.addIe('ExtChSwitchAnnounce', four)
iec.addIe('SupportedOperatingClasses', three)
iec.addIe('HT_Caps', one*26)
iec.addIe('HT_Ops', one*22)
iec.addIe('BSS_Coexist', one)
iec.addIe('Overlap_BSS_Scan_Param', one*14)
iec.addIe('Ext_Caps', one*10)
iec.addIe('FMS_Desc', one)
iec.addIe('QoS_Traffic_Cap', one)
iec.addIe('Time_Advertisement', one*16)
iec.addIe('Interworking', one*9)
iec.addIe('Advertise_Protocol', two)
iec.addIe('Roam_Consort', one*10)
iec.addIe('Emergency_Alert_Id', one)
iec.addIe('Mesh_ID', one)
iec.addIe('Mesh_Config', seven)
iec.addIe('Mesh_Awake_Window', two)
iec.addIe('Beacon_Timing', one)
iec.addIe('MCCAOP_Advertisement_Overview', one)
iec.addIe('MCCAOP_Advertisement', one)
iec.addIe('Mesh_Ch_Switch_Param', six)
iec.addIe('QMF_Policy', one)
iec.addIe('Qload_Report', one)
iec.addIe('HCCA_TXOP_Update_Count', one)
iec.addIe('Multiband', one*22)
iec.addIe('VHT_Caps', one*12)
iec.addIe('VHT_Ops', five)
iec.addIe('Trans_Pwr_Env', five)

de = Dot11Extended(ID='Country', info=seven)
iec.addIe('Chn_Switch_Wrap', raw(de))

iec.addIe('Ext_BSS_Load', six)
iec.addIe('Quiet_Channel', one)
iec.addIe('Op_Mode_Notify', one)
iec.addIe('Reduced_Neighbor_Rpt', one)
iec.addIe('TVHT_Ops', one)
iec.addIe('Mult_Ele_ID', one)

iec.addIe('vendor', broadcom)
iec.addIe('vendor', msoft)

p = RadioTap()/\
Dot11( addr1=addr1 , addr2=addr2 , addr3=broadcast )/\
Dot11Beacon()

ies = iec.getIes()
for ie in ies:
    p.add_payload(ie)
wrpcap('beacon.pcap', p )

# wrpcap('pkt.pcap', p, append=True, )
