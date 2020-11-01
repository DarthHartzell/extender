
import argparse
import sys
from scapy.layers.dot11 import (Dot11, RadioTap, Dot11AssoReq, Dot11AssoResp)
from scapy.layers.dot11 import Dot11Auth, Dot11Beacon, Dot11Deauth
from scapy.layers.dot11 import Dot11Disas, Dot11ProbeReq, Dot11ProbeResp
from scapy.layers.dot11 import Dot11ReassoReq, Dot11ReassoResp, Dot11Elt
from binascii import unhexlify, hexlify
from DotExtended import Dot11_extended_ids, Dot11Elt_fields, Dot11Extended
from scapy.utils import raw, wrpcap


a1 = 'aa:bb:cc:dd:ee:ff'
a2 = '11:22:33:44:55'
bcast = 'ff:ff:ff:ff:ff:ff'

def getDefaultValue(tag):
    if tag == 0:
        return 'DarkSide'
    elif tag == 1:
        return unhexlify('02040b160c121824')
    elif tag == 3:
        return unhexlify('07')
    elif tag == 4:
        return unhexlify('00'*6)
    elif tag == 5:
        return unhexlify('00010000')
    elif tag == 6:
        return unhexlify('00'*2)
    elif tag == 7:
        return unhexlify('00'*7)
    elif tag == 11:
        return unhexlify('00'*5)
    elif tag == 12:
        return unhexlify('00'*18)
    elif tag == 15:
        return unhexlify('00'*14)
    elif tag == 33:
        return unhexlify('00'*2)
    elif tag == 35:
        return unhexlify('00'*2)
    elif tag == 36:
        return unhexlify('00'*4)
    elif tag == 37:
        return unhexlify('00'*3)
    elif tag == 40:
        return unhexlify('00'*6)
    elif tag == 41:
        return unhexlify('00'*7)
    elif tag == 45:
        return unhexlify('00'*26)
    elif tag == 48:
        return unhexlify('0100000fac020200000fac04000fac020100000fac020000')
    elif tag == 50:
        return unhexlify('3048606c')
    elif tag == 51:
        return unhexlify('00'*2)
    elif tag == 52:
        return unhexlify('00'*13)
    elif tag == 54:
        return unhexlify('00'*3)
    elif tag == 55:
        return unhexlify('00'*82)
    elif tag == 56:
        return unhexlify('00'*5)
    elif tag == 57:
        return unhexlify('00'*4)
    elif tag == 59:
        return unhexlify('00'*3)
    elif tag == 60:
        return unhexlify('00'*4)
    elif tag == 61:
        return unhexlify('00'*22)
    elif tag == 67:
        return unhexlify('00'*3)
    elif tag == 68:
        return unhexlify('00'*4)
    elif tag == 69:
        return unhexlify('00'*16)
    elif tag == 70:
        return unhexlify('00'*5)
    elif tag == 74:
        return unhexlify('00'*14)
    elif tag == 75:
        return unhexlify('00'*3)
    elif tag == 76:
        return unhexlify('00'*16)
    elif tag == 84:
        return unhexlify('000161')
    elif tag == 90:
        return unhexlify('00'*3)
    elif tag == 101:
        return unhexlify('00'*17)
    elif tag == 104:
        return unhexlify('00'*4)
    elif tag == 108:
        return unhexlify('00'*2)
    elif tag == 110:
        return unhexlify('00'*16)
    elif tag == 111:
        return unhexlify('00'*10)
    elif tag == 113:
        return unhexlify('00'*7)
    elif tag == 118:
        return unhexlify('00'*6)
    elif tag == 119:
        return unhexlify('00'*2)
    elif tag == 127:
        return unhexlify('00'*10)
    elif tag == 148:
        return unhexlify('00'*17)
    elif tag == 151:
        return unhexlify('00'*10)
    elif tag == 152:
        return unhexlify('00'*7)
    elif tag == 158:
        return unhexlify('00'*22)
    elif tag == 164:
        return unhexlify('00'*13)
    elif tag == 168:
        return unhexlify('00'*8)
    elif tag == 190:
        return unhexlify('00'*4)
    elif tag == 191:
        return unhexlify('00'*12)
    elif tag == 192:
        return unhexlify('00'*5)
    elif tag == 193:
        return unhexlify('00'*6)
    elif tag == 194:
        return unhexlify('00'*3)
    elif tag == 195:
        return unhexlify('00'*2)
    elif tag == 221:
        return unhexlify('00'*3)
    else:
        return unhexlify('00')

def getInformationElement( tag, info ):
    p = None
    if info == None:
        info = getDefaultValue(tag)
    else:
        info = unhexlify(info)
    if tag >= 0 and tag <= 6:
        p = Dot11Elt(ID=Dot11Elt_fields[tag], info=info)
    elif tag == 16 or tag == 42 or tag == 46 or tag == 47:
        p = Dot11Elt(ID=Dot11Elt_fields[tag], info=info)
    elif tag == 48 or tag == 50 or tag == 68 or tag == 221:
        p = Dot11Elt(ID=Dot11Elt_fields[tag], info=info)
    else:
        p = Dot11Extended(ID=Dot11_extended_ids[tag], info=info)
    return p

types = ['assoc_req', 'assoc_resp',
         'auth', 'de_auth',
         'beacon', 'dis_assoc',
         'probe_req', 'probe_resp',
         're_assoc_req', 're_assoc_resp']

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("type", help="the type of packet to generate")
    parser.add_argument('IEtag', help='the IE to put in the packet, should be an int', type=int)
    parser.add_argument('--value', help='the value field for the IE, if blank, default value used')
    args = parser.parse_args()

    if args.type not in types:
        print('invalid type, valid types are:')
        for t in types:
            print(t)
        sys.exit()
    print('all OK')
    p = RadioTap()/\
    Dot11( addr1=a1 , addr2=a2 , addr3=bcast )

    if args.type == 'assoc_req':
        p.add_payload(Dot11AssoReq())
    elif args.type == 'assoc_resp':
        p.add_payload(Dot11AssoResp())
    elif args.type == 'auth':
        p.add_payload(Dot11Auth())
    elif args.type == 'beacon':
        p.add_payload(Dot11Beacon())
    elif args.type == 'de_auth':
        p.add_payload(Dot11Deauth())
    elif args.type == 'dis_assoc':
        p.add_payload( Dot11Disas() )
    elif args.type == 'probe_req':
        p.add_payload(Dot11ProbeReq())
    elif args.type == 'probe_resp':
        p.add_payload(Dot11ProbeResp())
    elif args.type == 're_assoc_req':
        p.add_payload(Dot11ReassoReq())
    elif args.type == 're_assoc_resp':
        p.add_payload(Dot11ReassoResp())
    p.add_payload(getInformationElement(args.IEtag, args.value))
    print(hexlify(raw(p)))
    wrpcap('beacon.pcap', p )
