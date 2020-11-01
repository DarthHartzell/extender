from scapy.all import Packet
from scapy.all import ByteEnumField
from scapy.all import FieldLenField
from scapy.all import StrLenField
from scapy.layers.dot11 import Dot11
from scapy.compat import orb, chb
from scapy.layers.dot11 import Dot11Elt
from scapy.utils import issubtype

Dot11Elt_fields = {
    0:"SSID", # max ssid == 32
    1:"Rates", # len >= 1
    2: "FHset", 
    3:"DSset", # len == 1
    4:"CFset", # len == 6
    5:"TIM", # len >= 4
    6:"IBSSset", # len == 2
    16:"challenge", # len > 0
    42:"ERPinfo", # len == 1
    46:"QoS Capability", # len == 1
    47:"ERPinfo", # len == 1
    48:"RSNinfo", # len >= 2, but 18 really...
    50:"ESRates", # len > 0
    221:"vendor", # len > 3
    68:"reserved"
}

Dot11_extended_ids = {
    7:"Country", # len >= 6 ## (sub-element to 196)
    8:"Reserved_8",
    9:"Reserved_9",
    10:"Request", # len > 0
    11:"BSS_Load", # len == 4 || len == 5
    12:"EDCA_Parameter_Set", # len == 18
    15:"Schedule", # len == 14 # not sure which message contains
    32:"Power_Constraint", # len == 1
    33:"Pwr_Caps", # len == 2
    35:"TPC_Report", # len == 2
    36:"Supported_Channels", # len % 2 == 0 (even)
    37:"Channel_Switch_Announcement", # len == 3
    40:"Quiet", # len == 6
    41:"IBSS_DFS", # len >= 7
    45:"HT_Caps", # len == 26
    51:"AP_Chan_Rep", # len > 1
    52:"Neighbor_Rep", # len >= 13
    53:"RCPI", # len == 1
    54:"Mobility_Domain", # len >= 3
    55:"FTE", # len >= 82
    56:"TimeoutInterval", # len >= 5
    # RIC is a container of containers
    57:"RIC", # len if RIC data == 4
    58:"DSE_registered_loc", # no wireshark dissector
    59:"SupportedOperatingClasses", # len >= 2 and len <= 255
    60:"ExtChSwitchAnnounce", # len == 4
    61:"HT_Ops", # len >= 22
    63:"BSS_Avg_Access_Delay", # len == 1
    64:"Antenna", # len == 1
    65:"RSNI", # len == 1
    # tag 66 could have (vendor specific) sub-elements
    # wireshark code has TODO: tag to fix parser in case
    # of sub-elements
    66:"Meas_Pilot_Trans", # len?
    # tag:67  Element ID | Length | Capacity Bitmask | Capacity List
    # length  1            1         2                (2*total # non-zero bits in prev field)
    67:"BSS_Avail_Admission_Cap", # len >= 2
    68:"BSS_AC_Access_Delay_or_WAPI", # len == 4 or len >= 20
    69:"Time_Advertisement", # len >= 16
    70:"RMEnabledCap", # len == 5
    71:"Mult_BSSID", # len >= 1
    72:"BSS_Coexist", # len == 1
    74:"Overlap_BSS_Scan_Param", # len == 14
    75:"RIC_Descriptor", # len >= 1
    76:"Management_MIC", # len >= 16
    84:"SSID_List", # list of tlv ssid(s)
    86:"FMS_Desc", # no wireshark dissector
    87:"FMS_Req", # no wireshark dissector
    88:"FMS_Resp", # no wireshark dissector
    89:"QoS_Traffic_Cap", # no wireshark dissector
    90:"BSS_MaxIdle", # len == 3
    94:"TIM_Broadcast_Req", # no wireshark dissector
    95:"TIM_Broadcast_Resp", # no wireshark dissector
    97:"Channel_Usage", # no wireshark dissector
    98:"Time_Zone", # len > 0
    99:"DMS_Req", # no wireshark dissector
    100:"DMS_Resp", # no wireshark dissector
    101:"Link_ID", # len >= 17 # has to do with TDLS but not sure which message
    104:"ChSwitch_Timing", # len >= 4 # not sure which message
    107:"Interworking", # len == 3 || len == 9 || len == 7 || len == 1
    108:"Advertise_Protocol", # various lengths valid
    110:"QoS_Map", # len >= 16 && even len
    111:"Roam_Consort", # various lengths valid
    112:"Emergency_Alert_Id", # no wireshark dissector
    113:"Mesh_Config", # len == 7
    114:"Mesh_ID", # len > 0
    118:"Mesh_Ch_Switch_Param", # len == 6
    119:"Mesh_Awake_Window", # len == 2
    120:"Beacon_Timing", # no wireshark dissector
    123:"MCCAOP_Advertisement", # no wireshark dissector
    127:"Ext_Caps", # len > 0
    136:"Res_136",
    # DMC_Caps len used to be 17, after 2016 became 22
    148:"DMG_Caps", # len >= 22
    151:"DMG_Ops", # len == 10
    152:"DMG_BSS_Param_Change", # len == 7 # not sure which message
    155:"Res_155",
    156:"Res_156",
    158:"Multiband", # len >= 22
    160:"Rext_PCP_List", # len >= 1 # not sure which message
    164:"Sess_Trans", # no wireshark dissector ### not sure which message # len >= 13 ??
    167:"Relay_Caps", # len >= 2
    168:"Relay_Trans_Param_Set", # len == 8 ### not sure which message
    170:"Multi_MAC_Sublayers", # no wireshark dissector
    174:"MCCAOP_Advertisement_Overview", # no wireshark dissector
    176:"Res_176",
    181:"QMF_Policy", # no wireshark dissector
    186:"Qload_Report", # no wireshark dissector
    187:"HCCA_TXOP_Update_Count", # no wireshark dissector
    190:"Ant_Sec_ID_Pattern", # len == 4
    191:"VHT_Caps", # len == 12
    192:"VHT_Ops", # len == 5
    193:"Ext_BSS_Load", # len == 6
    194:"Wide_Band_Chan_Switch", # len == 3 ## (sub-element to 196)
    195:"Trans_Pwr_Env", # len >= 2 and len <= 5 ## (sub-element to 196)
    # three subelement in IE-196(Channel Switch Wrapper element):
    #    (1) New Country subelement
    #    (2) Wide Bandwidth Channel Switch subelement
    #    (3) New VHT Transmit Power Envelope subelement
    196:"Chn_Switch_Wrap", # len > 0, sub elements must parse see above
    198:"Quiet_Channel", # no wireshark dissector
    199:"Op_Mode_Notify", # len > 0 or possibly len == 1
    201:"Reduced_Neighbor_Rpt", # no wireshark dissector
    202:"TVHT_Ops", # no wireshark dissector
    210:"Res_210",
    216:"Res_216",
    217:"Res_217",
    240:"Res_240",
    # 255 is overloaded, parsed differently based
    # upon various factors such as length
    # switch on value after the length values
    # [4, 8, 13, 11, 14, 32, 33, 35, 36, 37, 38, 39, 41, 42, 43, 44, 92, 93, 10]
    255:"Mult_Ele_ID" # len >= 1 
}

class Dot11Extended(Packet):
    __slots__ = ['info']
    name = 'IE extended'
    fields_desc = [ByteEnumField( "ID", 0, Dot11_extended_ids ),
                   FieldLenField('len', None, 'info', "B"),
                   StrLenField("info", "", length_from=lambda x: x.len)]
    show_indent = 0

    def mysummary(self):
        if self.ID == 0:
            ssid = repr(self.info)
            if ssid[:2] in ['b"', "b'"]:
                ssid = ssid[1:]
            return "SSID=%s" % ssid, [Dot11]
        else:
            return ""

    registered_ies = {}

    @classmethod
    def register_variant(cls):
        cls.registered_ies[cls.ID.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            _id = orb(_pkt[0])
            return cls.registered_ies.get(_id, cls)
        return cls

    def haslayer(self, cls):
        if cls == "Dot11Extended":
            if isinstance(self, Dot11Extended):
                return True
        elif issubtype(cls, Dot11Extended):
            if isinstance(self, cls):
                return True
        return super(Dot11Extended, self).haslayer(cls)

    def getlayer(self, cls, nb=1, _track=None, _subclass=True, **flt):
        return super(Dot11Extended, self).getlayer(cls, nb=nb, _track=_track,
                                              _subclass=True, **flt)

    def pre_dissect(self, s):
        # Backward compatibility: add info to all elements
        # This allows to introduce new Dot11Extended classes without breaking
        # previous code
        if len(s) >= 3:
            length = orb(s[1])
            if length > 0 and length <= 255:
                self.info = s[2:2 + length]
        return s

    def post_build(self, p, pay):
        if self.len is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay
