

from scapy.layers.dot11 import Dot11Elt

from DotExtended import Dot11Extended

class IEContainer():

    def __init__(self):
        self.ies = []

    def addIe(self, id, val):
        try:
            Dot11Elt.fields_desc[0].s2i[id]
            self.ies.append(Dot11Elt(ID=id, info=val))
        except:
            self.ies.append(Dot11Extended(ID=id, info = val))

    def getIes(self):
        return self.ies
