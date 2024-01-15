import pyradamsa
import random
import utils as ut
import os
from scapy.layers.dot11 import *
from mutator import Mutator


class WiFiMutator(Mutator):

    def __init__(self, protocol):
        super(WiFiMutator, self).__init__(protocol)

    def mutate_capabilities_field(self, value):
        pass

    def mutate_listen_interval_field(self, value):
        pass

    def mutate_beacon_interval_field(self, value):
        pass

    def mutate_reason_code_field(self, value):
        pass

    def mutate_timestamp_field(self):
        pass

    def mutate_algo_field(self, value):
        pass

    def mutate_AID_field(self, value):
        pass

    def mutate_seqnum_field(self, value):
        pass

    def mutate_currentAP_field(self, value):
        pass

    def mutate_status_field(self, value):
        pass

    def mutate_Dot11Auth_packet(self, field, value):
        pass

    def return_single_Dot11_packet_mutated(self, packet):
        pass

    def return_single_Dot11_packet_mutated_by_field(self, packet):
        pass


