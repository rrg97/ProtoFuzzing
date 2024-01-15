import pyradamsa
import random
import utils as ut
import os
from mutator import Mutator
from scapy2dict import to_dict
from scapy.utils import *
from scapy.layers.http import *
from scapy.layers.inet import TCP, IP
import logging


class HTTPMutator(Mutator):

    def __init__(self, protocol, path_to_valid_pkts, path_to_mut_pkts):
        super(HTTPMutator, self).__init__(protocol)
        self.path_to_valid_pkts = path_to_valid_pkts
        self.path_to_mut_pkts = path_to_mut_pkts
        self.mutate_entire_pkt = True

    def mutate_field(self, value, rad):
        if value is None:
            value = bytes(ut.get_random_string(10), encoding='utf-8')
        new_value = rad.fuzz(value, max_mut=10000)

        return new_value

    def return_single_packet_mutated_by_field(self, packet, field, is_proxy_fuzzer_call):
        rad = pyradamsa.Radamsa()
        if is_proxy_fuzzer_call:
            if packet.haslayer(HTTPRequest):
                method = str(packet['HTTP Request'].Method)[2:-1]
                print('\n Tipo de paquete: HTTPRequest')
                logging.info('\n Tipo de paquete: HTTPRequest')
                print('\n Método: {}'.format(method))
                logging.info('\n Método: {}'.format(method))
            else:
                print('\n Tipo de paquete: HTTPResponse')
                logging.info('\n Tipo de paquete: HTTPResponse')
            logging.info('\n Realizando mutación sobre el campo {}'.format(field))
            ut.print_pretty_message('Success', ' Realizando mutación sobre el campo {}', True, field)

        value = getattr(packet['HTTP'], field)
        random_field_value_mut = self.mutate_field(value, rad)
        setattr(packet['HTTP'], field, random_field_value_mut)

        del packet[IP].id
        del packet[IP].chksum
        del packet[TCP].chksum
        del packet[IP].len

        if is_proxy_fuzzer_call:
            print('\n ########## Paquete mutado ##########')
            packet.show()
        else:
            packet.__class__(bytes(packet))

        return packet

    def mutate_packets(self):

        if os.path.exists(self.path_to_valid_pkts):
            if not os.path.exists(self.path_to_mut_pkts):
                os.mkdir(self.path_to_mut_pkts)

            for item in ['HTTPRequest', 'HTTPResponse']:
                i = 0
                field_packets_dictionary = ut.get_packet_field_dict(self.protocol)
                if item == 'HTTPRequest':
                    for method in ut.LIST_OF_HTTP_METHODS:
                        if os.path.exists(os.path.join(self.path_to_valid_pkts, item, method)):
                            if not os.path.exists(os.path.join(self.path_to_mut_pkts, item, method)):
                                os.makedirs(os.path.join(self.path_to_mut_pkts, item, method))
                            ut.print_pretty_message('Success', ' Generando los paquetes mutados HTTP del método {} ...',
                                                    True, method)
                            path_to_iterate = os.path.join(self.path_to_valid_pkts, item, method)
                            for filename in os.listdir(path_to_iterate):
                                file_to_mutate = rdpcap(os.path.join(path_to_iterate, filename))
                                if self.mutate_entire_pkt:
                                    self.mutate_entire_packet(file_to_mutate[0], i,
                                                              os.path.join(self.path_to_mut_pkts, item, method))
                                    self.mutate_entire_pkt = False
                                else:
                                    pkt_dict = to_dict(file_to_mutate[0]['HTTPRequest'], strict=True)
                                    field_to_mut = field_packets_dictionary[item].pop(0)
                                    while 1:
                                        field_packets_dictionary[item].append(field_to_mut)
                                        if field_to_mut in pkt_dict['HTTP Request']:
                                            break
                                        field_to_mut = field_packets_dictionary[item].pop(0)

                                    self.mutate_HTTP_packet_by_specific_field(file_to_mutate[0], i,
                                                                              os.path.join(self.path_to_mut_pkts,
                                                                                           item, method), field_to_mut)
                                    self.mutate_entire_pkt = True
                            i += 1
                else:
                    if not os.path.exists(os.path.join(self.path_to_mut_pkts, item)):
                        os.makedirs(os.path.join(self.path_to_mut_pkts, item))
                    path_to_iterate = os.path.join(self.path_to_valid_pkts, item)
                    for filename in os.listdir(path_to_iterate):
                        file_to_mutate = rdpcap(os.path.join(path_to_iterate, filename))
                        if self.mutate_entire_pkt:
                            self.mutate_entire_packet(file_to_mutate[0], i,
                                                      os.path.join(self.path_to_mut_pkts, item))
                            self.mutate_entire_pkt = False
                        else:
                            pkt_dict = to_dict(file_to_mutate[0]['HTTPResponse'], strict=True)
                            field_to_mut = field_packets_dictionary[item].pop(0)
                            while 1:
                                field_packets_dictionary[item].append(field_to_mut)
                                if field_to_mut in pkt_dict['HTTP Response']:
                                    break
                                field_to_mut = field_packets_dictionary[item].pop(0)
                            self.mutate_HTTP_packet_by_specific_field(file_to_mutate[0], i,
                                                                      os.path.join(self.path_to_mut_pkts, item),
                                                                      field_to_mut)
                            self.mutate_entire_pkt = True
                        i += 1
        else:
            print("\n")
            ut.print_pretty_message('Warning', ' No hay paquetes válidos del protocolo {}', True, self.protocol)

    def mutate_HTTP_packet_by_specific_field(self, file_to_mut, j, path_to_save, field_to_mut):
        try:
            packet_to_save = self.return_single_packet_mutated_by_field(file_to_mut[0], field_to_mut, False)
            self.save_mutated_packet(path_to_save, packet_to_save, j)
        except Exception as e:
            print(e)

'''def test():
    http_mut = HTTPMutator('HTTP', os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP'),
                      os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, 'HTTP'))
    http_mut.mutate_packets()

test()'''