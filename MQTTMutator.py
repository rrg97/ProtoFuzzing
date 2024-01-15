import pyradamsa
import random
import utils as ut
import os
from scapy.utils import *
from scapy.contrib.mqtt import *
from scapy.layers.inet import *
from mutator import Mutator
import logging


class MQTTMutator(Mutator):

    def __init__(self, protocol, path_to_valid_pkts, path_to_mut_pkts):
        """

        :param protocol: MQTT
        :param path_to_valid_pkts: Ruta donde se guardan los paquetes válidos.
        :param path_to_mut_pkts: Ruta donde se guardan los paquetes mutados.
        mutate_entire_pkt: Indica si se muta el paquete entero o no.
        """
        super(MQTTMutator, self).__init__(protocol)
        self.path_to_valid_pkts = path_to_valid_pkts
        self.path_to_mut_pkts = path_to_mut_pkts
        self.mutate_entire_pkt = True

    def mutate_fixed_header(self, pkt, is_proxy_fuzzer_call):
        """
        Recibe un paquete y muta la capa Fixed Header.
        Si la llamada es desde el proxy, se imprimen mensajes.
        :param pkt: Paquete a mutar.
        :param is_proxy_fuzzer_call: Indica si se ha llamado desde el ProxyFuzzer.
        :return: Paquete con capa fixed header mutada.
        """
        setattr(pkt['MQTT'], 'type', random.randint(1, 15))

        field_value = getattr(pkt['MQTT'], 'DUP')
        if field_value == 0:
            setattr(pkt['MQTT'], 'DUP', 1)
        else:
            setattr(pkt['MQTT'], 'DUP', 0)

        field_value = getattr(pkt['MQTT'], 'QOS')
        setattr(pkt['MQTT'], 'QOS', self.mutate_QOS_level(field_value))

        field_value = getattr(pkt['MQTT'], 'RETAIN')

        if field_value == 0:
            setattr(pkt['MQTT'], 'RETAIN', 1)
        else:
            setattr(pkt['MQTT'], 'RETAIN', 0)

        del pkt[IP].id
        del pkt[IP].chksum
        del pkt[TCP].chksum
        del pkt[IP].len

        if is_proxy_fuzzer_call:
            print('\n ########## Paquete mutado ##########')
            pkt.show()
        else:
            pkt.__class__(bytes(pkt))
        return pkt

    def mutate_connect_packet(self, random_field, random_field_value, rad):
        """

        :param random_field: Campo a mutar.
        :param random_field_value: Antiguo valor.
        :param rad: Objeto Radamsa.
        :return: Paquete Connect con campo mutado.
        """
        if random_field == 'protoname':
            random_field_value = rad.fuzz(random_field_value, max_mut=1000)
        elif random_field == 'protolevel':
            if random_field_value == 3:
                random_field_value = random.randint(4, 5)
            elif random_field_value == 4:
                random_field_value = random.choice([3, 5])
            else:
                random_field_value = random.choice([3, 4])
        elif random_field == 'usernameflag' or random_field == 'passwordflag' or random_field == 'willretainflag' \
                or random_field == 'cleansess' or random_field == 'willflag' or random_field == 'reserved':
            if random_field_value == 0:
                random_field_value = 1
            else:
                random_field_value = 0
        elif random_field == 'willQOSflag':
            random_field_value = self.mutate_QOS_level(random_field_value)
        elif random_field == 'klive':
            aux = rad.fuzz(random_field_value.to_bytes(2, 'little'), max_mut=2)
            random_field_value = int.from_bytes(aux, 'little')
        elif random_field == 'clientId':
            random_field_value = rad.fuzz(random_field_value, max_mut=1000)

        return random_field_value

    def mutate_publish_packet(self, random_field, random_field_value, rad):
        """
        Retorna un paquete Publish con un campo mutado.
        :param random_field: Campo a mutar.
        :param random_field_value: Valor antiguo.
        :param rad: Objeto Radamsa.
        :return: Paquete con campo mutado.
        """
        if random_field == 'topic':
            random_field_value = rad.fuzz(random_field_value)
        elif random_field == 'msgid':
            random_field_value = self.mutate_msgid_field()
        elif random_field == 'value':
            if random_field_value == '':
                random_field_value = ut.get_random_string(8)
            random_field_value = rad.fuzz(random_field_value, max_mut=1000)

        return random_field_value

    def mutate_subscribe_packet(self, random_field, random_field_value, rad):
        """
        Retorna un paquete Subscribe con un campo mutado.
        :param random_field: Campo a mutar.
        :param random_field_value: Valor antiguo.
        :param rad: Objeto Radamsa.
        :return: Paquete con campo mutado.
        """
        if random_field == 'msgid':
            random_field_value = self.mutate_msgid_field()
        elif random_field == 'topics':
            topics = random_field_value
            for t in topics:
                t.topic = rad.fuzz(t.topic, max_mut=1000)
                t.QOS = self.mutate_QOS_level(t.QOS)
            random_field_value = topics
        return random_field_value

    def mutate_connack_packet(self, random_field, random_field_value, rad):
        """
        Retorna un paquete Connack con un campo mutado.
        :param random_field: Campo a mutar.
        :param random_field_value: Valor antiguo.
        :param rad: Objeto Radamsa.
        :return: Paquete con campo mutado.
        """
        if random_field == 'sessPresentFlag':
            random_field_value = random.randint(0, 255)
        elif random_field == 'retcode':
            if random_field_value == 0:
                random_field_value = random.randint(1, 5)
            elif random_field_value == 1:
                random_field_value = random.choice([0, 2, 3, 4, 5])
            elif random_field_value == 2:
                random_field_value = random.choice([0, 1, 3, 4, 5])
            elif random_field_value == 3:
                random_field_value = random.choice([0, 2, 1, 4, 5])
            elif random_field_value == 4:
                random_field_value = random.choice([0, 2, 3, 1, 5])
            else:
                random_field_value = random.randint(0, 4)

        return random_field_value

    def mutate_msgid_field(self):
        """
        Retorna un valor mutado para el campo msgid.
        :return: Valor random entre 0 y 60000.
        """
        random_field_value = random.randint(0, 60000)

        return random_field_value

    def mutate_QOS_level(self, random_field_value):
        """
        Retorn un valor mutado para el campo QoS.
        :param random_field_value: Valor antiguo.
        :return: Si QoS= 0, 1 ó 2, Si QoS= 1, 0 ó 2, Si QoS= 2, 0 ó 1.
        """
        random_decision = random.randint(0, 1)

        if random_field_value == 0:
            random_field_value = random.randint(1, 2)
        elif random_field_value == 1:
            if random_decision:
                random_field_value = 2
            else:
                random_field_value = 0
        else:
            random_field_value = random.randint(0, 1)

        return random_field_value

    def mutate_suback_packet(self, random_field, random_field_value, rad):
        """
        Retorna un paquete Suback con campo mutado.
        :param random_field: Campo a mutar.
        :param random_field_value: Valor antiguo.
        :param rad: Objeto Radamsa.
        :return: Paquete Suback con campo mutado.
        """
        if random_field == 'msgid':
            random_field_value = self.mutate_msgid_field()
        elif random_field == 'retcode':
            if random_field_value == 128:
                random_field_value = random.choice([0, 1, 2])
            elif random_field_value == 0:
                random_field_value = random.choice([1, 2, 128])
            elif random_field_value == 1:
                random_field_value = random.choice([0, 2, 128])
            elif random_field_value == 2:
                random_field_value = random.choice([0, 1, 128])

        return random_field_value

    def mutate_unsubscribe_packet(self, random_field, random_field_value, rad):
        """
        Retorna un paquete Unsubscribe con campo mutado.
        :param random_field: Campo a mutar.
        :param random_field_value: Valor antiguo.
        :param rad: Objeto Radamsa.
        :return: Paquete Unsubscribe con campo mutado.
        """
        if random_field == 'msgid':
            random_field_value = self.mutate_msgid_field()
        elif random_field == 'topics':
            topics = random_field_value
            for t in topics:
                t.topic = rad.fuzz(t.topic, max_mut=1000)
            random_field_value = topics
        return random_field_value

    def return_single_packet_mutated_by_field(self, packet, field, is_proxy_fuzzer_call):
        """
        Recibe un paquete y un campo específico o None. Si field no es None, se aplica una mutación sobre
        la capa Fixed Header o sobre el campo field.
        Si la llamada es desde el ProxyFuzzer, se imprimen mensajes informativos.
        :param packet: Paquete a mutar.
        :param field: Campo a mutar o None.
        :param is_proxy_fuzzer_call: Indica si se llama desde el ProxyFuzzer.
        :return: Paquete mutado.
        """
        p_type = ut.return_mqtt_int_type_to_str_type(packet['MQTT'].type)
        random_decision = random.randint(0, 1)

        if field is None:
            if random_decision:
                pkt = self.return_single_packet_mutated(packet, is_proxy_fuzzer_call)
                return pkt
            else:
                if is_proxy_fuzzer_call:
                    print('\n Tipo de paquete: {}'.format(p_type))
                    logging.info('\n Tipo de paquete: {}'.format(p_type))
                    logging.info('Realizando mutación sobre fixed header')
                    ut.print_pretty_message('Success', ' Realizando mutación sobre fixed header', False, None)

                pkt = self.mutate_fixed_header(packet, is_proxy_fuzzer_call)
                return pkt

        if random_decision:
            if is_proxy_fuzzer_call:
                print('\n Tipo de paquete: {}'.format(p_type))
                logging.info('\n Tipo de paquete: {}'.format(p_type))
                logging.info('Realizando mutación sobre fixed header')
                ut.print_pretty_message('Success', ' Realizando mutación sobre fixed header', False, None)

            pkt = self.mutate_fixed_header(packet, is_proxy_fuzzer_call)
            return pkt
        else:
            if is_proxy_fuzzer_call:
                print('\n Tipo de paquete: {}'.format(p_type))
                logging.info('\n Tipo de paquete: {}'.format(p_type))
            rad = pyradamsa.Radamsa()

            random_field_value = getattr(packet['MQTT'], field)
            if is_proxy_fuzzer_call:
                logging.info('Realizando mutación sobre el campo {}'.format(field))
                ut.print_pretty_message('Success', ' Realizando mutación sobre el campo {}', True, field)

            if p_type == 'Connect':
                random_field_value_mut = self.mutate_connect_packet(field, random_field_value, rad)
            elif p_type == 'Connack':
                random_field_value_mut = self.mutate_connack_packet(field, random_field_value, rad)
            elif p_type == 'Publish':
                random_field_value_mut = self.mutate_publish_packet(field, random_field_value, rad)
            elif p_type == 'Subscribe':
                random_field_value_mut = self.mutate_subscribe_packet(field, random_field_value, rad)
            elif p_type == 'Puback':
                random_field_value_mut = self.mutate_msgid_field()
            elif p_type == 'Pubrec':
                random_field_value_mut = self.mutate_msgid_field()
            elif p_type == 'Pubcomp':
                random_field_value_mut = self.mutate_msgid_field()
            elif p_type == 'Pubrel':
                random_field_value_mut = self.mutate_msgid_field()
            elif p_type == 'Unsubscribe':
                random_field_value_mut = self.mutate_unsubscribe_packet(field, random_field_value, rad)
            elif p_type == 'Unsuback':
                random_field_value_mut = self.mutate_msgid_field()
            elif p_type == 'Suback':
                random_field_value_mut = self.mutate_suback_packet(field, random_field_value, rad)

            setattr(packet['MQTT'], field, random_field_value_mut)

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
        """
        Muta los paquetes que están en la carpeta paquetes_validos y los guarda
        en paquetes_mutados.
        """
        if not os.path.exists(self.path_to_mut_pkts):
            os.mkdir(self.path_to_mut_pkts)

        field_packets_dictionary = ut.get_packet_field_dict(self.protocol)
        for p_type in ut.LIST_OF_MQTT_PACKET_TYPES:

            if os.path.exists(os.path.join(self.path_to_valid_pkts, p_type)):
                if not os.path.exists(os.path.join(self.path_to_mut_pkts, p_type)):
                    os.mkdir(os.path.join(self.path_to_mut_pkts, p_type))

                ut.print_pretty_message('Success', ' Generando los paquetes mutados del tipo {}', True, p_type)
                i = 0
                path_to_iterate = os.path.join(self.path_to_valid_pkts, p_type)
                for filename in os.listdir(path_to_iterate):
                    file_to_mutate = rdpcap(os.path.join(path_to_iterate, filename))
                    if p_type not in ut.MQTT_DICT_FOR_MUTATE_SPEFICIC_FIELD.keys():
                        self.mutate_entire_packet(file_to_mutate[0], i, os.path.join(self.path_to_mut_pkts, p_type))
                    else:
                        if self.mutate_entire_pkt:
                            self.mutate_entire_packet(file_to_mutate[0], i,
                                                      os.path.join(self.path_to_mut_pkts, p_type))
                            self.mutate_entire_pkt = False
                        else:
                            field_to_mut = field_packets_dictionary[p_type].pop(0)
                            field_packets_dictionary[p_type].append(field_to_mut)

                            self.mutate_MQTT_packet_by_specific_field(file_to_mutate[0], i,
                                                                      os.path.join(self.path_to_mut_pkts, p_type),
                                                                      field_to_mut)
                            self.mutate_entire_pkt = True
                    i += 1
            else:
                print("\n")
                ut.print_pretty_message('Warning', ' No hay paquetes válidos del tipo {}', True, p_type)

        print("\n")
        ut.print_pretty_message('Success', ' Se han mutado {} paquetes MQTT', True, self.num_of_pkts_mutated)

    def mutate_MQTT_packet_by_specific_field(self, file_to_mut, j, path_to_save, field_to_mut):
        """
        Muta el paquete por el campo field_to_mut si no es None y luego lo guarda.
        :param file_to_mut: Paquete a mutar.
        :param j: Número de paquete.
        :param path_to_save: Ruta donde se guardará.
        :param field_to_mut: Campo a mutar o None.
        """
        try:
            packet_to_save = self.return_single_packet_mutated_by_field(file_to_mut[0], field_to_mut, False)
            self.save_mutated_packet(path_to_save, packet_to_save, j)
        except Exception as e:
            print(e)

'''def test():
    mut = MQTTMutator('MQTT', os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'MQTT'),
                      os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, 'MQTT'))
    mut.mutate_MQTT_packets()


test()'''
