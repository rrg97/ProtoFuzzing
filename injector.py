import shutil
import scapy.contrib.mqtt as mqtt

import utils as ut
import os
from scapy.utils import *
import socket
import random
import logging
import itertools
import tempfile
import time


class Injector:

    def __init__(self, protocol, host, port):
        """
        :param protocol: Protocolo objetivo.
        :param host: Equipo destino.
        :param port: Puerto destino.
        number_of_pkts_sent: Total de paquetes mutados enviados.
        s: socket.
        fuzz_packets_iter: iterable con los paquetes mutados.
        fuzz_packets: lista para construir el iterable de paquetes mutados.
        valid_cases_iter: iterable con los paquetes mutados.
        valid_cases: lista para construir el iterable de los paquetes mutados.
        """
        self.protocol = protocol
        self.host = host
        self.port = port
        self.number_of_pkts_sent = 0
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.fuzz_packets_iter = {}
        self.fuzz_packets = {}
        self.valid_cases_iter = {}
        self.valid_cases = {}

    def generate_new_mut_pkts_from_existing(self, path, p_type):
        """
        Recibe un path y genera los paquetes mutados partiendo de los paquetes válidos.
        Retorna la nueva lista de paquetes para formar el iterable.
        :param path: Ruta que apunta a los paquetes válidos.
        :param p_type: Tipo de paquete.
        :return: Lista con los nuevos paquetes mutados.
        """
        temp_fuzz_dir = tempfile.mkdtemp()
        mut_class = ut.get_class_from_string(self.protocol + 'Mutator' + '.' + self.protocol + 'Mutator')
        mut = mut_class(self.protocol, None, None)

        ut.print_pretty_message('Success', ' Generando 500 nuevos paquetes mutados ...', False)
        fuzz_list = []
        i = 0
        field_packets_dictionary = ut.get_packet_field_dict(self.protocol)
        field_to_mut = None

        while i < 500:
            for filename in os.listdir(path):
                file_to_mutate = rdpcap(os.path.join(path, filename))
                if random.randint(0, 1):
                    packet = mut.return_single_packet_mutated(file_to_mutate[0], False)
                else:
                    if self.protocol == 'MQTT':
                        if p_type != 'Disconnect':
                            field_to_mut = field_packets_dictionary[p_type].pop(0)
                            field_packets_dictionary[p_type].append(field_to_mut)
                    packet = mut.return_single_packet_mutated_by_field(file_to_mutate[0], field_to_mut, False)

                pname = "pcapfuzz%d" % i + ".pcap"
                wrpcap(os.path.join(temp_fuzz_dir, pname), packet)
                i += 1

        for file in os.listdir(temp_fuzz_dir):
            fuzz_list.append(rdpcap(os.path.join(temp_fuzz_dir, file)))
        shutil.rmtree(temp_fuzz_dir)

        return fuzz_list

    def Recv(self, buffer):
        """
        Recibe los datos del socket.
        :param buffer: Buffer para almacenar los bytes.
        :return: Datos recibidos.
        """
        while True:
            buf = self.s.recv(1024)
            if len(buf) == 0:
                self.s.close()
                ut.print_pretty_message('Warning', ' Conexión cerrada.', False, None)
                self.connect_to_server()
            buffer.extend(buf)
            try:
                p = buffer
                return p
            except socket.error as e:
                print(e)
                continue

    def is_socket_closed(self):
        """
        Retorna True si el socket está cerrado.
        :return: True si cerrado o False si abierto.
        """
        try:
            # this will try to read bytes without blocking and also without removing them from buffer (peek only)
            data = self.s.recv(1024)
            if len(data) == 0:
                return True
        except socket.error as e:
            return True  # socket was closed for some other reason
        except Exception as e:
            print(e)
            return False
        return False

    def get_next_fuzzed_packet(self, path_mut, path_valid, p_type):
        """
        Retorna el siguiente paquete mutado del iterable.
        :param path: Ruta.
        :param p_type: Tipo de paquete.
        :return: Paquete mutado.
        """
        try:
            return next(self.fuzz_packets_iter[path_mut])
        except KeyError:
            if os.path.isdir(path_mut) is False:
                raise IOError('El path que se ha pasado no es válido')
        except StopIteration:
            self.s.close()
            self.fuzz_packets[path_mut] = self.generate_new_mut_pkts_from_existing(path_valid, p_type)
            self.fuzz_packets_iter[path_mut] = iter(self.fuzz_packets[path_mut])
            self.connect_to_server()
            return next(self.fuzz_packets_iter[path_mut])

    def get_valid_packet(self, path):
        """
        Retorna el siguiente paquete válido del iterable.
        :param path: Ruta.
        :return: Paquete válido.
        """
        try:
            return next(self.valid_cases_iter[path])
        except (StopIteration, KeyError):
            if os.path.isdir(path) is False:
                raise IOError('El path que se ha pasado no es válido')

    def connect_to_server(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(2.0)
        self.s.connect((self.host, self.port))

        print('\n')
        ut.print_pretty_message('Success', ' Conectado al servidor {} en el puerto {} ({})', True, self.host,
                                self.port,
                                time.strftime("%a, %d %b %Y %H:%M:%S"))
        logging.info('Conectado al servidor {} en el puerto {}'.format(self.host, self.port))

    def send_fuzzed_packets(self):
        """
        Envía paquetes al equipo host en el puerto port.
        """
        try:
            while 1:
                random_file = random.choice(os.listdir(os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, self.protocol)))
                packet_to_send = rdpcap(
                    os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, self.protocol, random_file))

                print('\n Paquete mutado -> {}'.format(packet_to_send[0]))
                logging.info('Paquete mutado -> {}'.format(packet_to_send[0]))
                try:
                    print('\n')
                    ut.print_pretty_message('Success', ' Enviando paquete mutado... ({})', True,
                                            time.strftime("%a, %d %b %Y %H:%M:%S"))
                    logging.info('Enviando paquete mutado')
                    self.s.send(bytes(packet_to_send[0]))
                    self.number_of_pkts_sent += 1

                    print('\n')
                    ut.print_pretty_message('Success', ' Recibiendo datos del broker ... ({})', True,
                                            time.strftime("%a, %d %b %Y %H:%M:%S"))
                    logging.info('Recibiendo datos del bróker ...')
                    self.Recv(bytearray())

                except socket.error as e:
                    if self.s._closed:
                        print("\n")
                        ut.print_pretty_message('Warning', ' La conexión se perdió. Reconectando ...', False, None)
                        logging.warning('La conexión se perdió. Reconectando ...')
                        self.connect_to_server()
                        continue
        except KeyboardInterrupt:
            print('\n')
            ut.print_pretty_message('Success', ' Parando el envío de paquetes mutados ... ({})', True,
                                    time.strftime("%a, %d %b %Y %H:%M:%S"))
            logging.info('Parando el envío de paquetes mutados ...')
            self.s.close()
            time.sleep(1)

    def run(self):
        """
        Ejecuta la inyección de paquetes.
        """
        connected = False
        repeat_process = True
        conn_tries = 0

        while repeat_process:
            response = ''

            while not connected:
                try:
                    self.connect_to_server()
                    connected = True

                    print('\n')
                    ut.print_pretty_message('Success', ' Conectado al servidor {} en el puerto {} ({})', True,
                                            self.host, self.port, time.strftime("%a, %d %b %Y %H:%M:%S"))
                    self.send_fuzzed_packets()
                except socket.error as e:
                    connected = False
                    conn_tries += 1
                    print("\n")
                    ut.print_pretty_message('Warning', ' Se produjo un error en el socket -> {}', True, e)
                    if (conn_tries < 50):
                        print('\n [+] Intentando conectar de nuevo...')
                        continue
                    else:
                        print("\n")
                        ut.print_pretty_message('Warning', ' Se han realizado 50 intentos de conexión sin éxito.',
                                                False, None)
                        break
                except Exception as e:
                    print("\n")
                    ut.print_pretty_message('Warning', ' Algo no fue bien. Excepción -> {}', True, e)
                    print("\n")
                    ut.print_pretty_message('Success', ' Intentando conectar de nuevo con el servidor ...', False, None)
                    continue

            while not (response == 'S' or response == 'N' or response == 's' or response == 'n'):
                response = input('\n ¿Desea volver a comenzar el envío de paquetes? (S/N):')
            repeat_process = (response == 'S' or response == 's')
