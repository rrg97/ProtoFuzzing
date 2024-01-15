import itertools
import time
import utils as ut
from scapy.layers.http import *
from scapy.utils import rdpcap
from injector import Injector
import errno
import logging
import os


class HTTPInjector(Injector):

    def __init__(self, protocol, host, port):
        super(HTTPInjector, self).__init__(protocol, host, port)
        self.session_structures = [
            ['GET'],
            ['GET', 'POST'],
            ['POST', 'PUT'],
            ['DELETE', 'PUT', 'POST', 'GET'],
            ['POST', 'PUT', 'HEAD', 'OPTIONS', 'DELETE'],
            ['HEAD'],
            ['DELETE'],
            ['OPTIONS', 'PUT']
        ]
        self.session = itertools.cycle(iter(self.session_structures))
        self.current_session = iter(self.session.__next__())
        self.protocol = 'HTTP'
        self.send_mutated_packet = True

    def fill_buffers(self):
        """
        Llena las estructuras iterables de la clase padre Injector con los paquetes
        de las carpetas paquetes_validos y paquetes_mutados
        """
        for method in ut.LIST_OF_HTTP_METHODS:
            path = os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, self.protocol, 'HTTPRequest', method)
            self.valid_cases[path] = []
            for filename in os.listdir(path):
                self.valid_cases[path].append(rdpcap(os.path.join(path, filename)))
            self.valid_cases_iter[path] = itertools.cycle(iter(self.valid_cases[path]))

            path = os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, self.protocol, 'HTTPRequest', method)
            self.fuzz_packets[path] = []
            for filename in os.listdir(path):
                self.fuzz_packets[path].append(rdpcap(os.path.join(path, filename)))
            self.fuzz_packets_iter[path] = \
                iter(self.fuzz_packets[path])

    def send_pkt(self, method):
        """
        Envía un paquete mutado o sin mutar y recibe los datos del equipo destino.
        Si no quedan paquetes en el iterable de paquetes mutados, se generan nuevos paquetes.
        :param method: tipo de método HTTP en str
        """
        try:
            print('\n Método: {}'.format(method))
            if self.send_mutated_packet:
                packet_to_send = self.get_next_fuzzed_packet(os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR,
                                                                          self.protocol, 'HTTPRequest',
                                                                          method),
                                                             os.path.join(ut.PATH_TO_VALID_PACKETS_DIR,
                                                                          self.protocol, 'HTTPRequest',
                                                                          method), method)
                if packet_to_send[0].haslayer(HTTP):
                    logging.info('Paquete HTTP mutado -> {}'.format(packet_to_send[0]['HTTP']))
                    print('\n ########## Paquete mutado ##########')
                    packet_to_send[0].show()
                    self.s.send(bytes(packet_to_send[0]['HTTP']))
                else:
                    logging.info('Paquete HTTP mutado entero -> {}'.format(packet_to_send[0][TCP].load))
                    print('\n ########## Paquete mutado ##########')
                    packet_to_send[0].show()
                    self.s.send(bytes(packet_to_send[0][TCP].load))

                print('\n')
                ut.print_pretty_message('Success', ' Enviado paquete mutado del método {} ...', True,
                                        method)
                logging.info('Enviado paquete mutado del método {} ...'.format(method))

                self.number_of_pkts_sent += 1
                self.send_mutated_packet = False
            else:
                self.send_mutated_packet = True
                packet_to_send = self.get_valid_packet(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, self.protocol,
                                                                    'HTTPRequest', method))
                print('\n Paquete sin mutar -> {}'.format(packet_to_send[0]))
                logging.info('Paquete sin mutar -> {}'.format(packet_to_send[0]))

                print('\n')
                self.s.send(bytes(packet_to_send[0]['HTTP']))
                ut.print_pretty_message('Success', ' Enviado paquete sin mutar del método {} ...', True,
                                        method)
                logging.info('Enviado paquete sin mutar del método {} ...'.format(method))

            ut.print_pretty_message('Success', ' Recibiendo datos del bróker ...', True)
            logging.info('Recibiendo datos del bróker ...')
            resp = self.Recv(bytearray())
            print('Datos -> {}'.format(resp))
            time.sleep(1)
        except socket.error as e:
            if e.errno != errno.ECONNRESET:
                ut.print_pretty_message('Warning',
                                        ' Se cerró la conexión con el equipo. Reconectando ...',
                                        False,
                                        None)
                logging.warning('Se cerró la conexión con el equipo. Reconectando ...')
                self.s.close()
                self.connect_to_server()
                print("\n")
            else:
                ut.print_pretty_message('Warning',
                                        ' El servidor ha reseteado la conexión. Esperando unos segundos...',
                                        False,
                                        None)
                logging.warning('El servidor ha reseteado la conexión. Esperando unos segundos ... ')
                self.s.close()
                self.connect_to_server()
                print("\n")
        except Exception as e:
            ut.print_pretty_message('Error',
                                    ' Ha ocurrido el siguiente error -> {}.',
                                    True,
                                    e)

    def send_fuzzed_pkts(self, start_exec_time):
        """
        Función que itera sobre las sesiones y llama a send_pkt.
        Si se presiona CTRL-C se para la ejecución y se imprime el tiempo de ejecución
        y el número de paquetes mutados.
        :param start_exec_time: tiempo de ejecución inicial.
        """
        try:
            i = 0
            print('Sesión {} -> {}'.format(str(i), self.session_structures[i]))
            while 1:
                try:
                    self.send_pkt(self.current_session.__next__())
                except StopIteration:
                    ut.print_pretty_message('Success', ' Se ha completado la sesión {} ({})',
                                            True, str(i + 1),
                                            time.strftime("%a, %d %b %Y %H:%M:%S"))
                    logging.info('Se ha completado la sesión {} ({}).'.format(str(i + 1),
                                                                              time.strftime("%a, %d %b %Y %H:%M:%S")))
                    print('\n')
                    time.sleep(2)
                    self.current_session = iter(self.session.__next__())
                    if i == len(self.session_structures) - 1:
                        i = 0
                    else:
                        i += 1
                    print('Sesión {} -> {}'.format(str(i), self.session_structures[i]))

        except KeyboardInterrupt:
            print('\n')
            ut.print_pretty_message('Success', ' Parando el envío de paquetes mutados ... ({})', True,
                                    time.strftime("%a, %d %b %Y %H:%M:%S"))
            logging.info('Parando el envío de paquetes mutados ...')
            self.s.close()
            print('Se han enviado {} paquetes mutados en total.'.format(str(self.number_of_pkts_sent)))
            logging.info('Se han enviado {} paquetes en total.'.format(str(self.number_of_pkts_sent)))
            print(ut.return_execution_elapsed_time(start_exec_time, time.time()))
            logging.info(ut.return_execution_elapsed_time(start_exec_time, time.time()))
            self.number_of_pkts_sent = 0

    def run(self):
        """
        Crea las carpetas necesarias en el caso de que no existan.
        Llena las estructuras iterables de paquetes.
        Si existe algún tipo de problema de conexión, se intenta un máximo de 49 veces conectar de nuevo.
        Si la conexión se establece, comienza el envío de paquetes.
        Recoge cualquier error que suceda en el socket.
        """
        if not os.path.exists(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', self.protocol)):
            os.makedirs(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', self.protocol))

        ut.set_file_logger(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', self.protocol, ut.session_file_name))
        self.fill_buffers()
        connected = False
        repeat_process = True
        conn_tries = 0

        while repeat_process:
            response = ''

            while not connected:
                try:
                    self.connect_to_server()
                    connected = True
                    start_exec_time = time.time()
                    self.send_fuzzed_pkts(start_exec_time)
                except socket.error as e:
                    connected = False
                    conn_tries += 1
                    print("\n")
                    ut.print_pretty_message('Warning', ' Se produjo un error en el socket -> {}', True, e)
                    logging.warning('Se produjo un error en el socket -> {}'.format(e))
                    if (conn_tries < 50):
                        print('\n Intentando reconectar ...')
                        logging.info('Intentando reconectar ...')
                        continue
                    else:
                        print("\n")
                        ut.print_pretty_message('Warning', ' Se han realizado 50 intentos de conexión sin éxito.',
                                                False, None)
                        logging.warning('Se han realizado 50 intentos de conexión sin éxito.')
                        break
                except Exception as e:
                    print("\n")
                    ut.print_pretty_message('Warning', ' Algo no fue bien. Excepción -> {}', True, e)
                    logging.warning('Algo no fue bien -> {}'.format(e))
                    print("\n")
                    ut.print_pretty_message('Success', ' Intentando conectar de nuevo con el equipo ...', False, None)
                    logging.info('Intentando reconectar con el equipo ...')
                    continue

            if self.number_of_pkts_sent > 0:
                print('Se han enviado {} paquetes mutados en total.'.format(str(self.number_of_pkts_sent)))
                logging.info('Se han enviado {} paquetes en total.'.format(str(self.number_of_pkts_sent)))
                print(ut.return_execution_elapsed_time(start_exec_time, time.time()))
                logging.info(ut.return_execution_elapsed_time(start_exec_time, time.time()))

            connected = False
            conn_tries = 0
            response = 'L'
            while response != 'S' and response != 's' and response != 'N' and response != 'n':
                response = input('\n ¿Desea volver a comenzar el envío de paquetes? (S/N):')

            if response == 'S' or response == 's':
                repeat_process = True
            else:
                repeat_process = False