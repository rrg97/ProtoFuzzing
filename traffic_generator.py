import requests as req
import requests
import re
import random
import subprocess
import utils as ut
from fake_headers import Headers


class Traffic_Generator:

    def __init__(self):
        pass

    def retrieve_url_to_test(self):
        list_of_url = []
        r = None
        try:
            r = req.get('http://scratchpads.org/explore/sites-list', timeout=5)
        except req.exceptions.ConnectTimeout as e:
            print(e)
        if r.status_code == 200:
            regex = r'.*?<td>.*?<a href=\"(.*?)\">.*?</a></td>.*?'
            list_of_url = re.findall(regex, r.text, re.DOTALL)
        else:
            r = req.get('http://www.testingmcafeesites.com/')
            regex = r'.*?<A HREF=\"(.*?)\">.*?</A>.*?'
            list_of_url = re.findall(regex, r.text, re.DOTALL)

        return list_of_url

    def generate_http_traffic(self):
        urls = self.retrieve_url_to_test()
        urls = urls[:50]
        while len(urls) > 0:
            url = urls.pop()
            print("\n")
            ut.print_pretty_message('Success', ' Generando peticiones http a {} ...', True, url)
            try:
                r = req.get(url)
            except req.exceptions.ConnectionError as e:
                print(e)

    def return_values_for_method_http(self, method):
        os = ['linux', 'mac', 'win']

        headers = Headers(os=random.choice(os), headers=True).generate()

        if method.startswith('p'):
            data = """
                    {
                      "Id":""" + ut.get_random_string(10) + """ ,
                      "Customer":""" + ut.get_random_string(8) + """ ,
                      "Date":""" + ut.get_random_string(5) + """ ,
                      "Price":""" + ut.get_random_string(3) + """ ,
                    }
                    """
            return headers, data
        else:
            return headers

    def generate_http_traffic2(self):
        #url = 'http://eu.httpbin.org'
        url = 'http://www.testingmcafeesites.com/'
        LIST_OF_HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

        while len(LIST_OF_HTTP_METHODS) > 0:
            i = 0
            method = LIST_OF_HTTP_METHODS.pop()
            if method.startswith('p'):
                headers, data = self.return_values_for_method_http(method)
            else:
                headers = self.return_values_for_method_http(method)

            while i < 10:
                try:
                    print("\n")
                    ut.print_pretty_message('Success', ' Generando peticiones http a {} ...', True, url)
                    if method.startswith('p'):
                        r = getattr(requests, method)(url, headers=headers, data=data)
                    else:
                        r = getattr(requests, method)(url, headers=headers)
                    i += 1
                except req.exceptions.ConnectionError:
                    ut.print_pretty_message('Error', ' No se puede conectar con {} ...', True, url)
                    print('Probando con la url {}'.format('http://scratchpads.org/explore/sites-list'))
                    url = 'http://scratchpads.org/explore/sites-list'

    def generate_mqtt_traffic(self):
        MQTT_HOST = "broker.emqx.io"
        MQTT_KEEPALIVE_INTERVAL = 5
        MQTT_TOPIC = "helloTopic"
        MQTT_MSG = "hello MQTT"
        MQTT_QoS = 0

        i = 0

        decision = 0
        while i < 6:
            try:
                if decision == 1:
                    # Con esto forzamos a que se envíen pubrec, pubrel, pubcomp o puback
                    decision = 0
                    subprocess.run(['mosquitto_pub', '-h', MQTT_HOST, '-t', MQTT_TOPIC, '-m', MQTT_MSG, '-k',
                                    str(MQTT_KEEPALIVE_INTERVAL), '-q', str(MQTT_QoS)])

                    if MQTT_QoS == 2:
                        MQTT_QoS = 0
                    else:
                        MQTT_QoS += 1
                else:
                    decision = 1
                    cmd = 'mosquitto_sub -h ' + MQTT_HOST + ' -t ' + MQTT_TOPIC
                    try:
                        # Con esto obligamos a que se manden mensajes pingreq y pingresp
                        p = subprocess.Popen(
                            ['mosquitto_sub', '-h', MQTT_HOST, '-t', MQTT_TOPIC, '-k', str(MQTT_KEEPALIVE_INTERVAL)])
                        p2 = subprocess.Popen(['mosquitto_sub', '-h', MQTT_HOST, '-t', 'new_topic', '-U', MQTT_TOPIC])
                        p.wait(timeout=7)
                        p2.wait(timeout=7)

                    except subprocess.TimeoutExpired:
                        p.kill()
                        p2.kill()
            except Exception as e:
                print(e)
            finally:
                i += 1

'''def test():
    tg = Traffic_Generator()
    tg.generate_html_traffic2()

test()'''
