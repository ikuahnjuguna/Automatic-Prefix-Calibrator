import sys
import requests
import re
from http import HTTPStatus
from datetime import datetime
from requests import RequestException
from ipaddress import AddressValueError
import signal
import ipaddress
import subprocess
from itertools import starmap
import os
from collections import Counter
from itertools import starmap


def sigint_handler(signum, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)


# check_conn_dict = {'[2]\d+': True, '^(HTTP|Resource|Unable).*': False}

class AspathException(Exception):
    error_message = "As Path Contains a Private ASN"

    def __init__(self, *args):
        if args:
            self.error_message = args
            super().__init__(args)
        else:
            super().__init__(self.error_message)

    def log_exception(self):
        exception = {
            "type": type(self).__name__,
            "message": self.error_message,

        }
        return f'Exception: {datetime.utcnow().isoformat()}:{exception}'


class AsPathMismatchException(AspathException):
    error_message = 'Please check on the as-path Format'


class AspathPrivateException(AspathException):
    pass


class PrefixException(AddressValueError, AspathException):
    error_message = "An error occurred. PLease review Prefix Structure"

    def __init__(self, *args):
        if args:
            self.error_message = args
            super().__init__(args)
        else:
            super().__init__(self.error_message)


class PrefixFormatMIsmatchException(PrefixException):
    error_message = 'Please check on the prefix Format'


class PrefixLengthException(PrefixException):
    error_message = 'Please check on the Prefix Subnet Mask'


class PrefixObjectException(PrefixException):
    error_message = 'Failed to create a Network Object for the prefix. Pleas retry'


class PrefixTypeException(PrefixException):
    error_message = 'Prefix is not Globally routable***********.'


class PrefixHostBitSet(PrefixException):
    error_message = 'Prefix shared is a host subnet instead of a network address'


class ConnectException(RequestException):
    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_message = 'An internal Error occurred'

    def __init__(self, *args):
        if args:
            self.error_message = args
            super().__init__(args)
        else:
            super().__init__(self.error_message)

    def log_exception(self):
        exception = {
            "type": type(self).__name__,
            "http_status": self.http_status,
            "message": self.error_message,

        }
        return f'Exception: {datetime.utcnow().isoformat()}:{exception}'


class UserException(ConnectException):
    http_status = HTTPStatus.NOT_FOUND
    error_message = 'A client side Error message occurred'


class ServerException(ConnectException):
    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_message = 'An internal Error message occurred'


class RequestTimeoutException(ConnectException):
    http_status = HTTPStatus.REQUEST_TIMEOUT
    error_message = 'Request Timed out.Please try again'


def check_connectivity(param):
    try:
        r = requests.get(param)
        r.raise_for_status()
    except requests.exceptions.HTTPError as ex:

        if re.match('^4\d{2}$', str(ex.response.status_code)):
            raise UserException('User side Exception Occurred')

        elif re.match('^5\d{2}$', str(ex.response.status_code)):
            raise ServerException('Server Side Exception Occurred')

    except requests.exceptions.Timeout as ex:

        raise RequestTimeoutException()

    except requests.exceptions.RequestException as ex:

        raise ConnectException('Connection could not be established to the server')

    else:

        return r.status_code


def get_connection_status(param):
    try:
        status = check_connectivity(param)
    except ConnectException as ex:
        print(ex.log_exception())
        sys.exit()
    except RequestException as ex:
        print(ex)
        sys.exit()
    else:
        # return [value for key, value in check_conn_dict.items() if re.match(key, status)]
        return True


class ValidateAsPath:
    as_path_pattern = re.compile('([1-9][0-9]{0,4}\|*){1,}$')

    def __set_name__(self, instance, property_name):
        self.property_name = property_name

    def __get__(self, instance, owner_class):
        if instance is None:
            return self
        else:
            if self.property_name not in instance.__dict__:
                instance.__dict__[self.property_name] = []
        return instance.__dict__.get(self.property_name, None)

    def __set__(self, instance, value):

        if not re.match(type(self).as_path_pattern, value):
            raise AsPathMismatchException()

        valid_as_path = type(self).remove_private_asn(value.split('|'))
        instance.__dict__[self.property_name] = valid_as_path

    @staticmethod
    def remove_private_asn(as_path):

        # private_asn = filter(lambda x: int(x) > 600000, as_path)
        private_asn = filter(lambda x: (int(x) in {int(i) for i in range(64512, 65536)}) or (int(x) > int(4200000000)),
                             as_path)
        if len(list(private_asn)) > 0:
            raise AspathPrivateException()
            # raise ValueError
        return tuple(map(lambda x: int(x), as_path))


class ValidateRegistryOriginAsn(ValidateAsPath):
    @staticmethod
    def remove_private_asn(as_path):
        # private_asn = filter(lambda x: int(x) > 600000, as_path)
        private_asn = filter(lambda x: (int(x) in {int(i) for i in range(64512, 65536)}) or (int(x) > int(4200000000)),
                             as_path)
        if len(list(private_asn)) > 0:
            raise AspathPrivateException()
            # raise ValueError
        return next(map(lambda x: str(x), as_path))


class ValidatePrefix:
    prefix_pattern = re.compile(
        '^(([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9][0-9]?)$')

    ipv4_prefix_pattern = re.compile('((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9][0-9]?$')

    def __init__(self, ipv4_max_length=24, ipv6_max_length=48):
        self.ipv4_max_length = ipv4_max_length
        self.ipv6_max_length = ipv6_max_length

    def __set_name__(self, instance, property_name):
        self.property_name = property_name

    def __get__(self, instance, owner_class):
        if instance is None:
            return self
        return instance.__dict__.get(self.property_name, None)

    def __set__(self, instance, value):

        if not re.match(type(self).prefix_pattern, value):
            raise PrefixFormatMIsmatchException()

        if re.match(type(self).ipv4_prefix_pattern, value):
            type(self).check_prefix_length(value, self.ipv4_max_length)
        else:
            type(self).check_prefix_length(value, self.ipv6_max_length)

        instance.__dict__[self.property_name] = type(self).validate_prefix_object(value)

    @staticmethod
    def check_prefix_length(val_, length):
        prefix_length_ = int(val_.split('/')[1])
        if prefix_length_ <= 0:
            raise PrefixLengthException()
        if prefix_length_ > length:
            raise PrefixLengthException()
            # raise ValueError

    @staticmethod
    def validate_prefix_object(val_):
        prefix, mask = val_.split('/')
        try:
            network_prefix = ipaddress.ip_network(f'{prefix}/{mask}')
        except ValueError:
            raise PrefixHostBitSet()

        if not isinstance(network_prefix, ipaddress.IPv4Network) and not isinstance(network_prefix,
                                                                                    ipaddress.IPv6Network):
            raise PrefixObjectException()
            # raise ValueError
        if not network_prefix.is_global:
            # print(f'{val_} is not global')
            raise PrefixTypeException()
            # raise ValueError()
        else:
            return network_prefix


class Resource:
    prefix = ValidatePrefix()
    as_path = ValidateAsPath()

    def __init__(self, prefix_as_path, web_status):
        self.mask = None
        self.web_status = web_status

        if prefix_as_path is not None:
            self.prefix, self.as_path = prefix_as_path.strip('|').split('-')

    @property
    def customer_received_origin_as(self):
        return str(self.as_path[-1])

    @property
    def customer_received_prefix(self):
        return self.prefix

    def __repr__(self):
        return f'Resource(Prefix={self.prefix},As-path={self.as_path})'


class Validate_Afrinic(Resource):
    afrinic_feedback_regex_match = re.compile(
        '(?=^inet\d?num:.*)^inet\d?num\:\s+(([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]|(((25[0-5]|2[0-4][0-9]|1[0-9]'
        '[0-9]|[1-9]?[0-9])\.){3}[0] - ((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}25[5]))')
    afrinic_search_prefix_regex = re.compile(
        '(([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]|(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.)'
        '{3}[0] - ((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}25[5]))')
    ipv6_prefix_pattern = re.compile('([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]$')
    customer_received_afrinic_ro_origin_pattern = re.compile(
        '(route6?:|origin:)\s+((([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]'
        '|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9]'
        '[0-9]?)|(AS([1-9][0-9]{0,4})){1,})')
    customer_received_afrinic_prefix_originas_pattern = re.compile(
        '(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9]'
        '[0-9]?|([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]|(AS|as)[1-9][0-9]{0,})')

    customer_received_afrinic_prefix_originas_final_match = re.compile('((([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]'
                                                                       '|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
                                                                       '\.){3}[0]\/[1-9]'
                                                                       '[0-9]?)|(AS|as)[1-9][0-9]{0,})')

    rpki_pattern = re.compile('^invalid$')

    afrinic_allocation_prefix = ValidatePrefix()
    customer_received_afrinic_RO_Prefix = ValidatePrefix()
    customer_received_afrinic_RO_Origin_AS=ValidateRegistryOriginAsn()
    allocation_received_afrinic_RO_Prefix = ValidatePrefix()
    allocation_received_afrinic_RO_Origin_AS=ValidateRegistryOriginAsn()
    radb_received_prefix = ValidatePrefix()
    radb_received_asn = ValidateRegistryOriginAsn()

    def __init__(self, prefix_as_path, web_status):
        super().__init__(prefix_as_path, web_status)
        self.radb_results = {}
        dict_status, radb_status = self.get_resources_from_afrinic()

        for key, value in dict_status.items():
            print(f"{value.get('message', None)}")

        if radb_status:
            print('The below Entries have been found on RADB')

            ls = []
            for key, record in radb_status.items():
                self.radb_received_prefix = record.get('Prefix', None).strip(' ')
                self.radb_received_asn = record.get('ASN', None).strip(' ')
                print(
                    f"Registry-->{record.get('Registry', 'None')}, Prefix-->{self.radb_received_prefix}, ASN-->{self.radb_received_asn}, RPKI Status-->{record.get('RPKI', None)}")
                # print(self.customer_received_origin_as)

                if record.get('ASN').strip() == self.customer_received_origin_as:
                    ls.append((record.get('Prefix', None), record.get('ASN', None), record.get('RPKI', 'Unkown')))

            if ls:

                if any(list(map(lambda x: True if str(self.customer_received_prefix) == x[0] else False, ls))):
                    if any(list(map(lambda x: False if re.match(type(self).rpki_pattern, x[2]) else True, ls))):

                        print(
                            f'Please lift filters using Prefix-> {next(type(self).return_supernet(ls))}, ASN-> {self.customer_received_origin_as}')

                    else:
                        print(f'RPKI Mismatch occurred')
                else:
                    print(
                        f'Please advise customer to create an Exact RO Match on either AFRINIC OR RADB.DO NOT LIFT FILTERS')
            else:

                if 'allocation_supernet_received_prefix' in dict_status:
                    if dict_status.get('allocation_supernet_received_prefix').get('state') is False:
                        print(f'Found matching prefixes on RADB, but there was an ASN Mismatch')
                        print(
                            f'Please Lift filters using Prefix: {self.customer_received_prefix} ASN: {self.customer_received_origin_as} received from Customer')
                    else:
                        print('We could not find matching prefixes on RADB.DO NOT LIFT FILTERS')
                else:
                    print('Do NOT LIFT FILTERS')

    def process_overall_results(self, status_dict, status_dict_data):

        dict_status = {}
        radb_status = {}

        if status_dict.get('check_allocation_from_afrinic', None):
            # if there is an allocation on Afrinic..get it and check if there is a route object..
            self.afrinic_allocation_prefix = (self.process_prefix_allocation_feedbackfrom_afrinic
                                              (status_dict_data.get('prefix_allocation_from_afrinic', None)))
            dict_status['allocation_prefix'] = {
                'message': f'Prefix Allocation on Afrinic- {self.afrinic_allocation_prefix}'}

            if status_dict.get('check_route_objectfrom_afrinic', None):
                # we now know there is a route object
                self.customer_received_afrinic_RO_Prefix, self.customer_received_afrinic_RO_Origin_AS = self.process_customer_received_afrinic_RoPrefix(
                    status_dict_data.get('customer_received_afrinic_prefix_origin_as', None))

                if ((self.customer_received_prefix == self.customer_received_afrinic_RO_Prefix) and
                        (self.customer_received_origin_as == self.customer_received_afrinic_RO_Origin_AS)):
                    dict_status['afrinic_route_object'] = {'state': True,
                                                           'message': f"Route object Found(Prefix-{self.customer_received_afrinic_RO_Prefix},Origin ASN-{self.customer_received_afrinic_RO_Origin_AS})"}

                    self.radb_results = Validate_Radb(self.customer_received_prefix).get_resources_from_radb()

                    rpki_values_list = [item.get('RPKI', None) for item in self.radb_results.values()]
                    rpki_values_boolstatus = map(lambda x: False if re.match(type(self).rpki_pattern, x) else True,
                                                 rpki_values_list)

                    if self.radb_results and any(rpki_values_boolstatus):
                        dict_status['afrinic_route_object'] = {'state': True,
                                                               'message': f"Route object Found(Prefix-{self.customer_received_afrinic_RO_Prefix},Origin ASN-{self.customer_received_afrinic_RO_Origin_AS},RPKI Status-{self.radb_results.get(f'AFRINIC-{self.customer_received_prefix}').get('RPKI', 'Unkown')})"}

                else:
                    print(dict_status.get('allocation_prefix', None).get('message'))
                    print(
                        f'Route Object returned from Afrinic Prefix:{self.customer_received_afrinic_RO_Prefix},ASN:{self.customer_received_afrinic_RO_Origin_AS} does not match prefix and ASN from customer')
                    print(
                        f'Proceeding to check prefix and ASN( {self.customer_received_prefix}, ASN {self.customer_received_origin_as}) from RADB')

                    self.radb_results = Validate_Radb(self.customer_received_prefix).get_resources_from_radb()

                    if not self.radb_results:
                        raise ValueError(
                            f'Could not find Route object for the Prefix on both RADB and AFRINIC')

                    print('The following Objects have been found in RADB')

                    ls = []

                    for key, record in self.radb_results.items():
                        self.radb_received_prefix = record.get('Prefix', None).strip(' ')
                        self.radb_received_asn = record.get('ASN', None).strip(' ')

                        print(
                            f"Registry-->{record.get('Registry', 'None')}, Prefix-->{self.radb_received_prefix}, ASN-->{self.radb_received_asn}, RPKI Status-->{record.get('RPKI', None)}")
                        # print(self.customer_received_origin_as)

                        if record.get('ASN').strip() == self.customer_received_origin_as:
                            ls.append(
                                (record.get('Prefix', None), record.get('ASN', None), record.get('RPKI', 'Unkown')))

                    if ls:
                        if any(list(map(lambda x: True if str(self.customer_received_prefix) == x[0] else False, ls))):
                            if any(list(map(lambda x: False if re.match(type(self).rpki_pattern, x[2]) else True, ls))):

                                print(
                                    f'Please lift filters using Prefix-> {next(type(self).return_supernet(ls))}, ASN-> {self.customer_received_origin_as}')
                            else:
                                print(f'RPKI Mismatch occurred')
                        else:
                            print(
                                f'Please advise customer to create an Exact RO Match on either AFRINIC OR RADB.DO NOT LIFT FILTERS')

                    else:
                        print('We could not find matching prefixes on RADB.DO NOT LIFT FILTERS')
                    return {}, {}

                # check if the prefix allocated by Afrinic is same as prefix and asn received from Afrinic routeboject.

                if ((self.afrinic_allocation_prefix == self.customer_received_afrinic_RO_Prefix) and
                        (self.customer_received_origin_as == self.customer_received_afrinic_RO_Origin_AS)):
                    dict_status['prefix_equality'] = {'state': True,
                                                      'message': f'Please lift filters using prefix {self.afrinic_allocation_prefix},ASN {self.customer_received_afrinic_RO_Origin_AS}'}

                else:

                    # print(' Check if alloction has route object before deciding to lift filters using prefix received form Afrinic')
                    p4 = type(self).execute_initial_command_on_afrinic(self.afrinic_allocation_prefix)
                    dict_status['prefix_equality'] = {'state': False,
                                                      'message': 'Check if alloction has route object before deciding to lift filters using prefix received form Afrinic'}

                    if p4.returncode != 0:
                        print('Return code is not 0')
                    #   Could not get a response server...consider lifting filters using prefix  and asn received in RO
                    else:
                        # we got response from server and now checking for route object from response
                        check_allocation_route_object_from_afrinic, status_dict_data[
                            'allocation_received_afrinic_prefix_origin_as'] = type(
                            self).check_route_object_from_afrinic(
                            p4)

                        if check_allocation_route_object_from_afrinic != 0:
                            dict_status['allocation_route_object'] = {'state': False,
                                                                      'message': f'Could not find allocation route object on Afrinic.Proceed to lift filters using Prefix:{self.customer_received_prefix},ASN:{self.customer_received_origin_as}.'}

                        else:
                            # print('Found allocation prefix route object on Africin')
                            self.allocation_received_afrinic_RO_Prefix, self.allocation_received_afrinic_RO_Origin_AS = (
                                self.process_customer_received_afrinic_RoPrefix(
                                    status_dict_data.get('allocation_received_afrinic_prefix_origin_as', None)))
                            dict_status['allocation_route_object'] = {'state': True,
                                                                      'message': f'Found Route objects on Afrinic for allocation prefix->{self.allocation_received_afrinic_RO_Prefix},ASN->{self.allocation_received_afrinic_RO_Origin_AS}'}

                            if type(self).return_ip_network_object(
                                    self.allocation_received_afrinic_RO_Prefix).supernet_of(
                                type(self).return_ip_network_object(self.customer_received_prefix)) \
                                    and self.allocation_received_afrinic_RO_Origin_AS == self.customer_received_origin_as:

                                dict_status['allocation_supernet_received_prefix'] = {'state': True,
                                                                                      'message': f'Customer received prefix is a subset of the allocation prefix. Please lift filters using Prefix:{self.allocation_received_afrinic_RO_Prefix},ASN:{self.allocation_received_afrinic_RO_Origin_AS}'}
                                # some mismatch noted
                            else:
                                # 'Alloction RO != Received RO Lift filters using customer received Afrinic received prefix********'
                                dict_status['allocation_supernet_received_prefix'] = {'state': False,
                                                                                      'message': 'Customer received prefix is either not a  subset of the allocation prefix or we have an ASN Mismatch. Checking RADB'}
                                radb_status = Validate_Radb(self.afrinic_allocation_prefix).get_resources_from_radb()

            else:

                dict_status['afrinic_route_object'] = {'state': False,
                                                       'message': 'Prefix found on  AFRINIC REGISTRY, however Prefix has no Route Object.Check RADB'}

                radb_status = Validate_Radb(self.customer_received_prefix).get_resources_from_radb()

        else:
            dict_status['allocation_prefix'] = {'state': False, 'allocation_prefix': self.customer_received_prefix,
                                                'message': f'prefix {self.customer_received_prefix} not found in the Afrinic Registry.Please check RADB'}

            radb_status = Validate_Radb(self.customer_received_prefix).get_resources_from_radb()

        return (dict_status, radb_status)

    def get_resources_from_afrinic(self):
        status_dict = {}
        status_dict_data = {}
        p1 = type(self).execute_initial_command_on_afrinic(self.customer_received_prefix)

        if p1.returncode != 0:
            print('Return code is not 0')
            # Raise ValueError-could not get results from afrinic server
            # consider retrying again.....
        check_prefix_allocationfrom_afrinic, status_dict_data['prefix_allocation_from_afrinic'] = (
            type(self).check_prefix_allocation_from_afrinic(p1))
        if check_prefix_allocationfrom_afrinic != 0:
            print('Prefix  does not  exist on Afrinic')
            status_dict['check_allocation_from_afrinic'] = False

        else:
            status_dict['check_allocation_from_afrinic'] = True
            check_route_objectfrom_afrinic, status_dict_data['customer_received_afrinic_prefix_origin_as'] = type(
                self).check_route_object_from_afrinic(p1)
            if check_route_objectfrom_afrinic != 0:
                status_dict['check_route_objectfrom_afrinic'] = False
            else:
                status_dict['check_route_objectfrom_afrinic'] = True

        return self.process_overall_results(status_dict, status_dict_data)

    @staticmethod
    def return_ip_network_object(param):
        return ipaddress.ip_network(param)

    @staticmethod
    def return_supernet(param_iterable):
        iplist = list(starmap(lambda x, y, z: ipaddress.ip_network(x), param_iterable))
        supernet = ipaddress.collapse_addresses(iplist)
        return supernet

    def process_customer_received_afrinic_RoPrefix(self, data):

        if re.match(type(self).customer_received_afrinic_ro_origin_pattern, data):
            vax = re.findall(type(self).customer_received_afrinic_prefix_originas_pattern, data)
            newval = tuple(starmap(Validate_Afrinic.filter_customer_received_RoPrefix, vax))

            return newval

    @staticmethod
    def filter_customer_received_RoPrefix(*args):
        for arg in args:
            if re.match(Validate_Afrinic.customer_received_afrinic_prefix_originas_final_match, arg):
                return str(arg).replace('AS', '').replace('as', '')
            pass

    def process_prefix_allocation_feedbackfrom_afrinic(self, data):
        if re.match(type(self).afrinic_feedback_regex_match, data):
            val = re.search(type(self).afrinic_search_prefix_regex, data)
            if re.match(type(self).ipv6_prefix_pattern, val.group(0)):
                if isinstance(ipaddress.ip_network(val.group(0)), ipaddress.IPv6Network):
                    return str(val.group(0))
            else:
                ipaddr1, ipaddr2 = tuple(map(lambda x: x.strip(), val.group(0).split('-')))
                xl = ipaddress.summarize_address_range(ipaddress.ip_address(ipaddr1), ipaddress.ip_address(ipaddr2))
                return str(next(xl))

        # raise ValueError('Unable to process feedback from the server')

    @staticmethod
    def execute_initial_command_on_afrinic(prefix_):
        return subprocess.run(["whois", "-h", "whois.afrinic.net", f"{prefix_}"],
                              capture_output=True, text=True)

    @staticmethod
    def check_prefix_allocation_from_afrinic(get_resources_object):
        p2 = subprocess.run(["grep", "-E", "inet6num|inetnum"], capture_output=True, text=True,
                            input=get_resources_object.stdout)
        if p2.returncode != 0:
            return p2.returncode, None
        return p2.returncode, p2.stdout

    @staticmethod
    def check_route_object_from_afrinic(get_resources_object):
        p3 = subprocess.run(["grep", "-E", "^route6|^route|origin"], capture_output=True, text=True,
                            input=get_resources_object.stdout)
        if p3.returncode != 0:
            return p3.returncode, None
        return p3.returncode, p3.stdout


class Validate_Radb():
    radb_match_pattern = re.compile(
        '^(route\d?:|origin:|source:|rpki-ov-state:)\s+(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9][0-9]?|([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]|AS[1-9][0-9]{0}|(AS|as).*|(valid|invalid|not_found.*)|.*)',
        re.MULTILINE)
    radb_match_pattern_final_match = re.compile('((([0-9a-fA-F]{1,4}\:{1,2}){1,3}\/[1-4][0-9]'
                                                '|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}[0]\/[1-9]'
                                                '[0-9]?)|\s(AS|as)[1-9][0-9]{0,}|(valid|invalid|not_found.*)|source:\s+.*)')

    def __init__(self, prefix):
        self.final_results_dict = dict()
        self.afrinic_received_prefix = prefix

    def get_resources_from_radb(self):
        radb_command_output = self.execute_initial_command_on_radb(self.afrinic_received_prefix)
        return self.process_customer_received_radb_RoPrefix(radb_command_output)

    @staticmethod
    def execute_initial_command_on_radb(prefix_):
        result = subprocess.run(["whois", "-h", "whois.radb.net", f"{prefix_}"],
                                capture_output=True, text=True)
        return result.stdout.split(os.linesep + os.linesep)

    def process_customer_received_radb_RoPrefix(self, data):

        for record in data:
            if re.match(self.radb_match_pattern, record):
                val = re.findall(self.radb_match_pattern_final_match, record)
                # print(val)
                fields = ('Prefix', 'ASN', 'Registry', 'RPKI')
                newval = tuple(zip(fields, tuple(map(lambda x: re.sub(r'(^source:\s+)', '', str(x)),
                                                     Counter(
                                                         tuple(starmap(type(self).filter_RADB_values, val))).keys()))))

                key = filter(lambda x: x != False, list(starmap(type(self).match_dict_key, newval)))

                self.final_results_dict[list(key)[0] + '-' + str(self.afrinic_received_prefix)] = dict(newval)

        return self.final_results_dict

    @staticmethod
    def filter_RADB_values(*args):
        for arg in args:
            if re.match(Validate_Radb.radb_match_pattern_final_match, arg):
                return str(arg).replace('AS', '').replace('as', '')
            pass

    @staticmethod
    def match_dict_key(*tp):
        if tp[0] == 'Registry':
            return tp[1]
        else:
            return False


try:
    xy = Resource(*sys.argv[1:], get_connection_status('https://whois.afrinic.net/'))

except (PrefixException, AspathException) as ex:
    print(ex.log_exception())
    sys.exit()
else:
    try:
        xa = Validate_Afrinic(*sys.argv[1:], get_connection_status('https://whois.afrinic.net/'))

    except (PrefixException, AspathException) as ex:
        print(ex.log_exception())
        sys.exit()


    except ValueError as ex:
        print(ex)
