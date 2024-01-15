#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_ca
version_added: 0.1.0
short_description: Manage pfSense Certificate Authorities
description:
  >
    Manage pfSense Certificate Authorities
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the Certificate Authority
    required: true
    type: str
  state:
    description: State in which to leave the Certificate Authority
    default: present
    choices: [ "present", "absent" ]
    type: str
  method:
    description:
      >
        The type of Certificate Authority to create. `internal` will create a new internal CA. `existing` will import a CA certificate. `intermediate` will
        cerate a new intermediate CA.
    default: existing
    choices: ['internal', 'existing', 'intermediate']
    type: str
    version_added: 0.7.0
  trust:
    description: Add this Certificate Authority to the Operating System Trust Store. Defaults to false.
    type: bool
    version_added: 0.5.0
  randomserial:
    description:  Use random serial numbers when signing certifices. Defaults to false.
    type: bool
    version_added: 0.5.0
  certificate:
    description:
      >
        The certificate for the Certificate Authority.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  crl:
    description:
      >
        The Certificate Revocation List for the Certificate Authority.  This can be in PEM
        form or Base64 encoded PEM as a single string (which is how pfSense stores it).
    required: false
    type: str
  crlname:
    description:
      >
        The name of the CRL.  This will default to name + ' CRL'.  If multiple CRLs exist
        with this name, you must specify crlrefid.
    required: false
    type: str
    version_added: 0.5.0
  crlrefid:
    description: The refrence ID of the CRL.  This will default to a unique id based on time.
    required: false
    type: str
    version_added: 0.5.0
  serial:
    description: Number to be used as a sequential serial number for the next certificate to be signed by this CA.
    type: int
    version_added: 0.5.0
  keytype:
    description: Key type of the Certficate Authority
    choices: ['RSA', 'ECDSA']
    type: str
    version_added: 0.7.0
  keylen:
    description: The keylen of the Certficate Authority
    choices: ['1024', '2048', '3072', '4096', '6144', '7680', '8192', '15360', '16384']
    type: str
    version_added: 0.7.0
  ecname:
    description: The ecname of the Certficate Authority
    choices: ['secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2', 'secp192k1', 'secp224k1', 'secp224r1', 'secp256k1', 'secp384r1', 'secp521r1', 'prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3', 'prime256v1', 'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1', 'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1', 'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1', 'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2pnb208w1', 'c2tnb239v1', 'c2tnb239v2', 'c2tnb239v3', 'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1', 'c2pnb368w1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls3', 'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5', 'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8', 'wap-wsg-idm-ecid-wtls9', 'wap-wsg-idm-ecid-wtls10', 'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'Oakley-EC2N-3', 'Oakley-EC2N-4', 'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1', 'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1', 'brainpoolP256r1', 'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1', 'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1', 'brainpoolP512t1']
    type: str
    version_added: 0.7.0
  digest_alg:
    description: Digest Algorithm of the Certficate Authority. The digest method used when the CA is signed.
    choices: ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    type: str
    version_added: 0.7.0
  lifetime:
    description: Lifetime (days) of the Certficate Authority
    type: int
    version_added: 0.7.0
  dn_commonname:
    description: Common Name of the Certficate Authority
    type: str
    version_added: 0.7.0
  dn_country:
    description: Country Code of the Certficate Authority
    choices: ['', 'US', 'CA', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'ST', 'SV', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW']
    type: str
    version_added: 0.7.0
  dn_state:
    description: State or Province of the Certficate Authority
    type: str
    version_added: 0.7.0
  dn_city:
    description: City of the Certficate Authority
    type: str
    version_added: 0.7.0
  dn_organization:
    description: Organization of the Certficate Authority
    type: str
    version_added: 0.7.0
  dn_organizationalunit:
    description: Organizational Unit of the Certficate Authority
    type: str
    version_added: 0.7.0
"""

EXAMPLES = """
- name: Add AD Certificate Authority
  pfsensible.core.pfsense_ca:
    name: AD CA
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dB...
    crl: |
      -----BEGIN X509 CRL-----
      MIICazCCAVMCAQEwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPTldSQSBPcGVu
      ...
      r0hUUy3w1trKtymlyhmd5XmYzINYp8p/Ws+boST+Fcw3chWTep/J8nKMeKESO0w=
      -----END X509 CRL-----
    state: present

- name: Add a new internal CA
  pfsensible.core.pfsense_ca:
    name: My Internal CA
    method: internal
    trust: true
    randomserial: true
    serial: 1
    keytype: RSA
    keylen: 1024
    ecname: secp112r1
    digest_alg: sha1
    lifetime: 3650
    dn_commonname: myinternal-ca
    dn_country: US
    dn_state: Colorado
    dn_city: Boulder
    dn_organization: My Organization
    dn_organizationalunit: My Department
    state: present

- name: Remove AD Certificate Authority
  pfsense_ca:
    name: AD CA
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

PFSENSE_CA_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    method=dict(type='str', choices=['internal', 'existing', 'intermediate']),
    trust=dict(type='bool'),
    randomserial=dict(type='bool'),
    certificate=dict(type='str'),
    crl=dict(default=None, type='str'),
    crlname=dict(default=None, type='str'),
    crlrefid=dict(default=None, type='str'),
    serial=dict(type='int'),
    keytype=dict(type='str', choices=['RSA', 'ECDSA'],),
    keylen=dict(type='str', choices=['1024', '2048', '3072', '4096', '6144', '7680', '8192', '15360', '16384'],),
    ecname=dict(type='str',
                choices=['secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2', 'secp192k1', 'secp224k1', 'secp224r1',
                         'secp256k1', 'secp384r1', 'secp521r1', 'prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3',
                         'prime256v1', 'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2',
                         'sect233k1', 'sect233r1', 'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1', 'c2pnb163v1',
                         'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1', 'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2pnb208w1', 'c2tnb239v1', 'c2tnb239v2',
                         'c2tnb239v3', 'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1', 'c2pnb368w1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls3',
                         'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5', 'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8',
                         'wap-wsg-idm-ecid-wtls9', 'wap-wsg-idm-ecid-wtls10', 'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'Oakley-EC2N-3',
                         'Oakley-EC2N-4', 'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1', 'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1',
                         'brainpoolP256r1', 'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1', 'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1',
                         'brainpoolP512t1'],),
    digest_alg=dict(type='str', choices=['sha1', 'sha224', 'sha256', 'sha384', 'sha512'],),
    lifetime=dict(type='int'),
    dn_commonname=dict(type='str'),
    dn_country=dict(type='str',
                    choices=['', 'US', 'CA', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB',
                             'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'ST', 'SV', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'],),
    dn_state=dict(type='str'),
    dn_city=dict(type='str'),
    dn_organization=dict(type='str'),
    dn_organizationalunit=dict(type='str'),
)

# These are default but not enforced values
CA_CREATE_DEFAULT = dict(
    randomserial='disabled',
    serial='0',
    trust='disabled',
)

# Booleans that map to different values
CA_BOOL_VALUES = dict(
    randomserial=('disabled', 'enabled'),
    trust=('disabled', 'enabled'),
)


class PFSenseCAModule(PFSenseModuleBase):
    """ module managing pfsense certificate authorities """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return PFSENSE_CA_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseCAModule, self).__init__(module, pfsense, root='pfsense', node='ca', have_refid=True, create_default=CA_CREATE_DEFAULT,
                                              bool_values=CA_BOOL_VALUES)
        self.name = "pfsense_ca"
        self.refresh_crls = False
        self.crl = None

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'absent':
            return

        # TODO - Make sure certificate purpose includes CA
        cert = params['certificate']
        lines = cert.splitlines()
        if lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----':
            params['certificate'] = base64.b64encode(cert.encode()).decode()
        elif not re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', cert):
            self.module.fail_json(msg='Could not recognize certificate format: %s' % (cert))

        if params['crl'] is not None:
            crl = params['crl']
            lines = crl.splitlines()
            if lines[0] == '-----BEGIN X509 CRL-----' and lines[-1] == '-----END X509 CRL-----':
                params['crl'] = base64.b64encode(crl.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0t', crl):
                self.module.fail_json(msg='Could not recognize CRL format: %s' % (crl))

        if params['serial'] is not None:
            if int(params['serial']) < 1:
                self.module.fail_json(msg='serial must be greater than 0')

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        obj['descr'] = params['name']
        if params['state'] == 'present':
            if 'certificate' in params and params['certificate'] is not None:
                obj['crt'] = params['certificate']
            if params['crl'] is not None:
                self.crl = {}
                self.crl['method'] = 'existing'
                self.crl['text'] = params['crl']
                self._get_ansible_param(self.crl, 'crlname', fname='descr', force=True, force_value=obj['descr'] + ' CRL')
                self._get_ansible_param(self.crl, 'crlrefid', fname='refid')

        for arg in CA_BOOL_VALUES:
            self._get_ansible_param_bool(obj, arg, value=CA_BOOL_VALUES[arg][1], value_false=CA_BOOL_VALUES[arg][0])

        self._get_ansible_param(obj, 'serial')

        return obj

    ##############################
    # XML processing
    #
    def _find_crl_for_ca(self, caref):
        result = self.root_elt.findall("crl[caref='{0}']".format(caref))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for caref {0}, you must specify crlname or crlrefid.'.format(caref))
        else:
            return None

    def _find_crl_by_name(self, crlname):
        result = self.root_elt.findall("crl[descr='{0}']".format(crlname))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for name {0}, you must specify crlrefid.'.format(crlname))
        else:
            return None

    def _find_crl_by_refid(self, crlrefid):
        result = self.root_elt.findall("crl[refid='{0}']".format(crlrefid))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for refid {0}.  This is an unsupported condition'.format(crlrefid))
        else:
            return None

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        self.root_elt.insert(self._find_last_element_index(), self.target_elt)
        if self.crl is not None:
            crl_elt = self.pfsense.new_element('crl')
            self.crl['caref'] = self.obj['refid']
            if 'refid' not in self.crl:
                self.crl['refid'] = self.pfsense.uniqid()
            self.pfsense.copy_dict_to_element(self.crl, crl_elt)
            self.diff['after']['crl'] = self.crl['text']
            self.pfsense.root.append(crl_elt)
            self.refresh_crls = True

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        (before, changed) = super(PFSenseCAModule, self)._copy_and_update_target()

        if self.crl is not None:
            crl_elt = None

            # If a crlrefid is specified, update it or create a new one with that refid
            if self.params['crlrefid'] is not None:
                crl_elt = self._find_crl_by_refid(self.params['crlrefid'])
                self.crl['refid'] = self.params['crlrefid']
            else:
                if self.params['crlname'] is not None:
                    crl_elt = self._find_crl_by_name(self.params['crlname'])
                if crl_elt is None:
                    crl_elt = self._find_crl_for_ca(self.target_elt.find('refid').text)

            if crl_elt is None:
                changed = True
                crl_elt = self.pfsense.new_element('crl')
                self.crl['caref'] = self.target_elt.find('refid').text
                if 'refid' not in self.crl:
                    self.crl['refid'] = self.pfsense.uniqid()
                self.pfsense.copy_dict_to_element(self.crl, crl_elt)
                # Add after the existing ca entry
                self.pfsense.root.insert(self._find_this_element_index() + 1, crl_elt)
                self.refresh_crls = True
            else:
                before['crl'] = crl_elt.find('text').text
                before['crlname'] = crl_elt.find('descr').text
                if 'crlname' not in self.crl:
                    self.crl['descr'] = before['crlname']
                before['crlrefid'] = crl_elt.find('refid').text
                if 'refid' not in self.crl:
                    self.crl['refid'] = before['crlrefid']
                if self.pfsense.copy_dict_to_element(self.crl, crl_elt):
                    changed = True
                    self.refresh_crls = True
            self.diff['after']['crl'] = self.crl['text']
            self.diff['after']['crlname'] = self.crl['descr']
            self.diff['after']['crlrefid'] = self.crl['refid']

        return (before, changed)

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            # ca_import will base64 encode the cert + key  and will fix 'caref' for CAs that reference each other
            # $ca needs to be an existing reference (particularly 'refid' must be set) before calling ca_import
            # key and serial are optional arguments.  TODO - handle key and serial
            (dummy, stdout, stderr) = self.pfsense.phpshell("""
                init_config_arr(array('ca'));
                $ca =& lookup_ca('{refid}');
                ca_import($ca, '{cert}');
                print_r($ca);
                print_r($config['ca']);
                write_config('Update CA reference');
                ca_setup_trust_store();""".format(refid=self.target_elt.find('refid').text,
                                                  cert=base64.b64decode(self.target_elt.find('crt').text.encode()).decode()))

            crl_stdout = ''
            crl_stderr = ''
            if self.refresh_crls:
                (dummy, crl_stdout, crl_stderr) = self.pfsense.phpshell("""
                    require_once("openvpn.inc");
                    openvpn_refresh_crls();
                    require_once("vpn.inc");
                    ipsec_configure();""")
                return (dummy, stdout + crl_stdout, stderr + crl_stderr)

            return (dummy, stdout + crl_stdout, stderr + crl_stderr)
        else:
            return ('', '', '')

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            crl_elt = self._find_crl_for_ca(self.target_elt.find('refid').text)
            self.elements.remove(self.target_elt)
            if crl_elt is not None:
                self.diff['before']['crl'] = crl_elt.find('text').text
                self.root_elt.remove(crl_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=PFSENSE_CA_ARGUMENT_SPEC,
        required_if=[
            ["state", "present", ["certificate"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseCAModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
