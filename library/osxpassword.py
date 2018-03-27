#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: osxpassword
author: Benjamin R. Haskell
short_description: Set a user's password on OS X given a password hash
description:
    - The user module has the caveat for the password parameter that:
      """
      Note on Darwin system, this value has to be cleartext.
      Beware of security issues.
      """
      You don't say...
options:
    password:
        required: true
        description:
            - The password hash to use.
    user:
        required: false
        default: current user
        description:
            - User for whom the hashed password is being stored/extracted.
    salt:
        required: false
        default: extracted from password
        description:
            - The Base64-encoded salt value.  Will be taken from the password
              if not explicitly provided.
'''

EXAMPLES = '''
# TODO
'''

import base64
from os import fdopen, getuid, path, unlink
from pwd import getpwuid
from subprocess import Popen, PIPE
from tempfile import mkstemp
import textwrap

from ansible.module_utils.basic import AnsibleModule


class Dict(dict):
    """Super-simple "keys-are-attributes" dictionary object"""

    def __init__(self, **kwargs):
        self.__dict__ = kwargs


class OSXPassword(object):
    """
    TODO DOCS
    """

    passlib_hash_name = 'pbkdf2-sha512-osx'
    osx_hash_name = 'SALTED-SHA512-PBKDF2'
    osx_iterations = 35087
    osx_entropy_len = 128
    osx_salt_len = 32

    def __init__(self, module):
        self.module = module
        self.password = module.params['password']
        self.salt = module.params['salt']
        self.user = module.params['user'] or getpwuid(getuid())[0]

    def validate(self, pw, *properties):
        invalid = []
        for prop in properties:
            _, actual, expected = prop
            if actual != expected:
                invalid += [prop]
        if len(invalid) == 0:
            return
        lines = ["Invalid password hash: [%s]" % pw]
        lines += ["Invalid %s: expected [%s] got [%s]" % i for i in invalid]
        self.module.fail_json(msg="\n".join(lines))

    def parse_hash(self):
        ## E.g.: when split on '$': [
        # '',
        # 'pbkdf2-sha512-osx',
        # '35087',
        # 'FMJYay2l1FqL8d6bM8b4n7NW6h3DWIvx3ptT6p3TWgs',
        # 'gd6Oj0CYSUsUwBnZBOyJa/KOAFOoDV8zMju5DWGC7FvweEcVofIPi7Mb5zodsDuh.3QpeOgIBdQjiTP4YGAFaYVCFA7T.sp9kXFJCmoNd7DDHy/CPDpqJy7SZF5TwUhHjKyCJM/KKhTvPWQygfds9CAGiClxqJFQKWbydof4tIk',
        # ]
        pw = self.password
        blank, algo, iter_str, salt64, hash64 = pw.split('$')
        entropy = self.b64decode(hash64)
        iterations = int(iter_str)
        salt = self.b64decode(salt64)

        expectations = [
            ('leading blank', '', blank),
            ('hash type', self.passlib_hash_name, algo),
            ('entropy length', self.osx_entropy_len, len(entropy)),
            ('salt length', self.osx_salt_len, len(salt)),
            ('iterations', self.osx_iterations, iterations),
        ]

        self.validate(pw, *expectations)

        return Dict(entropy=entropy, iterations=iterations, salt=salt)

    def b64decode(self, data):
        add = '=' * (-len(data) % 4)
        return base64.b64decode(data + add, './')

    def b64encode(self, data):
        return base64.b64encode(data, '+/')

    def modify_hash(self, xml, key, data):
        path = '.'.join([self.osx_hash_name, key])
        encoded = self.b64encode(data)
        cmd = ['plutil', '-replace', path, '-data', encoded, '-o', '-', '-']
        return self.run_or_die(cmd, data=xml)

    def shadow_data_plist(self):
        # ## This works to create a password, AFAICT
        # printf '{"SALTED-SHA512-PBKDF2":{"entropy":"","iterations":35087,"salt":""}}' |
        # plutil -convert xml1 -o - - |
        # plutil -replace SALTED-SHA512-PBKDF2.entropy -data "$(printf %s 'pizza'{,}{,,,}{,,,} | openssl base64 -e -A)" -o - - |
        # plutil -replace SALTED-SHA512-PBKDF2.salt -data "$(printf %s xyzabc | openssl base64 -e -A)" -o - - |
        # plutil -convert binary1 -o - - |
        # openssl base64 -e -A

        # The "iterations" key can be present from the start, since it's an
        # -int value.  The other two have to be merged in, since they're -data
        # values (not representable by the .plist JSON format).
        parsed = self.parse_hash()
        start = Dict(entropy='', iterations=parsed.iterations, salt='')
        wrapped = self.module.jsonify({self.osx_hash_name: start})
        to_xml = ['plutil', '-convert', 'xml1', '-o', '-', '-']
        out = self.run_or_die(to_xml, data=wrapped)
        out = self.modify_hash(out, 'entropy', parsed.entropy)
        out = self.modify_hash(out, 'salt', parsed.salt)
        return out

    def store(self):
        data = self.shadow_data_plist()
        to_binary = ['plutil', '-convert', 'binary1', '-o', '-', '-']
        out = self.run_or_die(to_binary, data=data)

        shadow_hash64 = base64.b64encode(out)
        sep_chars = "\n\\:,"
        recordsep, _, fieldsep, _ = sep_chars
        separators = ' '.join(["0x%02X" % ord(x) for x in sep_chars])
        user = self.user
        recordtype = 'dsRecTypeStandard:Users'
        fields = [
            'dsAttrTypeStandard:RecordName',
            'base64:dsAttrTypeNative:ShadowHashData',
        ]
        header = ' '.join([separators, recordtype, str(len(fields))] + fields)
        record = user + fieldsep + shadow_hash64
        dsimport_file = header + recordsep + record + recordsep

        tmpfd, temp_filename = mkstemp()
        tmp = fdopen(tmpfd, 'w')
        tmp.write(dsimport_file + recordsep)
        tmp.close()

        delete = ['dscl', '.', 'delete', '/Users/%s' % user, 'ShadowHashData']
        dsimport = ['dsimport', temp_filename, '/Local/Default', 'A']

        out = self.run_or_die(delete)
        out = self.run_or_die(dsimport)
        try:
            unlink(temp_filename)
        except:
            pass # TODO: error msg?
        return (rc, out, err)

    def run(self, cmd, data=None):
        kwargs = dict(use_unsafe_shell=False)
        if data:
            kwargs['data'] = data
        return self.module.run_command(cmd, **kwargs)

    def run_or_die(self, cmd, data=None):
        (rc, out, err) = self.run(cmd, data)
        if rc != 0:
            lines = ["Failed to run %s (rc=%d)" % (repr(cmd), rc)]
            if data:
                lines += ["With data %s" % repr(data)]
            msg = "\n".join(lines)
            self.module.fail_json(msg=msg, rc=rc, out=out, err=err)
        return out

    def run_unless_checking(self, cmd):
        if self.module.check_mode:
            return (None, '', '')

        return self.module.run_command(cmd, use_unsafe_shell=False, data=None)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            password=dict(default=None, type='str', no_log=True),
            user=dict(default=None, type='str'),
            salt=dict(default=None, type='str'),
        ),
        supports_check_mode=True)
    osxpassword = OSXPassword(module)
    out = osxpassword.store()
    module.exit_json(out=out)


if __name__ == '__main__':
    main()
