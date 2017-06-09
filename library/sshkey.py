#!/usr/bin/env python2
### TODO ^^^ wrong for anything but Arch Linux
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: sshkey
author: Benjamin R. Haskell
short_description: Create an SSH key pair
description:
    - Similar to the core user module, this is a more flexible way to create
      key pairs.
options:
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Does nothing, currently
    user:
        required: false
        default: current user
        description:
            - User for whom the key pair is being generated.  Used to determine
              the default filename and file permissions.
    bits:
        required: false
        default: 2048
        description:
            - Number of bits in SSH key.
    type:
        required: false
        default: rsa
        description:
            - Specify the type of SSH key to create.
    file:
        required: false
        aliases: [ "path" ]
        default: .ssh/id_rsa
        description:
            - Output path for private key.  If not an absolute path, it will be
              relative to the user's home directory.  Allows `~` and
              `~username` expansion.
    comment:
        required: false
        default: generated by Ansible on $HOSTNAME
        description:
            - Comment for the SSH key.
    passphrase:
        required: false
        description:
            - Passphrase for the SSH private key.  Default is to have no
              passphrase.
'''

EXAMPLES = '''
# Create a 2048-bit RSA key for user myuser
# Will end up in ~myuser/.ssh/id_rsa
- sshkey: user=myuser bits=2048 file=.ssh/id_rsa

# Create a 256-bit ECDSA key in /tmp/temporary.ecdsa.key
- sshkey: bits=256 type=ecdsa file=/tmp/temporary.ecdsa.key
'''

import grp
import os
import pwd
import socket

from ansible.module_utils.basic import *

class SSHKey(object):
    """
    TODO DOCS
    """

    def __init__(self, module):
        self.module = module
        self.state = module.params['state']
        self.bits = module.params['bits']
        self.type = module.params['type']
        self.comment = module.params['comment']
        self.passphrase = module.params['passphrase']

        if module.params['user'] is not None:
            self.user = module.params['user']
        else:
            self.user = pwd.getpwuid(os.getuid())[0]

        pw_info = pwd.getpwnam(self.user)
        self.uid = pw_info.pw_uid
        self.gid = pw_info.pw_gid

        if module.params['file'] is not None:
            self.path = module.params['file']
        else:
            self.path = os.path.expanduser(os.path.join('~%s' % self.user, '.ssh', 'id_%s' % self.type))

    def generate(self):
        # TODO - is this mkdir stuff necessary?
        ssh_dir = os.path.dirname(self.path)
        if not os.path.exists(ssh_dir):
            try:
                os.mkdir(ssh_dir, int('700', 8))
                os.chown(ssh_dir, self.uid, self.gid)
            except OSError as e:
                return (1, '', 'Failed to create %s: %s' % (ssh_dir, str(e)))

        if os.path.exists(self.path):
            return (None, 'Key already exists', '')

        cmd = [self.module.get_bin_path('ssh-keygen', True)]
        cmd.append('-t')
        cmd.append(self.type)
        cmd.append('-b')
        cmd.append(self.bits)
        cmd.append('-C')
        cmd.append(self.comment)
        cmd.append('-f')
        cmd.append(self.path)
        cmd.append('-N')
        if self.passphrase is not None:
            cmd.append(self.passphrase)
        else:
            cmd.append('')

        (rc, out, err) = self.run_unless_checking(cmd)

        if rc == 0:
            # If the keys were successfully created, we should be able
            # to tweak ownership.
            os.chown(self.path, self.uid, self.gid)
            os.chown('%s.pub' % self.path, self.uid, self.gid)

        return (rc, out, err)

    def fingerprint(self):
        if not os.path.exists(self.path):
            return (1, 'SSH Key file %s does not exist' % self.path, '')
        cmd = [ self.module.get_bin_path('ssh-keygen', True) ]
        cmd.append('-l')
        cmd.append('-f')
        cmd.append(self.path)

        return self.run_unless_checking(cmd)

    def public_key(self):
        public_key_file = '%s.pub' % self.path
        try:
            f = open(public_key_file)
            public_key = f.read().strip()
            f.close()
        except IOError:
            return None
        return public_key

    def run_unless_checking(self, cmd):
        if self.module.check_mode:
            return (None, '', '')

        return self.module.run_command(cmd, use_unsafe_shell=False, data=None)

def main():
    defaults = {
            'bits': '2048',
            'type': 'rsa',
            'passphrase': None,
            'comment': 'generated by Ansible on %s' % socket.gethostname()
    }
    module = AnsibleModule(
        argument_spec = dict(
            # TODO - need this? does this work for `absent`?
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            bits=dict(default=defaults['bits'], type='str'),
            type=dict(default=defaults['type'], type='str'),
            user=dict(default=None, type='str'),
            file=dict(default=None, aliases=['path'], type='str'),
            comment=dict(default=defaults['comment'], type='str'),
            passphrase=dict(default=None, type='str'),
        ),
        supports_check_mode=True
    )

    sshkey = SSHKey(module)

    result = {
            'state': sshkey.state,
            'ssh_key_file': sshkey.path,
    }

    (rc, out, err) = sshkey.generate()


    if module.check_mode:
        result['changed'] = not os.path.exists(sshkey.path)
        module.exit_json(**result)

    if rc is not None and rc != 0:
        module.fail_json(msg=err, rc=rc)
    if rc == 0:
        result['changed'] = True

    (rc, out, err) = sshkey.fingerprint()
    if rc == 0:
        result['ssh_fingerprint'] = out.strip()
    else:
        result['ssh_fingerprint'] = err.strip()
    result['ssh_public_key'] = sshkey.public_key()

    module.exit_json(**result)

main()
