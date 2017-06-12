import ansible
from ansible import utils
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.utils.encrypt import do_encrypt

try:
    import passlib
except:
    raise AnsibleError("'passlib' is required to hash OS X passwords")

from passlib.handlers.pbkdf2 import Pbkdf2DigestHandler
from passlib.utils.binary import ab64_decode
from passlib.utils.compat import u
import passlib.utils.handlers as handlers
import passlib.hash


class pbkdf2_sha512_osx(Pbkdf2DigestHandler):
    """OS X SALTED-SHA512-PBKDF2 handler"""
    name = u('pbkdf2_sha512_osx')
    ident = u('$pbkdf2-sha512-osx$')
    settings_kwds = ("salt", "rounds")
    checksum_chars = handlers.HASH64_CHARS

    default_salt_size = 32  # required by OS X
    min_salt_size = default_salt_size
    max_salt_size = default_salt_size

    default_rounds = 35087  # default used by OS X 10.10.5
    min_rounds = default_rounds
    max_rounds = 0xffffffff
    rounds_cost = 'linear'

    _digest = 'sha512'
    checksum_size = 128  # required by OS X
    encoded_checksum_size = 171  # (128 * 4 + 2) // 3


passlib.hash.pbkdf2_sha512_osx = pbkdf2_sha512_osx


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=dict()):
        """
        Convert the "password" argument to a hashed password.
        Then call the actual module to do the work.
        """
        options = self._task.args.copy()
        if 'password' in options:
            plain = options['password']
            digest = 'pbkdf2_sha512_osx'
            kwargs = {}
            if 'salt' in options:
                kwargs['salt'] = ab64_decode(options['salt'])
            options['password'] = do_encrypt(plain, digest, **kwargs)
        return self._execute_module(
            module_name="osxpassword",
            module_args=options,
            task_vars=task_vars)


if __name__ == '__main__':
    hashed = do_encrypt('asdf', 'pbkdf2_sha512_osx')
    verify = pbkdf2_sha512_osx.verify('asdf', hashed)
    print('{"hashed":"%s","ok":"%s"}' % (hashed, verify))
