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
    from base64 import b64decode
    from os import environ
    from json import dumps

    # TODO: is this in stdlib somewhere?
    def slice(dict, *keys):
        return {key: dict[key] for key in keys if key in dict}

    def results(hash, ok):
        r = slice(locals(), 'hash', 'ok')
        part_names = ['blank', 'algo', 'rounds', 'salt', 'entropy']
        r.update(dict(zip(part_names, hash.split('$'))))
        return r

    digest = pbkdf2_sha512_osx
    static_password = 'asdf'
    predefined_salt = b64decode('RKi19p7zfs/5PyeEsNaaEwJAaE2pFaJ0rpWydk7J2bs=')
    env_pass = environ.get('password')
    env_hash = environ.get('hash')

    tests = dict(ok={})

    def do_test(name, password, hashed=None, salt=None):
        if not hashed:
            kwargs = {'salt':salt} if salt else {}
            hashed = do_encrypt(password, digest.name, **kwargs)
        ok = digest.verify(password, hashed)
        tests[name] = results(hashed, ok)
        tests['ok'][name] = ok

    # Use a static password
    do_test('static_pre', static_password, salt=predefined_salt)
    do_test('static_rand', static_password)

    # Try the password passed in env vars
    if env_pass:
        do_test('env_pre', env_pass, salt=predefined_salt)
        do_test('env_rand', env_pass)

    # Try the password and hash passed in env vars
    if env_pass and env_hash:
        do_test('env_env', env_pass, hashed=env_hash)

    print(dumps(tests))
