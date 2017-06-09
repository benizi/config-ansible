#!/usr/bin/python
# -*- coding: utf-8 -*-
import ansible.modules.system.user as user

class MacOSXUser(user.DarwinUser):
    """
    Extend the DarwinUser class to handle passwords properly, you idiots.

    Also, due to the fact that most of the User module is implemented as a ball
    of terrible procedural code in lib/ansible/modules/system/user.py#main(),
    and the User module has a bajillion module arguments (*cough* maybe someone
    should have realized the ssh_key_ arguments indicated the need for a
    separate module *cough*), I'm not going to reimplement the whole damn
    thing.  Instead I'm going to completely abuse the existing main() and
    repurpose the following two keys:

    login_class = "crypted"
    ssh_key_passphrase = crypted_password
    """
    distribution = 'MacOSX'

    def __init__(self, module):
        # config key to use to convey desire to use crypted password:
        flag_key = 'login_class'
        # value that indicates 'yes':
        flag_yes = 'crypted'
        # config key in which to pass the salted password hash:
        pass_key = 'ssh_key_passphrase'

        self.crypted_password = None
        if module.params.get(flag_key, None) == flag_yes:
            module.params[flag_key] = None
            try:
                self.crypted_password = module.params[pass_key]
            except KeyError:
                raise Error('WTF, need to fill in %s with %s=%s' % (
                    pass_key, flag_key, flag_yes))

        super(user.DarwinUser, self).__init__(module)
        self.module.debug('HEREIAM - using MacOSXUser module')

    def _change_user_password(self):
        """
        Change password using the supplied password_hash

        Password hash must be hashed using passlib's pbkdf2_sha512
        """
        # TODO(bhaskell): no idea whether that's the only hash that works, but
        # I'm not positive how to specify other hashing algorithms in the
        # constructed .plist data
        raise Error('WTF, hereiam')

if __name__ == '__main__':
    user.main()
