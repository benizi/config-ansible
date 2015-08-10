from ansible import utils
from ansible.runner.return_data import ReturnData

class ActionModule(object):
    def __init__(self, runner):
        self.runner = runner

    # in 2.0+?: def run(self, tmp=None, task_vars=dict()):
    def run(self, conn, tmp, module_name, module_args, inject, complex_args=None, **kwargs):
        '''Run pacman or aura as appropriate'''

        options = {}
        if complex_args:
            options.update(complex_args)
        options.update(utils.parse_kv(module_args))

        if self.runner.noop_on_check(inject):
            options['CHECKMODE'] = True

        name = options['name'] or None
        next_mod = 'pacman'
        aur_prefix = 'aur/'
        if name and name.startswith(aur_prefix):
            options['name'] = name.replace(aur_prefix, '', 1)
            next_mod = 'aura'

        return self.runner._execute_module(conn, tmp, next_mod, '', inject=inject, complex_args=options)
