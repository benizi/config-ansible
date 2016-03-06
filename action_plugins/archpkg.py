from ansible import utils
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=dict()):
        '''Run pacman or aura as appropriate'''

        options = self._task.args.copy()

        if self._play_context.check_mode:
            options['_ansible_check_mode'] = True

        name = options['name'] or None
        next_mod = 'pacman'
        aur_prefix = 'aur/'
        if name and name.startswith(aur_prefix):
            options['name'] = name.replace(aur_prefix, '', 1)
            next_mod = 'aura'

        return self._execute_module(module_name=next_mod, module_args=options, task_vars=task_vars)
