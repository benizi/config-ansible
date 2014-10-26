# config-ansible

Initial attempt at Ansible playbooks for my local machines.  This is very
idiosyncratic, and probably doesn't make sense for anyone else's setup:
    - Assumes Arch Linux for the `[laptops]` (main) group
    - Uses [my dotfiles](https://github.com/benizi/dotfiles)
    - Installs [my custom `rxvt-unicode`](https://github.com/benizi/rxvt-unicode)
    - Configures XMonad

# TODO

Currently, this is way too monolithic:

- [`00-initial.yml`](00-initial.yml):
    - stuff that needs to be set up for passwordless sudo
    - add host via IP to `hosts` in the `[initial]` section
    - run as: `ansible-playbook -i hosts 00-initial.yml`

- [`site.yml`](site.yml):
    - everything else
    - right now, just everything needed to get a new laptop up
