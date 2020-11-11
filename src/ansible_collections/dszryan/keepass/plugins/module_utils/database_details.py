import os
from typing import Union, Literal

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
from ansible.utils.display import Display


class DatabaseDetails(object):
    location: os.PathLike
    password = None             # type: Union[AnsibleVaultEncryptedUnicode, None]
    transformed_key = None      # type: Union[AnsibleVaultEncryptedUnicode, None]
    keyfile = None              # type: Union[os.PathLike, None]
    profile = "uncached"        # type: Literal["uncached", "throughput"]
    updatable: False            # type: bool

    def __init__(self, display: Display, **entries):
        self.__dict__.update(entries)

        self.location = os.path.realpath(os.path.expanduser(os.path.expandvars(self.location)))
        if not os.path.isfile(self.location):
            raise AnsibleParserError(AnsibleError(u"could not find keepass database - %s" % self.location))
        display.vvv(u"Keepass: database found - %s" % self.location)

        if self.keyfile:
            self.keyfile = os.path.realpath(os.path.expanduser(os.path.expandvars(self.keyfile)))
            if not os.path.isfile(self.keyfile):
                raise AnsibleParserError(AnsibleError(u"could not find keyfile - %s" % self.keyfile))
            display.vvv(u"Keepass: keyfile found - %s" % self.keyfile)
