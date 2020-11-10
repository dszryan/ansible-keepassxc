# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from typing import Union, Literal, List, Tuple, Optional

from ansible.errors import AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
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
            raise AnsibleParserError(u"could not find keepass database - %s" % self.location)
        display.vvv(u"Keepass: database found - %s" % self.location)

        if self.keyfile:
            self.keyfile = os.path.realpath(os.path.expanduser(os.path.expandvars(self.keyfile)))
            if not os.path.isfile(self.keyfile):
                raise AnsibleParserError(u"could not find keyfile - %s" % self.keyfile)
            display.vvv(u"Keepass: keyfile found - %s" % self.keyfile)


class EntryDump(object):
    def __init__(self, entry):
        self.title = entry.title                            # type: str
        self.path = entry.group.path                        # type: str
        self.username = entry.username                      # type: Optional[str]
        self.password = entry.password                      # type: Optional[str]
        self.url = entry.url                                # type: Optional[str]
        self.notes = entry.notes                            # type: Optional[str]
        self.custom_properties = entry.custom_properties    # type: dict
        self.attachments = [{"filename": attachment.filename, "length": len(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []    # type: list


class Result(object):
    def __init__(self, query: dict, warnings: List[str] = None):
        self.changed = False                                # type: bool
        self.failed = False                                 # type: bool
        self.query = query                                  # type: dict
        if warnings and len(warnings) > 0:
            self.warnings = warnings

    def success(self, result: Tuple[bool, dict]):
        self.changed = result[0]
        setattr(self, "stdout", result[1])

    def fail(self, result: Tuple[str, Exception]):
        self.failed = True
        setattr(self, "stderr", {
            "trace": to_native(result[0]),
            "message": to_native(result[1])
        })

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
