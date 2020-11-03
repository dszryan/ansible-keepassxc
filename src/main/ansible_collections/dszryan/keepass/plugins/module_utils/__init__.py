# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Tuple

from ansible.module_utils.common.text.converters import to_native
from pykeepass.entry import Entry

from ansible_collections.dszryan.keepass.plugins.module_utils.search import Search


class EntryDump(object):
    def __init__(self, entry: Entry):
        self.title = entry.title                # type: str
        self.path = entry.group.path            # type: str
        self.username = entry.username          # type: str
        self.password = entry.password          # type: str
        self.url = entry.url                    # type: str
        self.notes = entry.notes                # type: str
        self.custom_properties = entry.custom_properties    # type: dict
        self.attachments = [{"filename": attachment.filename, "length": len(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []    # type: list


class Outcome(object):
    def __init__(self, search_value: Search):
        self.changed = False                                                # type: bool
        self.failed = False                                                 # type: bool
        self.outcome = {"search": search_value.__dict__, "result": None}    # type: dict

    def success(self, outcome: Tuple[bool, dict]):
        self.changed = outcome[0]
        self.outcome["result"] = outcome[1]

    def failure(self, outcome: Tuple[str, Exception]):
        self.failed = True
        self.outcome["result"] = {
            "trace": outcome[0],
            "error": to_native(outcome[1])
        }

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
