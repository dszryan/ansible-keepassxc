# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Tuple, List, Optional

from ansible.module_utils.common.text.converters import to_native
from pykeepass.entry import Entry

from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery
from ansible_collections.dszryan.keepass.plugins.module_utils.request_term import RequestTerm


class EntryDump(object):
    def __init__(self, entry: Entry):
        self.title = entry.title                            # type: str
        self.path = entry.group.path                        # type: str
        self.username = entry.username                      # type: Optional[str]
        self.password = entry.password                      # type: Optional[str]
        self.url = entry.url                                # type: Optional[str]
        self.notes = entry.notes                            # type: Optional[str]
        self.custom_properties = entry.custom_properties    # type: dict
        self.attachments = [{"filename": attachment.filename, "length": len(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []    # type: list


class Result(object):
    def __init__(self, query: RequestQuery, warnings: List[str] = None):
        self.changed = False                                # type: bool
        self.failed = False                                 # type: bool
        self.query = query.__dict__                         # type: dict
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
