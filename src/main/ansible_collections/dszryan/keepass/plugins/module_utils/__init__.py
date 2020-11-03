# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

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


class SearchResult(object):
    def __init__(self, search: Search):
        self.changed = False                    # type: bool
        self.failed = False                     # type: bool
        self.outcome = Outcome(search)          # type: Outcome


class Outcome(object):
    def __init__(self, search: Search):
        self.search = search                    # type: Search
        self.result = None                      # type: dict
