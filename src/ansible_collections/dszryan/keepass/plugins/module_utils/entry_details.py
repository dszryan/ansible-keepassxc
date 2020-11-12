# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from typing import Optional

from pykeepass.entry import Entry

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache


class EntryDetails(object):
    def __init__(self, entry: Entry, key_cache: Optional[KeepassKeyCache]):
        self.title = entry.title                                                                        # type: str
        self.path = entry.group.path.strip("/")                                                         # type: str
        self.username = entry.username                                                                  # type: Optional[str]
        self.password = key_cache.encrypt(entry.password) if entry.password and key_cache else None     # type: Optional[str]
        self.url = entry.url                                                                            # type: Optional[str]
        self.notes = entry.notes                                                                        # type: Optional[str]
        self.custom_properties = entry.custom_properties or {}                                          # type: dict
        self.attachments = [{"filename": attachment.filename, "length": len(attachment.binary)}
                            for index, attachment in enumerate(entry.attachments)] or []                # type: list
