# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from base64 import b64encode
from typing import Optional

from pykeepass.entry import Entry


class EntryDetails(object):
    def __init__(self, entry: Entry, include_files: bool = False):
        self.uuid = entry.uuid.__str__()                                                                    # type: str
        self.title = entry.title                                                                            # type: str
        self.path = entry.group.path.strip("/")                                                             # type: str
        self.username = entry.username                                                                      # type: Optional[str]
        self.password = entry.password                                                                      # type: Optional[str]
        self.url = entry.url                                                                                # type: Optional[str]
        self.notes = entry.notes                                                                            # type: Optional[str]
        self.custom_properties = entry.custom_properties or {}                                              # type: dict
        self.attachments = [{"filename": attachment.filename,
                             "length": len(attachment.binary),
                             "binary": b64encode(attachment.binary).decode() if include_files else None}
                            for index, attachment in enumerate(entry.attachments)] or []                    # type: list
