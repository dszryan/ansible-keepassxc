# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import os
import traceback
import uuid
from typing import Tuple, Union, AnyStr

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display
from pykeepass import PyKeePass
from pykeepass.attachment import Attachment
from pykeepass.entry import Entry
from pykeepass.group import Group

from ansible_collections.dszryan.keepass.plugins.module_utils.search import Search


class EntryDump(object):
    def __init__(self, entry: Entry):
        self.title = entry.title            # type: str
        self.path = entry.group.path        # type: str
        self.username = entry.username      # type: str
        self.password = entry.password      # type: str
        self.url = entry.url                # type: str
        self.notes = entry.notes            # type: str
        self.custom_properties = entry.custom_properties    # type: dict
        self.attachments = [{"filename": attachment.filename, "length": len(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []    # type: list


class SearchResult(object):
    def __init__(self, search: Search):
        self.changed = False            # type: bool
        self.failed = False             # type: bool
        self.outcome = Outcome(search)  # type: Outcome


class Outcome(object):
    def __init__(self, search: Search):
        self.search = search    # type: Search
        self.result = None      # type: dict


class KeepassDatabase(object):
    def __init__(self, display: Display, details: dict):
        self._display = display                                         # type: Display
        self.location = os.path.abspath(os.path.expanduser(os.path.expandvars(details.get("location", None))))  # type: AnyStr
        self.keyfile = os.path.abspath(os.path.expanduser(os.path.expandvars(details.get("keyfile", None))))    # type: AnyStr
        self.password = details.get("password", None)                   # type: str
        self.transformed_key = details.get("transformed_key", None)     # type: str
        self.is_updatable = details.get("updatable", False)             # type: bool
        self._database = self._open()                                   # type: PyKeePass

    def _open(self) -> PyKeePass:
        if not os.path.isfile(self.location):
            raise AnsibleParserError(u"could not find keepass database - %s" % self.location)
        self._display.v(u"Keepass: database found - %s" % self.location)
        if self.keyfile is not None:
            if not os.path.isfile(self.keyfile):
                raise AnsibleParserError(u"could not find keyfile - %s" % self.keyfile)
            self._display.vvv(u"Keepass: keyfile found - %s" % self.keyfile)

        database = PyKeePass(
            filename=self.location,
            password=self.password,
            keyfile=self.keyfile,
            transformed_key=self.transformed_key)
        self._display.v(u"Keepass: database opened - %s" % self.location)

        return database

    # noinspection PyBroadException
    @staticmethod
    def _get_binary(possibly_base64_encoded) -> Tuple[bytes, bool]:
        return_value, was_encoded = (None, None)
        try:
            binary_stream = base64.b64decode(possibly_base64_encoded)
            if base64.b64encode(binary_stream) == possibly_base64_encoded:
                return_value, was_encoded = binary_stream, True
        except Exception:
            return_value, was_encoded = (str(possibly_base64_encoded).encode() if isinstance(possibly_base64_encoded, str) else bytes(possibly_base64_encoded), False)
        return return_value, was_encoded

    def _save(self):
        self._database.save()
        self._display.v(u"Keepass: database saved - %s" % self.location)

    def _entry_find(self, search: Search, ref_uuid=None, not_found_throw=True) -> Entry:
        entry = self._database.find_entries_by_path(path=search.path, first=True) if ref_uuid is None else self._database.find_entries_by_uuid(uuid=ref_uuid, first=True)
        if entry is None:
            self._display.vv(u"KeePass: entry%s NOT found - %s" % ("" if ref_uuid is None else " (and its reference)", search))
            if not_found_throw:
                raise AnsibleError(u"Entry is not found")
            else:
                return None
        self._display.vv(u"KeePass: entry%s found - %s" % ("" if ref_uuid is None else " (and its reference)", search))
        return entry

    def _entry_upsert(self, search: Search, check_mode: bool) -> Tuple[bool, Union[EntryDump, None]]:
        entry = self._entry_find(search, not_found_throw=False)
        if search.action == "post" and entry is not None:
            raise AttributeError(u"Invalid query - cannot post/insert when entry exists")

        path_split = (entry.path if entry is not None else search.path).rsplit("/", 1)
        title = path_split if len(path_split) == 1 else path_split[1]
        group_path = "/" if len(path_split) == 1 else path_split[0]

        destination_group: Group = self._database.find_groups(path=group_path, regex=False, first=True)
        if not check_mode and destination_group is None:
            previous_group: Group = self._database.root_group
            for path in group_path.split("/"):
                found_group: Group = self._database.find_groups(path=(previous_group.path + path), regex=False, first=True)
                previous_group = found_group if found_group is not None else self._database.add_group(previous_group, path)
            destination_group = previous_group

        search_value = dict(search.value)
        entry_is_created, entry_is_updated = (False, False)
        if not check_mode:
            if entry is None:
                entry: Entry = self._database.add_entry(
                    destination_group=destination_group,
                    title=title,
                    username=search_value.get("username", ""),
                    password=search_value.get("password", ""),
                    url=search_value.get("url", None),
                    notes=search_value.get("notes", None),
                    expiry_time=search_value.get("expiry_time", None),
                    tags=search_value.get("tags", None),
                    force_creation=False)
                list(map(lambda dict_key: search_value.pop(dict_key, None), ["username", "password", "url", "notes", "expiry_time", "tags"]))
                entry_is_created = True

            for (key, value) in search_value.items():
                if key == "attachments":
                    entry_attachments = entry.attachments
                    for item in value:
                        filename = item["filename"]
                        binary, was_encoded = KeepassDatabase._get_binary(item["binary"])
                        entry_attachment_item: Attachment = \
                            ([attachment for index, attachment in enumerate(entry_attachments) if attachment.filename == filename] or [None])[0]
                        if entry_attachment_item is None or entry_attachment_item.binary != binary:
                            if not (entry_is_updated or entry_is_created):
                                entry.save_history()
                            if entry_attachment_item is not None:
                                self._database.delete_binary(entry_attachment_item.id)
                            entry.add_attachment(self._database.add_binary(binary), filename)
                            entry_is_updated = True
                elif hasattr(entry, key):
                    if getattr(entry, key, None) != value or (key in ["username", "password"] and getattr(entry, key, "") != ("" if value is None else value)):
                        if not (entry_is_updated or entry_is_created):
                            entry.save_history()
                        setattr(entry, key, value)
                        entry_is_updated = True
                elif key not in entry.custom_properties.keys() or entry.custom_properties.get(key, None) != value:
                    if not (entry_is_updated or entry_is_created):
                        entry.save_history()
                    entry.set_custom_property(key, value)
                    entry_is_updated = True

        if not check_mode and (entry_is_created or entry_is_updated):
            if not entry_is_created:
                entry.touch(True)
            self._save()
            return True, EntryDump(self._entry_find(search))
        else:
            return False, (EntryDump(entry) if entry is not None else None)

    def get(self, search: Search, check_mode=False) -> Tuple[bool, Union[EntryDump, AnyStr, None]]:
        entry = self._entry_find(search)
        if search.field is None:
            return False, EntryDump(entry)

        # get entry value
        result = getattr(entry, search.field, None) or \
            entry.custom_properties.get(search.field, None) or \
            ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == search.field] or [None])[0] or \
            (search.value if not check_mode and search.value_was_provided else None)

        # get reference value
        if search.field in ["title", "username", "password", "url", "notes", "uuid"]:
            if hasattr(result, "startswith") and result.startswith("{REF:"):
                entry = self._entry_find(search, uuid.UUID(result.split(":")[2].strip("}")))
                result = getattr(entry, search.field, (None if check_mode else search.value))

        # return result
        if result is not None or (not check_mode and search.value_was_provided):
            self._display.vv(u"KeePass: found property/file on entry - %s" % search)
            return False, (base64.b64encode(result.binary) if hasattr(result, "binary") else result)

        # throw error, value not found
        raise AttributeError(u"No property/file found")

    def post(self, search: Search, check_mode=False) -> Tuple[bool, Union[EntryDump, None]]:
        return self._entry_upsert(search, check_mode)

    def put(self, search: Search, check_mode=False) -> Tuple[bool, Union[EntryDump, None]]:
        return self._entry_upsert(search, check_mode)

    def delete(self, search: Search, check_mode=False) -> Tuple[bool, Union[EntryDump, None]]:
        entry = self._entry_find(search, not_found_throw=True)
        if search.field is None:
            self._database.delete_entry(entry) and not check_mode
        elif hasattr(entry, search.field):
            setattr(entry, search.field, ("" if search.field in ["username", "password"] else None)) and not check_mode
        elif search.field in entry.custom_properties.keys():
            entry.delete_custom_property(search.field) and not check_mode
        else:
            attachment = ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == search.field] or [None])[0]
            if attachment is not None:
                entry.delete_attachment(attachment) and not check_mode
            else:
                raise AttributeError(u"No property/file found")

        self._save() and not check_mode
        return True, (None if search.field is None else EntryDump(self._entry_find(search, not_found_throw=True)))

    def execute(self, search: Search, check_mode: bool, fail_silently: bool) -> SearchResult:
        search_result = SearchResult(search)
        try:
            if not self.is_updatable and search.action != "get":
                raise AttributeError(u"Invalid query - database is not 'updatable'")

            search_result.changed, search_result.outcome.result = \
                getattr(self, search.action.replace("del", "delete"))(search, check_mode)
        except Exception as error:
            search_result.failed = True
            search_result.outcome.result = {
                "traceback": traceback.format_exc(),
                "error": to_native(error)
            }

            if not fail_silently:
                raise AnsibleParserError(AnsibleError(message=traceback.format_exc(), orig_exc=error))

        return search_result
