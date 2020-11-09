# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import inspect
import traceback
import uuid
from typing import List, Tuple, Union

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display
from pykeepass import PyKeePass
from pykeepass.attachment import Attachment
from pykeepass.entry import Entry
from pykeepass.group import Group

from ansible_collections.dszryan.keepass.plugins import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils import RequestQuery, EntryDump, Result
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache


class KeepassDatabase(object):
    def __init__(self, details: DatabaseDetails, key_cache: KeepassKeyCache, display: Display):
        self._display = display                                                             # type: Display
        self._warnings = []                                                                 # type: List[str]
        if not key_cache or not KeepassKeyCache.get_secrets(details):
            self._warnings.append("Your keepass secrets are in clear text, why use a key store?")
        self._database, self._location, self._is_updatable = \
            self._open(details, key_cache, display)                                         # type: [PyKeePass, str, bool]

    @staticmethod
    def _open(details: DatabaseDetails, key_cache: KeepassKeyCache, display) -> [PyKeePass, str, bool]:
        cached_transform_key = key_cache.get() if key_cache else None              # type Optional[bytes]
        if cached_transform_key:
            display.vv(u"Keepass: database REOPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, transformed_key=cached_transform_key)
        elif details.transformed_key:
            display.vv(u"Keepass: database QUICK OPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, transformed_key=details.transformed_key)
        else:
            display.vv(u"Keepass: database DEFAULT OPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, keyfile=details.keyfile, password=details.password)

        if key_cache and key_cache.can_cache and not cached_transform_key:
            key_cache.set(database.transformed_key)

        display.v(u"Keepass: database opened - %s" % details.location)
        return database, details.location, details.updatable

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
        self._display.v(u"Keepass: database saved - %s" % self._location)

    def _entry_find(self, query: RequestQuery, ref_uuid=None, not_found_throw=True) -> Union[Entry, None]:
        entry = self._database.find_entries_by_path(path=query.path, first=True) if ref_uuid is None else self._database.find_entries_by_uuid(uuid=ref_uuid, first=True)
        if entry is None:
            self._display.vv(u"KeePass: entry%s NOT found - %s" % ("" if ref_uuid is None else " (and its reference)", query))
            if not_found_throw:
                raise AnsibleError(u"Entry is not found")
            else:
                return None
        self._display.vv(u"KeePass: entry%s found - %s" % ("" if ref_uuid is None else " (and its reference)", query))
        return entry

    def _entry_upsert(self, query: RequestQuery, check_mode: bool) -> Tuple[bool, dict]:
        entry = self._entry_find(query, not_found_throw=False)
        if query.action == "post" and entry is not None:
            raise AttributeError(u"Invalid request - cannot post/insert when entry exists")

        path_split = (entry.path if entry is not None else query.path).rsplit("/", 1)
        title = path_split if len(path_split) == 1 else path_split[1]
        group_path = "/" if len(path_split) == 1 else path_split[0]

        destination_group: Group = self._database.find_groups(path=group_path, regex=False, first=True)
        if not check_mode and destination_group is None:
            previous_group: Group = self._database.root_group
            for path in group_path.split("/"):
                found_group: Group = self._database.find_groups(path=(previous_group.path + path), regex=False, first=True)
                previous_group = found_group if found_group is not None else self._database.add_group(previous_group, path)
            destination_group = previous_group

        search_value = dict(query.value)
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
                        entry_attachment_item: Union[Attachment, None] = \
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
            return True, EntryDump(self._entry_find(query)).__dict__
        else:
            return False, (EntryDump(entry).__dict__ if entry is not None else None)

    def get(self, query: RequestQuery, check_mode=False) -> Tuple[bool, dict]:
        entry = self._entry_find(query)
        if query.field is None:
            return False, EntryDump(entry).__dict__

        # get entry value
        result = getattr(entry, query.field, None) or \
                 entry.custom_properties.get(query.field, None) or \
                 ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query.field] or [None])[0] or \
                 (query.value if not check_mode and query.value is not None else None)

        # get reference value
        if query.field in ["title", "username", "password", "url", "notes", "uuid"] and \
                hasattr(result, "startswith") and result.startswith("{REF:"):
            entry = self._entry_find(query, uuid.UUID(result.split(":")[2].strip("}")))
            result = getattr(entry, query.field, (None if check_mode else query.value))

        if result is not None or (not check_mode and query.value is not None):
            self._display.vv(u"KeePass: found property/file on entry - %s" % query)
            return False, {"result": (base64.b64encode(result.binary) if hasattr(result, "binary") else result)}

        # throw error, value not found
        raise AttributeError(u"No property/file found")

    def post(self, query: RequestQuery, check_mode=False) -> Tuple[bool, dict]:
        return self._entry_upsert(query, check_mode)

    def put(self, query: RequestQuery, check_mode=False) -> Tuple[bool, dict]:
        return self._entry_upsert(query, check_mode)

    def delete(self, query: RequestQuery, check_mode=False) -> Tuple[bool, dict]:
        entry = self._entry_find(query, not_found_throw=True)
        if query.field is None:
            self._database.delete_entry(entry) and not check_mode
        elif hasattr(entry, query.field):
            setattr(entry, query.field, ("" if query.field in ["username", "password"] else None)) and not check_mode
        elif query.field in entry.custom_properties.keys():
            entry.delete_custom_property(query.field) and not check_mode
        else:
            attachment = ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query.field] or [None])[0]
            if attachment is not None:
                entry.delete_attachment(attachment) and not check_mode
            else:
                raise AttributeError(u"No property/file found")

        self._save() and not check_mode
        return True, (None if query.field is None else EntryDump(self._entry_find(query, not_found_throw=True)).__dict__)

    def execute(self, query: RequestQuery, check_mode: bool, fail_silently: bool) -> dict:
        self._display.vvv(u"Keepass: execute - %s" % list(({key: to_native(value)} for key, value in inspect.currentframe().f_locals.items() if key != "self" and not key.startswith("__"))))
        result = Result(query, self._warnings)
        try:
            if not self._is_updatable and query.action != "get":
                raise AttributeError(u"Invalid request - database is not 'updatable'")
            result.success(getattr(self, query.action.replace("del", "delete"))(query, check_mode))
        except Exception as error:
            if not fail_silently:
                raise AnsibleParserError(AnsibleError(message=traceback.format_exc(), orig_exc=error))
            result.fail((traceback.format_exc(), error))
        return result.__dict__
