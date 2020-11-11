# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import inspect
import traceback
import uuid
from os import PathLike
from typing import List, Tuple, Union, Optional, AnyStr

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display

from ansible_collections.dszryan.keepass.plugins.module_utils.database_details import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.entry_details import EntryDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache
from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery
from ansible_collections.dszryan.keepass.plugins.module_utils.request_result import RequestResult

# noinspection PyBroadException
try:
    PYKEEPASS_IMP_ERR = None
    from pykeepass import PyKeePass
    from pykeepass.attachment import Attachment
    from pykeepass.entry import Entry
    from pykeepass.group import Group
except Exception as import_error:
    PYKEEPASS_IMP_ERR = traceback.format_exc()
    PYKEEPASS_IMP_EXP = import_error


class KeepassDatabase(object):
    _warnings = []           # type: List
    _display: Display
    _key_cache: Optional[KeepassKeyCache]
    _database: PyKeePass
    _location: PathLike
    _is_updatable: bool

    def __init__(self, display: Display, details: DatabaseDetails, key_cache: Optional[KeepassKeyCache]):
        if PYKEEPASS_IMP_ERR:
            raise AnsibleParserError(AnsibleError(message=PYKEEPASS_IMP_ERR, orig_exc=PYKEEPASS_IMP_EXP))
        self._display = display
        self._key_cache = key_cache
        self._database, self._location, self._is_updatable = self._open(details, key_cache)

    def _open(self, details: DatabaseDetails, key_cache: KeepassKeyCache) -> Tuple[PyKeePass, PathLike, bool]:
        cached_transform_key = None
        if key_cache:
            if not key_cache.has_secrets:
                self._warnings.append("Your keepass secrets are in clear text, why use a key store?")
            elif key_cache.can_cache:
                cached_transform_key = key_cache.get()                          # type Optional[bytes]

        if cached_transform_key:
            self._display.vv(u"Keepass: database REOPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, transformed_key=cached_transform_key)
        elif details.transformed_key:
            self._display.vv(u"Keepass: database QUICK OPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, transformed_key=details.transformed_key)
        else:
            self._display.vv(u"Keepass: database DEFAULT OPEN - %s" % details.location)
            database = PyKeePass(filename=details.location, keyfile=details.keyfile, password=details.password)

        if key_cache and key_cache.can_cache and not cached_transform_key:
            key_cache.set(database.transformed_key)

        self._display.v(u"Keepass: database opened - %s" % details.location)
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

    def _entry_find(self, not_found_throw: bool, **arguments) -> Optional[Entry]:
        if arguments.get("path", None) is not None:
            arguments["group"] = self._database.find_groups(path=arguments["path"], first=True)
            arguments.pop("path")

        self._display.vv(u'KeePass: {"query": %s}' % arguments)
        find_result = self._database.find_entries(**arguments)

        if find_result is None:
            self._display.vv(u'KeePass: entry NOT found - {"query": %s}' % arguments)
            if not_found_throw:
                raise AnsibleError(u"Entry is not found")
            else:
                return None
        self._display.vv(u'KeePass: entry found - {"query": %s}' % arguments)
        return find_result

    def _entry_upsert(self, query: RequestQuery, check_mode: bool) -> Tuple[bool, Optional[dict]]:
        entry = self._entry_find(not_found_throw=False, first=True, **query.arguments)
        if query.action == "post" and not entry:
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
            fetched_entry = self._entry_find(not_found_throw=True, first=True, **query.arguments)
            return True, EntryDetails(fetched_entry, self._key_cache).__dict__
        elif entry:
            return (check_mode or entry_is_created or entry_is_updated), EntryDetails(entry, self._key_cache).__dict__
        else:
            return (check_mode or entry_is_created or entry_is_updated), None

    def get(self, query: RequestQuery, check_mode: bool = False) -> Tuple[bool, Union[list, dict, AnyStr, None]]:
        entry = self._entry_find(not_found_throw=True, **query.arguments)
        if not query.field:
            if not entry:
                return False, {}
            elif isinstance(entry, list):
                return False, list(map(lambda item: EntryDetails(item, self._key_cache).__dict__, entry))
            else:
                return False, EntryDetails(entry, self._key_cache).__dict__

        # get entry value
        result = getattr(entry, query.field, None) or \
                 entry.custom_properties.get(query.field, None) or \
                 ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query.field] or [None])[0] or \
                 (query.value if not check_mode and query.value is not None else None)

        # get reference value
        if query.field in ["title", "username", "password", "url", "notes", "uuid"] and \
                hasattr(result, "startswith") and result.startswith("{REF:"):
            entry = self._entry_find(not_found_throw=True, first=True, uuid=uuid.UUID(result.split(":")[2].strip("}")))
            result = getattr(entry, query.field, (None if check_mode else query.value))

        if result is not None or (not check_mode and query.value is not None):
            self._display.vv(u"KeePass: found property/file on entry - %s" % query)
            return False, (base64.b64encode(result.binary) if hasattr(result, "binary") else result)

        # throw error, value not found
        raise AttributeError(u"No property/file found")

    def post(self, query: RequestQuery, check_mode: bool = False) -> Tuple[bool, dict]:
        return self._entry_upsert(query, check_mode)

    def put(self, query: RequestQuery, check_mode: bool = False) -> Tuple[bool, dict]:
        return self._entry_upsert(query, check_mode)

    def delete(self, query: RequestQuery, check_mode: bool = False) -> Tuple[bool, Optional[dict]]:
        entry = self._entry_find(not_found_throw=True, first=True, **query.arguments)
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

        if not check_mode:
            self._save()
        if query.field:
            found_entry = self._entry_find(not_found_throw=True, first=True, **query.arguments)
            return True, EntryDetails(found_entry, self._key_cache).__dict__
        else:
            return True, None

    def execute(self, query: RequestQuery, check_mode: bool = False, fail_silently: bool = False) -> dict:
        self._display.vvv(u"Keepass: execute - %s" % list(({key: to_native(value)} for key, value in inspect.currentframe().f_locals.items() if key != "self" and not key.startswith("__"))))
        result = RequestResult(query.__dict__, self._warnings)
        try:
            if not self._is_updatable and query.action != "get":
                raise AttributeError(u"Invalid request - database is not 'updatable'")
            result.success(getattr(self, query.action.replace("del", "delete"))(query, check_mode))
        except Exception as error:
            if not fail_silently:
                raise AnsibleParserError(AnsibleError(message=traceback.format_exc(), orig_exc=error))
            result.fail((traceback.format_exc(), error))
        return result.__dict__
