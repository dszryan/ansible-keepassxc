# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import inspect
import re
import traceback
import uuid
from os import PathLike
from typing import AnyStr, List, Optional, Tuple, Union

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
    from pykeepass.exceptions import CredentialsError
    from pykeepass.group import Group
except Exception as import_error:
    PYKEEPASS_IMP_ERR = traceback.format_exc()
    PYKEEPASS_IMP_EXP = import_error


class KeepassDatabase(object):
    _REF_MAP = {
        "T": "title",
        "U": "username",
        "P": "password",
        "A": "url",
        "N": "notes",
        "I": "UUID",

    }
    # noinspection RegExpRedundantEscape
    _REF_PATTERN = re.compile("\\{REF:(?P<field_key>[" + "".join(_REF_MAP.keys()) + "])@I:(?P<ref_id>\\w*)\\}")

    _warnings = []           # type: List
    _display: Display
    _key_cache: Optional[KeepassKeyCache]
    _database: PyKeePass
    _location: PathLike
    _is_updatable: bool

    def __init__(self, display: Display, details: DatabaseDetails, key_cache: Optional[KeepassKeyCache]):
        if PYKEEPASS_IMP_ERR:
            raise AnsibleParserError(AnsibleError(message=PYKEEPASS_IMP_ERR, orig_exc=PYKEEPASS_IMP_EXP))
        self._found_refs = {}
        self._display = display
        self._key_cache = key_cache
        self._database, self._location, self._is_updatable = self._open(details, key_cache)

    def _open(self, details: DatabaseDetails, key_cache: KeepassKeyCache) -> Tuple[PyKeePass, PathLike, bool]:
        database, cached_transform_key = None, None
        if key_cache:
            if not key_cache.has_secrets:
                self._warnings.append("Your keepass secrets are in clear text, why use a key store?")
            elif key_cache.can_cache:
                cached_transform_key = key_cache.get()                          # type Optional[bytes]

        try:
            if cached_transform_key:
                self._display.vv(u"Keepass: database REOPEN - %s" % details.location)
                database = PyKeePass(filename=details.location, transformed_key=cached_transform_key)
        except CredentialsError:
            self._display.vv(u"Keepass: database REOPEN FAILED - Cleared Cache - %s" % details.location)
            cached_transform_key = None

        if not database:
            if details.transformed_key:
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

    def _dereference_field(self, entry: Entry, field_value, mask_password, lookup_chain: Optional[List[uuid.UUID]] = None):
        lookup_chain = lookup_chain or []
        field_match = KeepassDatabase._REF_PATTERN.search(field_value) if field_value else None
        if not field_match:
            return False, field_value

        ref_field = field_match.group("field_key")
        ref_uuid = uuid.UUID(field_match.group("ref_id"))

        if entry and ref_uuid == entry.uuid:
            self._found_refs[ref_uuid] = entry
        elif not self._found_refs.get(ref_uuid, None):
            self._found_refs[ref_uuid] = self._entry_find(not_found_throw=True, mask_password=mask_password, first=True, uuid=ref_uuid)

        if ref_field == "I":
            if entry and ref_uuid == entry.uuid or ref_uuid in lookup_chain:
                raise AnsibleParserError(AnsibleError(message="cyclic error for entry - %s/%s/%s" % (self._location, entry.path, entry.uuid)))
            return True, self._dereference_entry(self._found_refs[ref_uuid], mask_password, lookup_chain + [ref_uuid])
        else:
            ref_value = getattr(self._found_refs[ref_uuid], KeepassDatabase._REF_MAP[ref_field])
            if entry and ref_uuid == entry.uuid:
                return True, ref_value
            else:
                return True, self._dereference_field(entry, ref_value, mask_password, lookup_chain)[1]

    def _dereference_entry(self, item: Entry, mask_password, lookup_chain: Optional[List[uuid.UUID]] = None) -> Entry:
        lookup_chain = lookup_chain or []
        for field in (["title", "username", "password", "url", "notes"] +
                      list(map(lambda k: "custom_properties." + k, item.custom_properties.keys()))):
            field_name = ".".join(field.split(".")[1:]) if field.startswith("custom_properties.") else field
            field_value = item.custom_properties.get(field_name, None) \
                if field.startswith("custom_properties.") else getattr(item, field_name, None)
            value_was_updated, ref_value = self._dereference_field(item, field_value, mask_password, lookup_chain)
            if field == "password" and mask_password:
                ref_value = self._key_cache.encrypt(ref_value) if self._key_cache else "PASSWORD_VALUE_CLEARED"
                value_was_updated = True

            if value_was_updated:
                if field == "title":    # NB: workaround for keepassxc, since its ui does not support whole entry reference
                    return ref_value
                elif field.startswith("custom_properties."):
                    item.set_custom_property(field_name, to_native(ref_value))
                else:
                    setattr(item, field_name, ref_value)

        return item

    def _entry_find(self, not_found_throw: bool, mask_password: bool, **arguments) -> Union[List[Entry], Entry, None]:
        if arguments.get("path", None) is not None:
            arguments["group"] = self._database.find_groups(path=arguments["path"], first=True)
            arguments.pop("path")

        self._display.vv(u'KeePass: execute query - {"query": %s}' % arguments)
        find_result = self._database.find_entries(**arguments) if arguments.get("group", None) or arguments.get("uuid", None) else None     # type: Union[List[Entry], Entry, None]

        if not find_result:
            self._display.vv(u'KeePass: entry NOT found - {"query": %s}' % arguments)
            if not_found_throw:
                raise AnsibleError(u"Entry is not found")
            else:
                return None
        else:
            self._display.vv(u'KeePass: entry found - {"query": %s}' % arguments)
            if isinstance(find_result, list):
                return list(map(lambda item: self._dereference_entry(item, mask_password), find_result))
            else:
                return self._dereference_entry(find_result, mask_password)

    def _entry_upsert(self, query: RequestQuery, check_mode: bool) -> Tuple[bool, Optional[dict]]:
        entry = self._entry_find(not_found_throw=False, mask_password=False, **query.arguments)
        if query.action == "post" and entry:
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
                elif key == "custom_properties":
                    for item in value.items():
                        cp_key = item[0]
                        cp_value = self._dereference_field(entry, item[1], False)[1]
                        if cp_key not in entry.custom_properties.keys() or entry.custom_properties.get(cp_key, None) != cp_value:
                            if not (entry_is_updated or entry_is_created):
                                entry.save_history()
                            entry.set_custom_property(cp_key, cp_value)
                            entry_is_updated = True
                elif hasattr(entry, key):
                    value = self._dereference_field(entry, value, False)[1]
                    if getattr(entry, key, None) != value or (key in ["username", "password"] and getattr(entry, key, "") != ("" if value is None else value)):
                        if not (entry_is_updated or entry_is_created):
                            entry.save_history()
                        setattr(entry, key, value)
                        entry_is_updated = True
                else:
                    raise AnsibleParserError(AnsibleError("unknown value provided %s" % key))

        if not check_mode and (entry_is_created or entry_is_updated):
            if not entry_is_created:
                entry.touch(True)
            self._save()
            fetched_entry = self._entry_find(not_found_throw=True, mask_password=True, **query.arguments)
            return True, EntryDetails(fetched_entry).__dict__
        elif entry:
            return (check_mode or entry_is_created or entry_is_updated), EntryDetails(entry).__dict__
        else:
            return (check_mode or entry_is_created or entry_is_updated), None

    def get(self, query: RequestQuery, **flags) -> Tuple[bool, Union[list, dict, AnyStr, None]]:
        check_mode = flags.get("check_mode", False)
        include_files = flags.get("include_files", False)
        entry = self._entry_find(not_found_throw=True, mask_password=True, **query.arguments)
        if not query.field:
            if not entry:
                return False, None
            elif isinstance(entry, list):
                return False, list(map(lambda item: EntryDetails(item, include_files).__dict__, entry))
            else:
                return False, EntryDetails(entry, include_files).__dict__

        # get entry value
        result = getattr(entry, query.field, None) or \
                 entry.custom_properties.get(query.field, None) or \
                 ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query.field] or [None])[0] or \
                 (query.value if not check_mode and query.value is not None else None)

        if result is not None or (not check_mode and query.value is not None):
            self._display.vv(u"KeePass: found property/file on entry - %s" % query)
            return False, (base64.b64encode(result.binary) if hasattr(result, "binary") else result)

        # throw error, value not found
        raise AttributeError(u"No property/file found")

    def post(self, query: RequestQuery, **flags) -> Tuple[bool, dict]:
        return self._entry_upsert(query, flags.get("check_mode", False))

    def put(self, query: RequestQuery, **flags) -> Tuple[bool, dict]:
        return self._entry_upsert(query, flags.get("check_mode", False))

    def delete(self, query: RequestQuery, **flags) -> Tuple[bool, Optional[dict]]:
        check_mode = flags.get("check_mode", False)
        entry = self._entry_find(not_found_throw=True, mask_password=False, **query.arguments)
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
            found_entry = self._entry_find(not_found_throw=True, mask_password=True, **query.arguments)
            return True, EntryDetails(found_entry).__dict__
        else:
            return True, None

    def execute(self, query: RequestQuery, **flags) -> dict:
        self._display.vvv(u"Keepass: execute - %s" % list(({key: to_native(value)} for key, value in inspect.currentframe().f_locals.items() if key != "self" and not key.startswith("__"))))
        result = RequestResult(query.__dict__, self._warnings)
        try:
            if not self._is_updatable and query.action != "get":
                raise AttributeError(u"Invalid request - database is not 'updatable'")
            result.success(getattr(self, query.action.replace("del", "delete"))(query, **flags))
        except Exception as error:
            if not flags.get("fail_silently", False):
                raise AnsibleParserError(AnsibleError(message=traceback.format_exc(), orig_exc=error))
            result.fail((traceback.format_exc(), error))
        return result.__dict__
