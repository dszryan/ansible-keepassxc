# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import os
import uuid

from ansible.errors import AnsibleError
from pykeepass import PyKeePass


# noinspection PyBroadException
class Storage(object):
    def __init__(self, display):
        self._display = display
        self._databases = {}

    @staticmethod
    def _get_binary(possibly_base64_encoded):
        try:
            binary_stream = base64.b64decode(possibly_base64_encoded)
            if base64.b64encode(binary_stream) == possibly_base64_encoded:
                return_value, was_encoded = binary_stream, True
        except Exception:
            return_value, was_encoded = possibly_base64_encoded, False
        return (str.encode(return_value) if isinstance(return_value, str) else return_value), was_encoded

    def _open(self, database_details, query):
        database_location = os.path.abspath(os.path.expanduser(os.path.expandvars(database_details.get("location"))))
        if self._databases.get(database_location) is None:
            # get database location
            if os.path.isfile(database_location):
                self._display.v(u"Keepass: database found - %s" % query)

            # get database password
            database_password = database_details.get("password", '')

            # get database keyfile
            database_keyfile = database_details.get("keyfile", None)
            if database_keyfile:
                database_keyfile = os.path.abspath(os.path.expanduser(os.path.expandvars(database_keyfile)))
                if os.path.isfile(database_keyfile):
                    self._display.vvv(u"Keepass: database keyfile - %s" % query)

            self._databases[database_location] = PyKeePass(database_location, database_password, database_keyfile)

        self._display.v(u"Keepass: database opened - %s" % query)
        return self._databases[database_location]

    def _save(self, database, query):
        database.save()
        self._display.v(u"Keepass: database saved - %s" % query)

    @staticmethod
    def _entry_dump(entry):
        return {
            "title": getattr(entry, "title", None),
            "username": getattr(entry, "username", None),
            "password": getattr(entry, "password", None),
            "url": getattr(entry, "url", None),
            "notes": getattr(entry, "notes", None),
            "custom_properties": getattr(entry, "custom_properties", None),
            "attachments": [{"filename": attachment.filename, "length": len(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []
        }

    def _entry_find(self, database_details, query, ref_uuid=None, not_found_throw=True):
        database = database_details if isinstance(database_details, PyKeePass) else self._open(database_details, query)
        entry = database.find_entries_by_path(query["path"], first=True) if ref_uuid is None else database.find_entries_by_uuid(ref_uuid, first=True)
        if entry is None:
            self._display.vv(u"KeePass: entry%s NOT found - %s" % ("" if ref_uuid is None else " (and its reference)", query))
            if not_found_throw:
                raise AnsibleError(u"Entry is not found")
            else:
                return None, database
        self._display.vv(u"KeePass: entry%s found - %s" % ("" if ref_uuid is None else " (and its reference)", query))
        return entry, database

    def _entry_upsert(self, must_not_exists, database_details, query, check_mode):
        entry, database = self._entry_find(database_details, query, not_found_throw=False)
        if must_not_exists and entry is not None:
            raise AttributeError(u"Invalid query - cannot post/insert when entry exists")

        path_split = (entry.path if entry is not None else query["path"]).rsplit("/", 1)
        title = path_split if len(path_split) == 1 else path_split[1]
        group_path = "/" if len(path_split) == 1 else path_split[0]

        destination_group = database.find_groups(path=group_path, regex=False, first=True)
        if not check_mode and destination_group is None:
            previous_group = database.root_group
            for path in group_path.split("/"):
                group = database.find_groups(name=(previous_group.path + path), regex=False, first=True)
                if group is None:
                    group = database.add_group(previous_group, path)
                previous_group = group
            destination_group = previous_group

        query_value = dict(query["value"])
        entry_is_created, entry_is_updated = (False, False)
        if not check_mode:
            if entry is None:
                entry = database.add_entry(
                    destination_group=destination_group,
                    title=title,
                    username=query_value.get("username", ""),
                    password=query_value.get("password", ""),
                    url=query_value.get("url", None),
                    notes=query_value.get("notes", None),
                    expiry_time=query_value.get("expiry_time", None),
                    tags=query_value.get("tags", None),
                    force_creation=False)
                list(map(lambda dict_key: query_value.pop(dict_key, None), ["username", "password", "url", "notes", "expiry_time", "tags"]))
                entry_is_created = True

            for (key, value) in query_value.items():
                if key == "attachments":
                    entry_attachments = entry.attachments
                    for item in value:
                        filename = item["filename"]
                        binary, was_encoded = Storage._get_binary(item["binary"])
                        entry_attachment_item = \
                            ([attachment for index, attachment in enumerate(entry_attachments) if attachment.filename == filename] or [None])[0]
                        if entry_attachment_item is None or entry_attachment_item.data != binary:
                            if not (entry_is_updated or entry_is_created):
                                entry.save_history()
                            if entry_attachment_item is not None:
                                database.delete_binary(entry_attachment_item.id)
                            entry.add_attachment(database.add_binary(binary), filename)
                            entry_is_updated = True
                elif hasattr(entry, key):
                    if getattr(entry, key, None) != value or (key in ["username", "password"] and getattr(entry, key, "") != ""):
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
            self._save(database, query)
            return True, Storage._entry_dump(self._entry_find(database, query)[0])
        elif entry is not None:
            return False, Storage._entry_dump(entry)
        else:
            return False, {}

    def get(self, database_details, query, check_mode=False):
        entry, database = self._entry_find(database_details, query)
        if query["property"] is None:
            return False, Storage._entry_dump(entry)

        # get entry value
        result = getattr(entry, query["property"], None) or \
            entry.custom_properties.get(query["property"], None) or \
            ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query["property"]] or [None])[0] or \
            (None if check_mode else query["value"])

        # get reference value
        if query["property"] in ["title", "username", "password", "url", "notes", "uuid"]:
            if hasattr(result, "startswith") and result.startswith("{REF:"):
                entry, database = self._entry_find(database, query, uuid.UUID(result.split(":")[2].strip("}")))
                result = getattr(entry, query["property"], (None if check_mode else query["value"]))

        # return result
        if result is not None or (query["value_is_provided"] and not check_mode):
            self._display.vv(u"KeePass: found property/file on entry - %s" % query)
            return False, base64.b64encode(result.binary) if hasattr(result, "binary") else result

        # throw error, value not found
        raise AttributeError(u"No property/file found")

    def post(self, database_details, query, check_mode=False):
        return self._entry_upsert(True, database_details, query, check_mode)

    def put(self, database_details, query, check_mode=False):
        return self._entry_upsert(False, database_details, query, check_mode)

    def delete(self, database_details, query, check_mode=False):
        entry, database = self._entry_find(database_details, query, not_found_throw=True)
        if query["property"] is None:
            database.delete_entry(entry) and not check_mode
        elif hasattr(entry, query["property"]):
            setattr(entry, query["property"], ("" if query["property"] in ["username", "password"] else None)) and not check_mode
        elif query["property"] in entry.custom_properties.keys():
            entry.delete_custom_property(query["property"]) and not check_mode
        else:
            attachment = ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query["property"]] or [None])[0]
            if attachment is not None:
                entry.delete_attachment(attachment) and not check_mode
            else:
                raise AttributeError(u"No property/file found")

        self._save(database, query) and not check_mode
        return True, (None if query["property"] is None else self._entry_dump(self._entry_find(database, query, not_found_throw=True)[0]))
