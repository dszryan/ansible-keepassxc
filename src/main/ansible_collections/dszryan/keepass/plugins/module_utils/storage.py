# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import os
import json
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
                return binary_stream, True
        except Exception:
            return possibly_base64_encoded, False

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

            self._databases[database_location] = \
                PyKeePass(database_location, database_password, database_keyfile)

        self._display.v(u"Keepass: database opened - %s" % query)
        return self._databases[database_location]

    def _save(self, database_details, query):
        database = database_details if isinstance(database_details, type(PyKeePass)) == str else self._open(database_details, query)
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
            "attachments": [
                               {
                                   "filename": attachment.filename,
                                   "length": len(attachment.binary)
                               }
                               for index, attachment in enumerate(entry.attachments)
                           ] or []
        }

    def _entry_find(self, database_details, query, ref_uuid=None, not_found_throw=True):
        database = database_details if isinstance(database_details, type(PyKeePass)) == str else self._open(database_details, query)
        entry = database.find_entries_by_path(query["path"], first=True) if ref_uuid is None else database.find_entries_by_uuid(ref_uuid, first=True)
        if not_found_throw and entry is None:
            raise AnsibleError(u"Entry is not found")
        self._display.vv(u"KeePass: entry%s found - %s" % ("" if ref_uuid is None else " (and its reference)", query))
        return entry, database

    def _entry_upsert(self, must_not_exists, database_details, query, check_mode):
        entry, database = self._entry_find(database_details, query, not_found_throw=False)
        if must_not_exists and entry is not None:
            raise AttributeError(u"Invalid query - cannot post/insert when entry exists")

        json_payload = json.load(query["value"])
        path_split = (entry.path if entry is not None else query["path"]).rsplit("/", 1)
        title = path_split if len(path_split) == 1 else path_split[1]
        group_path = "/" if len(path_split) == 1 else path_split[0]
        found_mtime = getattr(entry, "mtime", "")

        destination_group = database.find_groups(path=group_path, regex=False, first=True)
        if not check_mode and destination_group is None:
            previous_group = database.root_group()
            for path in query["path"].split("/"):
                group = database.find_groups(name=path, regex=False, first=True)
                if group is None:
                    group = database.add_group(previous_group, path)
                previous_group = group
            destination_group = previous_group

        if not check_mode:
            entry = database.add_entry(
                destination_group=destination_group,
                title=title,
                username=getattr(json_payload, "username", ""),
                password=getattr(json_payload, "password", ""),
                url=getattr(json_payload, "url", None),
                notes=getattr(json_payload, "notes", None),
                expiry_time=getattr(json_payload, "expiry_time", None),
                tags=getattr(json_payload, "tags", None),
                force_creation=must_not_exists)

        for key in ["title", "username", "password", "url", "notes", "expiry_time", "tags"]:
            json_payload.pop(key, None)

        for key in json_payload.keys():
            if key == "attachments":
                attachments = json_payload[key]
                next_id = len(entry.attachments)
                for item in attachments:
                    filename = item["filename"]
                    binary = Storage._get_binary(item["binary"])
                    if not check_mode:
                        attachment = entry.add_attachment(next_id, filename)
                        attachment.binary = binary
                        next_id = next_id + 1
            elif not check_mode:
                entry.set_custom_property(key, json_payload[key])

        if not check_mode:
            self._save(database, query)
            upsert_entity = Storage._entry_dump(self._entry_find(database, query)[0])
            return (found_mtime == getattr(upsert_entity, "mtime", "")), upsert_entity
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
        entry, database = self._entry_find(database_details, query)
        if query["property"] is None:
            database.delete_entry(entry) and not check_mode
        elif hasattr(entry, query["property"]):
            setattr(entry, query["property"], None) and not check_mode
        elif query["property"] in entry.custom_properties.keys():
            entry.delete_custom_property(query["property"]) and not check_mode
        else:
            attachments = entry.find_attachments(filename=query["property"], regex=True)
            if attachments is None:
                return False, None
            elif not check_mode:
                for attachment in attachments:
                    entry.delete_attachment(attachment)

        self._save(database, query) and not check_mode
        return True, None
