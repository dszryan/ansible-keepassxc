# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import os
import uuid

from ansible.errors import AnsibleError
from ansible.utils.display import Display
from pykeepass import PyKeePass

display = Display()


class Storage(object):
    def __init__(self):
        self._databases = {}

    @staticmethod
    def _get_location(database_details):
        return os.path.abspath(os.path.expanduser(os.path.expandvars(database_details.get("location"))))

    def _open(self, database_details):
        try:
            database_location = Storage._get_location(database_details)
            if self._databases.get(database_location) is None:
                # get database location
                if os.path.isfile(database_location):
                    display.v(u"Keepass: database found - %s" % database_location)

                # get database password
                database_password = database_details.get("password", '')

                # get database keyfile
                database_keyfile = database_details.get("keyfile", None)
                if database_keyfile:
                    database_keyfile = os.path.abspath(os.path.expanduser(os.path.expandvars(database_keyfile)))
                    if os.path.isfile(database_keyfile):
                        display.vvv(u"Keepass: database keyfile - %s" % database_keyfile)

                self._databases[database_location] = \
                    PyKeePass(database_location, database_password, database_keyfile)

            display.v(u"Keepass: database opened - %s" % database_location)
            return self._databases[database_location]
        except Exception as error:
            raise AttributeError(u"'Cannot open database - '%s'" % error)

    def _save(self, database_details):
        try:
            database_location = Storage._get_location(database_details)
            database = self._databases[database_location]
            if database is not None:
                database.save()
            display.v(u"Keepass: database saved - %s" % database_location)
        except Exception as error:
            raise AttributeError(u"'Cannot save database - '%s'" % error)

    def _find_by_path(self, database_details, path):
        entry = self._open(database_details).find_entries_by_path(path, first=True)
        if entry is None:
            raise AnsibleError(u"Entry '%s' is not found" % path)
        display.vv(u"KeePass: entry found - %s" % path)
        return entry

    def _find_by_uuid(self, database_details, path, uuid_id):
        entry = self._open(database_details).find_entries_by_uuid(uuid_id, first=True)
        if entry is None:
            raise AnsibleError(u"Entry '%s' referencing another entry is not found" % path)
        display.vv(u"KeePass: referencing entry found - %s" % path)
        return entry

    @staticmethod
    def _entry_dump(entry):
        return {
            "title": getattr(entry, 'title', None),
            "username": getattr(entry, 'username', None),
            "password": getattr(entry, 'password', None),
            "url": getattr(entry, 'url', None),
            "notes": getattr(entry, 'notes', None),
            "custom_properties": getattr(entry, 'custom_properties', None),
            "attachments": [{"filename": attachment.filename, "binary": base64.b64encode(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []
        }

    def get(self, database_details, query, check_mode=False):
        entry = self._find_by_path(database_details, query["path"])
        if query["property"] is None:
            return [Storage._entry_dump(entry)]

        # get entry value
        result = getattr(entry, query["property"], None) or \
            entry.custom_properties.get(query["property"], None) or \
            ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query["property"]] or [None])[0] or \
            query["default_value"]

        # get reference value
        if query["property"] in ['title', 'username', 'password', 'url', 'notes', 'uuid']:
            if hasattr(result, 'startswith') and result.startswith('{REF:'):
                entry = self._find_by_uuid(database_details, query["path"], uuid.UUID(result.split(":")[2].strip('}')))
                result = getattr(entry, query["property"], query["default_value"])

        # return result
        if query["default_value_is_provided"] or result is not None:
            return [base64.b64encode(result.binary) if hasattr(result, 'binary') else result]

        # throw error, value not found
        raise AttributeError(u"'No property/file found '%s'" % query["property"])

    def put(self, database_details, query, check_mode=False):

        return None

    def post(self, database_details, query, check_mode=False):

        return None

    def delete(self, database_details, query, check_mode=False):

        return None
