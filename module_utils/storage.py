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
        self.databases = {}

    def __dump__(self, entry):
        return {
            "title": getattr(entry, 'title', None),
            "username": getattr(entry, 'username', None),
            "password": getattr(entry, 'password', None),
            "url": getattr(entry, 'url', None),
            "notes": getattr(entry, 'notes', None),
            "custom_properties": getattr(entry, 'custom_properties', None),
            "attachments": [{"filename": attachment.filename, "binary": base64.b64encode(attachment.binary)} for index, attachment in enumerate(entry.attachments)] or []
        }

    def __open__(self, database_details):
        database_location = os.path.abspath(os.path.expanduser(os.path.expandvars(database_details.get("location"))))
        if self.databases.get(database_location) is None:
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

            self.databases[database_location] = \
                PyKeePass(database_location, database_password, database_keyfile)

        display.v(u"Keepass: database opened - %s" % database_location)
        return self.databases[database_location]

    def __find_by_path__(self, database_details, path):
        return self.__open__(database_details).find_entries_by_path(path, first=True)

    def __find_by_uuid__(self, database_details, uuid_id):
        return self.__open__(database_details).find_entries_by_uuid(uuid_id, first=True)

    def get(self, database_details, query, check_mode=False):
        entry = self.__find_by_path__(database_details, query["path"])
        if entry is None:
            raise AnsibleError(u"Entry '%s' is not found" % query["path"])
        display.vv(u"KeePass: entry found - %s" % query["path"])

        if query["property"] is None:
            return [self.__dump__(entry)]

        # get entry value
        result = getattr(entry, query["property"], None) or \
            entry.custom_properties.get(query["property"], None) or \
            ([attachment for index, attachment in enumerate(entry.attachments) if attachment.filename == query["property"]] or [None])[0] or \
            query["default_value"]

        # get reference value
        if query["property"] in ['title', 'username', 'password', 'url', 'notes', 'uuid']:
            if hasattr(result, 'startswith') and result.startswith('{REF:'):
                entry = self.__find_by_uuid__(database_details, uuid.UUID(result.split(":")[2].strip('}')))
                result = getattr(entry, query["property"], query["default_value"])

        # return result
        if query["default_value_is_provided"] or result is not None:
            return [base64.b64encode(result.binary) if hasattr(result, 'binary') else result]

        # throw error, value not found
        raise AnsibleError(AttributeError(u"'No property/file found '%s'" % query["property"]))

    def put(self, database_details, query, check_mode=False):

        return None

    def post(self, database_details, query, check_mode=False):

        return None

    def delete(self, database_details, query, check_mode=False):

        return None
