# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import glob
import json
import os
import random
import string
from shutil import copy
from unittest import TestCase, mock
from unittest.mock import call
from uuid import UUID

from ansible.errors import AnsibleParserError, AnsibleError
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from ansible_collections.dszryan.keepass.plugins.module_utils.database_details import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.entry_details import EntryDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery


class TestStorage(TestCase):
    _display = mock.Mock()

    @classmethod
    def setUpClass(cls) -> None:
        list(map(lambda file: os.remove(file), glob.glob(os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_*"))))

    @classmethod
    def tearDownClass(cls) -> None:
        list(map(lambda file: os.remove(file), glob.glob(os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_*"))))

    @staticmethod
    def _duplicate_without_keys(old_dict: {}, keys: []):
        new_dict = dict(old_dict)
        list(map(lambda k: new_dict.pop(k, None), (key for key in old_dict.keys() if key in keys)))
        return new_dict
#
    def setUp(self) -> None:
        self._database_details_base = { "location": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.kdbx"),
                                        "keyfile": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.keyfile"),
                                        "password": "scratch",
                                        "profile": "cached_key",
                                        "updatable": True }
        self._database_details_valid = DatabaseDetails(self._display, **self._database_details_base.copy())
        self._database_entry_uuid_valid = UUID("9366b38f-2ee9-412f-a6ba-b2ab10d1f100")
        self._database_entry_uuid_invalid = UUID("00000000-0000-0000-0000-000000000000")
        self._database_entry = {
            "title": "test",
            "path": "one/two",
            "username": "test_username",
            "password": None,
            "url": "test_url",
            "notes": "test_notes",
            "custom_properties": {
                "test_custom_key": "test_custom_value"
            },
            "attachments": [
                {
                    "filename": "scratch.keyfile",
                    "length": 2048
                }
            ]
        }

        self._query_username = RequestQuery(self._display, True, term="get://one/two/test?username")
        self._query_custom = RequestQuery(self._display, True, term="get://one/two/test?test_custom_key")
        self._query_file = RequestQuery(self._display, True, term="get://one/two/test?scratch.keyfile")
        self._query_invalid = RequestQuery(self._display, True, term="get://one/two/test?DOES_NOT_EXISTS")
        self._query_clone = RequestQuery(self._display, True, term="get://one/two/clone?username")

        self._delete_entry = RequestQuery(self._display, False, term="del://one/two/test")
        self._delete_password = RequestQuery(self._display, False, term="del://one/two/test?password")
        self._delete_custom = RequestQuery(self._display, False, term="del://one/two/test?test_custom_key")
        self._delete_file = RequestQuery(self._display, False, term="del://one/two/test?scratch.keyfile")
        self._delete_clone = RequestQuery(self._display, False, term="del://one/two/clone?password")
        self._delete_invalid_entry = RequestQuery(self._display, False, term="del://one/two/DOES_NOT_EXISTS")
        self._delete_invalid_property = RequestQuery(self._display, False, term="del://one/two/test?DOES_NOT_EXISTS")

        self._search_path_valid = RequestQuery(self._display, True, term="get://one/two/test")
        self._search_path_invalid = RequestQuery(self._display, True, term="get://one/two/new")
        self._clone_entry = dict(self._database_entry, title="clone", username="{REF:U@I:9366B38F2EE9412FA6BAB2AB10D1F100}", password="{REF:P@I:9366B38F2EE9412FA6BAB2AB10D1F100}", attachments=[])
        self._post_path_invalid = RequestQuery(self._display, False, term="post://one/two/clone#" + json.dumps(self._duplicate_without_keys(self._clone_entry, ["title", "path"])))
        self._noop_path_valid = RequestQuery(self._display, False, term="put://one/two/clone#" + json.dumps(self._duplicate_without_keys(self._clone_entry, ["title", "path"])))
        self._update_entry_value = {
            "title": "test",
            "path": "one/two",
            "username": "test_username",
            "password": None,
            "url": "url_updated",
            "notes": "test_notes",
            "custom_properties": {
                "test_custom_key": "test_custom_value_updated",
                "new_custom_key": "new_custom_value"
            },
            "attachments": [
                {"filename": "scratch.keyfile", "length": 18}
            ]
        }
        self._update_path_valid = RequestQuery(self._display, False, term='put://one/two/test#{"url": "url_updated", "test_custom_key": "test_custom_value_updated", "new_custom_key": "new_custom_value", "attachments": [{"filename": "scratch.keyfile", "binary": "this is a new file"}]}')
        self._insert_entry_value = {
            "title": "test",
            "path": "new_path/one/two",
            "username": "",
            "password": None,
            "url": "url_updated",
            "notes": None,
            "custom_properties": {
                "test_custom_key": "test_custom_value_updated",
                "new_custom_key": "new_custom_value"
            },
            "attachments": [
                {"filename": "new_file", "length": 18}
            ]
        }
        self._insert_path_valid = RequestQuery(self._display, False, term='post://new_path/one/two/test#{"url": "url_updated", "test_custom_key": "test_custom_value_updated", "new_custom_key": "new_custom_value", "attachments": [{"filename": "new_file", "binary": "this is a new file"}]}')
        self._display.reset_mock()

    def tearDown(self) -> None:
        pass

    def _copy_database(self, new_name) -> DatabaseDetails:
        new_location = os.path.join(os.path.dirname(self._database_details_valid.location), new_name + ".kdbx")
        copy(self._database_details_valid.location, new_location)
        return DatabaseDetails(self._display, **dict(self._database_details_base.copy(), location=new_location))

    def test__get_binary_b64_encoded(self):
        message = "hello world".encode("utf16")
        base64_encoded = base64.b64encode(message)
        actual = KeepassDatabase(self._display, self._database_details_valid, None)._get_binary(base64_encoded)
        self.assertEqual((message, True), actual)

    def test__get_binary_plain_text(self):
        message = "hello world".encode("utf16")
        actual = KeepassDatabase(self._display, self._database_details_valid, None)._get_binary(message)
        self.assertEqual((bytes(message), False), actual)

    def test__open_valid_details(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        self.assertIsNotNone(storage._database)
        self.assertTrue(isinstance(storage._database, PyKeePass))
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v('Keepass: database opened - %s' % self._database_details_valid.location)
        ])

    def test__open_invalid_database_file(self):
        self.assertRaises(AnsibleParserError, DatabaseDetails,
                          self._display, location="JUNK", keyfile=self._database_details_valid.keyfile, password=self._database_details_valid.password)
        self._display.assert_has_calls([])

    def test__open_invalid_missing_keyfile(self):
        self.assertRaises(AnsibleParserError, DatabaseDetails,
                          self._display, location=self._database_details_valid.location, keyfile="JUNK", password=self._database_details_valid.password)
        self._display.assert_has_calls([
            call.vvv("Keepass: database found - %s" % self._database_details_valid.location)
        ])

    def test__open_invalid_missing_password(self):
        cleared_password = DatabaseDetails(self._display, **dict(self._database_details_base.copy(), password=""))
        self.assertRaises(CredentialsError, KeepassDatabase,
                          self._display, cleared_password, None)
        self._display.assert_has_calls([
            call.vvv("Keepass: database found - %s" % self._database_details_valid.location),
            call.vvv("Keepass: keyfile found - %s" % self._database_details_valid.keyfile),
            call.vv(u"Keepass: database DEFAULT OPEN - %s" % self._database_details_valid.location)
        ])

    def test__save_valid(self):
        database_details_save = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_save, None)
        self.assertTrue(isinstance(storage._database, PyKeePass))
        storage._save()
        self._display.assert_has_calls([
            call.vvv("Keepass: database found - %s" % database_details_save.location),
            call.vvv(u"Keepass: keyfile found - %s" % database_details_save.keyfile),
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_save.location),
            call.v(u"Keepass: database opened - %s" % database_details_save.location),
            call.v(u"Keepass: database saved - %s" % database_details_save.location)
        ])

    def test__entry_find_valid_by_path(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        actual_entry = storage._entry_find(not_found_throw=True, **self._search_path_valid.arguments)
        self.assertDictEqual(self._database_entry, EntryDetails(actual_entry, None).__dict__)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test__entry_find_valid_by_uuid(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        actual_entry = storage._entry_find(not_found_throw=True, first=True, uuid=self._database_entry_uuid_valid)
        self.assertEqual(self._database_entry, EntryDetails(actual_entry, None).__dict__)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test__entry_find_invalid_by_path_no_error(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        actual_entry = storage._entry_find(not_found_throw=False, first=True, uuid=self._database_entry_uuid_invalid)
        self.assertEqual(None, actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test__entry_find_invalid_entry_raise_error(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        self.assertRaises(AnsibleError, storage._entry_find, not_found_throw=True, first=True, uuid=self._database_entry_uuid_invalid)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test__entry_upsert_invalid_post_when_exists_throw_error(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        self.assertRaises(AttributeError, storage._entry_upsert, self._post_path_invalid, False)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test__entry_upsert_valid_upsert_custom_values(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        has_changed, updated_entry = storage._entry_upsert(self._update_path_valid, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(self._update_entry_value, updated_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test__entry_upsert_valid_noop(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        has_changed, updated_entry = storage._entry_upsert(self._noop_path_valid, check_mode=False)
        self.assertFalse(has_changed)
        self.assertDictEqual(dict(self._clone_entry, password=None), updated_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test__entry_insert_valid(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        has_changed, updated_entry = storage._entry_upsert(self._insert_path_valid, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(self._insert_entry_value, updated_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test_get_valid_entry(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        has_changed, actual_entry = storage.get(self._search_path_valid, check_mode=False)
        self.assertFalse(has_changed)
        self.assertDictEqual(self._database_entry, actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_get_valid_property(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        has_changed, actual_entry = storage.get(self._query_username, check_mode=False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["username"], actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_get_valid_custom(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        has_changed, actual_entry = storage.get(self._query_custom, check_mode=False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["custom_properties"]["test_custom_key"], actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_get_valid_file(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        has_changed, actual_entry = storage.get(self._query_file, check_mode=False)
        with open(self._database_details_valid.keyfile, mode="rb") as file:
            self.assertFalse(has_changed)
            self.assertEqual(base64.b64encode(file.read()), actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_get_valid_clone(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        has_changed, actual_entry = storage.get(self._query_clone, check_mode=False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["username"], actual_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_get_invalid(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        self.assertRaises(AttributeError, storage.get, self._query_invalid, False)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_delete_valid_entry(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        has_changed, deleted_entry = storage.delete(self._delete_entry, check_mode=False)
        self.assertTrue(has_changed)
        self.assertEqual(None, deleted_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_property(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        has_changed, deleted_entry = storage.delete(self._delete_password, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, password=None), deleted_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_custom(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        has_changed, deleted_entry = storage.delete(self._delete_custom, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, custom_properties={}), deleted_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_file(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        has_changed, deleted_entry = storage.delete(self._delete_file, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, attachments=[]), deleted_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_clone(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        has_changed, deleted_entry = storage.delete(self._delete_clone, check_mode=False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._clone_entry, password=None), deleted_entry)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_no_entry_exists(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        self.assertRaises(AnsibleError, storage.delete, self._delete_invalid_entry, False)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_delete_valid_no_property_exists(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        self.assertRaises(AttributeError, storage.delete, self._delete_invalid_property, False)
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_execute_valid_get(self):
        storage = KeepassDatabase(self._display, self._database_details_valid, None)
        actual = storage.execute(self._search_path_valid, check_mode=False, fail_silently=True)
        self.assertFalse(actual["changed"])
        self.assertFalse(actual["failed"])
        self.assertDictEqual(self._search_path_valid.__dict__, actual["query"])
        self.assertDictEqual(self._database_entry, actual["stdout"])
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % self._database_details_valid.location),
            call.v("Keepass: database opened - %s" % self._database_details_valid.location)
        ])

    def test_execute_valid_post_changed(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        actual = storage.execute(self._insert_path_valid, check_mode=False, fail_silently=True)
        self.assertTrue(actual["changed"])
        self.assertFalse(actual["failed"])
        self.assertDictEqual(self._insert_path_valid.__dict__, actual["query"])
        self.assertDictEqual(self._insert_entry_value, actual["stdout"])
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test_execute_valid_put_changed(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        actual = storage.execute(self._update_path_valid, check_mode=False, fail_silently=True)
        self.assertTrue(actual["changed"])
        self.assertFalse(actual["failed"])
        self.assertDictEqual(self._update_path_valid.__dict__, actual["query"])
        self.assertDictEqual(self._update_entry_value, actual["stdout"])
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location),
        ])

    def test_execute_valid_put_noop(self):
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_upsert, None)
        actual = storage.execute(self._noop_path_valid, check_mode=False, fail_silently=False)
        self.assertFalse(actual["changed"])
        self.assertFalse(actual["failed"])
        self.assertDictEqual(self._noop_path_valid.__dict__, actual["query"])
        self.assertDictEqual(dict(self._clone_entry, password=None), actual["stdout"])
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_upsert.location),
            call.v("Keepass: database opened - %s" % database_details_upsert.location)
        ])

    def test_execute_valid_delete_entry(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        storage = KeepassDatabase(self._display, database_details_delete, None)
        actual = storage.execute(self._delete_entry, check_mode=False, fail_silently=False)
        self.assertTrue(actual["changed"])
        self.assertFalse(actual["failed"])
        self.assertDictEqual(self._delete_entry.__dict__, actual["query"])
        self.assertEqual(None, actual["stdout"])
        self._display.assert_has_calls([
            call.vv('Keepass: database DEFAULT OPEN - %s' % database_details_delete.location),
            call.v("Keepass: database opened - %s" % database_details_delete.location)
        ])

    def test_execute_invalid_not_updatable_fail_silently(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        database_details_delete.updatable = False
        storage = KeepassDatabase(self._display, database_details_delete, None)
        actual = storage.execute(self._delete_entry, check_mode=False, fail_silently=True)
        self.assertFalse(actual["changed"])
        self.assertTrue(actual["failed"])
        self.assertDictEqual(self._delete_entry.__dict__, actual["query"])
        self.assertTrue("Invalid request - database is not 'updatable'" in (actual["stderr"]["message"]))
        self._display.assert_has_calls([])

    def test_execute_invalid_not_updatable_not_silently_throw(self):
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16)))
        database_details_delete.updatable = False
        storage = KeepassDatabase(self._display, database_details_delete, None)
        self.assertRaises(AnsibleParserError, storage.execute, self._delete_entry, check_mode=False, fail_silently=False)
        self._display.assert_has_calls([])
