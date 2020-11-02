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

from ansible.errors import AnsibleError
from pykeepass import PyKeePass

from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query
from ansible_collections.dszryan.keepass.plugins.module_utils.storage import Storage


class TestStorage(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        list(map(lambda file: os.remove(file), glob.glob(os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_*"))))

    @classmethod
    def tearDownClass(cls) -> None:
        list(map(lambda file: os.remove(file), glob.glob(os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_*"))))

    def setUp(self) -> None:
        self._database_details = {
            "location": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.kdbx"),
            "keyfile": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.keyfile"),
            "password": "scratch",
            "updatable": True
        }
        self._database_entry_uuid_valid = UUID("9366b38f-2ee9-412f-a6ba-b2ab10d1f100")
        self._database_entry_uuid_invalid = UUID("00000000-0000-0000-0000-000000000000")
        self._database_entry = {
            "title": "test",
            "username": "test_username",
            "password": "test_password",
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

        from ansible.plugins import display
        self._query_password = Query._parse("get://one/two/test?password", display)
        self._query_custom = Query._parse("get://one/two/test?test_custom_key", display)
        self._query_file = Query._parse("get://one/two/test?scratch.keyfile", display)
        self._query_invalid = Query._parse("get://one/two/test?DOES_NOT_EXISTS", display)
        self._query_clone = Query._parse("get://one/two/clone?password", display)

        self._delete_entry = Query._parse("del://one/two/test", display)
        self._delete_password = Query._parse("del://one/two/test?password", display)
        self._delete_custom = Query._parse("del://one/two/test?test_custom_key", display)
        self._delete_file = Query._parse("del://one/two/test?scratch.keyfile", display)
        self._delete_clone = Query._parse("del://one/two/clone?password", display)
        self._delete_invalid_entry = Query._parse("del://one/two/DOES_NOT_EXISTS", display)
        self._delete_invalid_property = Query._parse("del://one/two/test?DOES_NOT_EXISTS", display)

        self._search_path_valid = Query._parse("get://one/two/test", display)
        self._search_path_invalid = Query._parse("get://one/two/new", display)
        self._noop_entry_valid = self._duplicate_without_keys(self._database_entry, ["title"])
        self._noop_path_valid = Query._parse("put://one/two/test#" + json.dumps(self._noop_entry_valid), display)
        self._update_entry_value = {
            "title": "test",
            "username": "test_username",
            "password": "test_password",
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
        self._update_path_valid = Query._parse('put://one/two/test#{"url": "url_updated", "test_custom_key": "test_custom_value_updated", "new_custom_key": "new_custom_value", "attachments": [{"filename": "scratch.keyfile", "binary": "this is a new file"}]}', display)
        self._insert_entry_value = {
            "title": "test",
            "username": "",
            "password": "",
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
        self._insert_path_valid = Query._parse('post://new_path/one/two/test#{"url": "url_updated", "test_custom_key": "test_custom_value_updated", "new_custom_key": "new_custom_value", "attachments": [{"filename": "new_file", "binary": "this is a new file"}]}', display)
        self._display = mock.Mock()

    def tearDown(self) -> None:
        pass

    @staticmethod
    def _duplicate_without_keys(d, keys):
        new_dict = dict(d)
        list(map(lambda k: new_dict.pop(k, None) and k in keys, d.keys()))
        return new_dict

    def _copy_database(self, new_name):
        new_location = os.path.join(os.path.dirname(self._database_details["location"]), new_name + ".kdbx")
        copy(self._database_details["location"], new_location)
        return dict(self._database_details, location=new_location)

    def test__get_binary_b64_encoded(self):
        message = "hello world".encode("utf16")
        base64_encoded = base64.b64encode(message)
        actual = Storage(self._display)._get_binary(base64_encoded)
        self.assertEqual((message, True), actual)

    def test__get_binary_plain_text(self):
        message = "hello world"
        actual = Storage(self._display)._get_binary(message)
        self.assertEqual((str.encode(message), False), actual)

    def test__open_valid_details(self, storage=None, database_details=None):
        storage = Storage(self._display) if storage is None else storage
        database_details = self._database_details if database_details is None else database_details
        self.assertEqual(storage._databases, {})
        actual = storage._open(database_details, self._search_path_valid)
        self.assertTrue(isinstance(actual, PyKeePass))
        self.assertDictEqual({database_details["location"]: actual}, storage._databases)
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._search_path_valid),
            call.vvv(u"Keepass: database keyfile - %s" % self._search_path_valid),
            call.v(u"Keepass: database opened - %s" % self._search_path_valid)
        ])

    def test__open_invalid_database_file(self):
        storage = Storage(self._display)
        self.assertEqual(storage._databases, {})
        self._database_details["location"] = os.path.join(self._database_details["location"], "/INVALID")
        self.assertRaises(FileNotFoundError, storage._open, self._database_details, self._search_path_valid)
        self.assertEqual(storage._databases, {})
        self._display.assert_has_calls([])

    def test__open_invalid_missing_keyfile(self):
        from pykeepass.exceptions import CredentialsError
        storage = Storage(self._display)
        self.assertEqual(storage._databases, {})
        self._database_details.pop("keyfile", None)
        self.assertRaises(CredentialsError, storage._open, self._database_details, self._search_path_valid)
        self.assertEqual(storage._databases, {})
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._search_path_valid)
        ])

    def test__open_invalid_missing_password(self):
        from pykeepass.exceptions import CredentialsError
        storage = Storage(self._display)
        self.assertEqual(storage._databases, {})
        self._database_details.pop("password", None)
        self.assertRaises(CredentialsError, storage._open, self._database_details, self._search_path_valid)
        self.assertEqual(storage._databases, {})
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._search_path_valid),
            call.vvv(u"Keepass: database keyfile - %s" % self._search_path_valid)
        ])

    def test__save_valid(self):
        storage = Storage(self._display)
        database_details_save = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        self.test__open_valid_details(storage, database_details_save)
        storage._save(storage._databases[database_details_save["location"]], self._search_path_valid)
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._search_path_valid),
            call.vvv(u"Keepass: database keyfile - %s" % self._search_path_valid),
            call.v(u"Keepass: database opened - %s" % self._search_path_valid),
            call.v(u"Keepass: database saved - %s" % self._search_path_valid)
        ])

    def test__save_invalid(self):
        storage = Storage(self._display)
        self.assertRaises(AttributeError, storage._save, None, self._search_path_valid)
        self._display.assert_has_calls([])

    def test__entry_find_valid_by_path(self):
        storage = Storage(self._display)
        actual_entry, actual_database = storage._entry_find(self._database_details, self._search_path_valid, None, True)
        self.assertEqual(self._database_entry, storage._entry_dump(actual_entry))
        self.assertTrue(isinstance(actual_database, PyKeePass))
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_valid),
            call.v("Keepass: database opened - %s" % self._search_path_valid),
            call.vv("KeePass: entry found - %s" % self._search_path_valid),
        ])

    def test__entry_find_valid_by_uuid(self):
        storage = Storage(self._display)
        actual_entry, actual_database = storage._entry_find(self._database_details, self._search_path_valid, self._database_entry_uuid_valid, True)
        self.assertEqual(self._database_entry, storage._entry_dump(actual_entry))
        self.assertTrue(isinstance(actual_database, PyKeePass))
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_valid),
            call.v("Keepass: database opened - %s" % self._search_path_valid),
            call.vv("KeePass: entry (and its reference) found - %s" % self._search_path_valid)
        ])

    def test__entry_find_invalid_by_path_no_error(self):
        storage = Storage(self._display)
        actual_entry, actual_database = storage._entry_find(self._database_details, self._search_path_invalid, None, False)
        self.assertEqual(None, actual_entry)
        self.assertTrue(isinstance(actual_database, PyKeePass))
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_invalid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_invalid),
            call.v("Keepass: database opened - %s" % self._search_path_invalid),
            call.vv("KeePass: entry NOT found - %s" % self._search_path_invalid),
        ])

    def test__entry_find_invalid_path_raise_error(self):
        storage = Storage(self._display)
        self.assertRaises(AnsibleError, storage._entry_find, self._database_details, self._search_path_invalid, None, True)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_invalid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_invalid),
            call.v("Keepass: database opened - %s" % self._search_path_invalid),
            call.vv("KeePass: entry NOT found - %s" % self._search_path_invalid)
        ])

    def test__entry_find_invalid_uuid_raise_error(self):
        storage = Storage(self._display)
        self.assertRaises(AnsibleError, storage._entry_find, self._database_details, self._search_path_invalid, self._database_entry_uuid_invalid, True)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_invalid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_invalid),
            call.v("Keepass: database opened - %s" % self._search_path_invalid),
            call.vv("KeePass: entry (and its reference) NOT found - %s" % self._search_path_invalid)
        ])

    def test__entry_upsert_valid_must_not_exists_throw_error(self):
        storage = Storage(self._display)
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        self.assertRaises(AttributeError, storage._entry_upsert, True, database_details_upsert, self._search_path_valid, False)
        self._display.assert_has_calls([])

    def test__entry_upsert_valid_upsert_custom_values(self):
        storage = Storage(self._display)
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, updated_entry = storage._entry_upsert(False, database_details_upsert, self._update_path_valid, False)
        self.assertTrue(has_changed)
        self.assertEqual(self._update_entry_value, updated_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._update_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._update_path_valid),
            call.v("Keepass: database opened - %s" % self._update_path_valid),
            call.vv("KeePass: entry found - %s" % self._update_path_valid),
            call.v("Keepass: database saved - %s" % self._update_path_valid),
            call.vv("KeePass: entry found - %s" % self._update_path_valid)
        ])

    def test__entry_upsert_valid_noop(self):
        storage = Storage(self._display)
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, updated_entry = storage._entry_upsert(False, database_details_upsert, self._noop_path_valid, False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry, updated_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._noop_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._noop_path_valid),
            call.v("Keepass: database opened - %s" % self._noop_path_valid),
            call.vv("KeePass: entry found - %s" % self._noop_path_valid)
        ])

    def test__entry_insert_valid(self):
        storage = Storage(self._display)
        database_details_upsert = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, updated_entry = storage._entry_upsert(False, database_details_upsert, self._insert_path_valid, False)
        self.assertTrue(has_changed)
        self.assertEqual(self._insert_entry_value, updated_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._insert_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._insert_path_valid),
            call.v("Keepass: database opened - %s" % self._insert_path_valid),
            call.vv("KeePass: entry NOT found - %s" % self._insert_path_valid),
            call.v("Keepass: database saved - %s" % self._insert_path_valid),
            call.vv("KeePass: entry found - %s" % self._insert_path_valid)
        ])

    def test_get_valid_entry_dump(self):
        storage = Storage(self._display)
        has_changed, actual_entry = storage.get(self._database_details, self._search_path_valid, False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry, actual_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_valid),
            call.v("Keepass: database opened - %s" % self._search_path_valid),
            call.vv("KeePass: entry found - %s" % self._search_path_valid)
        ])

    def test_get_valid_property(self):
        storage = Storage(self._display)
        has_changed, actual_entry = storage.get(self._database_details, self._query_password, False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["password"], actual_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._query_password),
            call.vvv("Keepass: database keyfile - %s" % self._query_password),
            call.v("Keepass: database opened - %s" % self._query_password),
            call.vv("KeePass: entry found - %s" % self._query_password)
        ])

    def test_get_valid_custom(self):
        storage = Storage(self._display)
        has_changed, actual_entry = storage.get(self._database_details, self._query_custom, False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["custom_properties"]["test_custom_key"], actual_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._query_custom),
            call.vvv("Keepass: database keyfile - %s" % self._query_custom),
            call.v("Keepass: database opened - %s" % self._query_custom),
            call.vv("KeePass: entry found - %s" % self._query_custom),
            call.vv("KeePass: found property/file on entry - %s" % self._query_custom)
        ])

    def test_get_valid_file(self):
        storage = Storage(self._display)
        has_changed, actual_entry = storage.get(self._database_details, self._query_file, False)
        with open(self._database_details["keyfile"], mode="rb") as file:
            self.assertFalse(has_changed)
            self.assertEqual(base64.b64encode(file.read()), actual_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._query_file),
            call.vvv("Keepass: database keyfile - %s" % self._query_file),
            call.v("Keepass: database opened - %s" % self._query_file),
            call.vv("KeePass: entry found - %s" % self._query_file),
            call.vv("KeePass: found property/file on entry - %s" % self._query_file)
        ])

    def test_get_valid_file(self):
        storage = Storage(self._display)
        has_changed, actual_entry = storage.get(self._database_details, self._query_clone, False)
        self.assertFalse(has_changed)
        self.assertEqual(self._database_entry["password"], actual_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._query_clone),
            call.vvv("Keepass: database keyfile - %s" % self._query_clone),
            call.v("Keepass: database opened - %s" % self._query_clone),
            call.vv("KeePass: entry found - %s" % self._query_clone),
            call.vv("KeePass: entry (and its reference) found - %s" % self._query_clone),
            call.vv("KeePass: found property/file on entry - %s" % self._query_clone)
        ])

    def test_get_invalid(self):
        storage = Storage(self._display)
        self.assertRaises(AttributeError, storage.get, self._database_details, self._query_invalid, False)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._query_invalid),
            call.vvv("Keepass: database keyfile - %s" % self._query_invalid),
            call.v("Keepass: database opened - %s" % self._query_invalid),
            call.vv("KeePass: entry found - %s" % self._query_invalid)
        ])

    def test_delete_valid_entry(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, deleted_entry = storage.delete(database_details_delete, self._delete_entry, False)
        self.assertTrue(has_changed)
        self.assertEqual(None, deleted_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_entry),
            call.vvv("Keepass: database keyfile - %s" % self._delete_entry),
            call.v("Keepass: database opened - %s" % self._delete_entry),
            call.vv("KeePass: entry found - %s" % self._delete_entry),
            call.v("Keepass: database saved - %s" % self._delete_entry)
        ])

    def test_delete_valid_property(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, deleted_entry = storage.delete(database_details_delete, self._delete_password, False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, password=""), deleted_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_password),
            call.vvv("Keepass: database keyfile - %s" % self._delete_password),
            call.v("Keepass: database opened - %s" % self._delete_password),
            call.vv("KeePass: entry found - %s" % self._delete_password),
            call.v("Keepass: database saved - %s" % self._delete_password),
            call.vv("KeePass: entry found - %s" % self._delete_password)
        ])

    def test_delete_valid_custom(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, deleted_entry = storage.delete(database_details_delete, self._delete_custom, False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, custom_properties={}), deleted_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_custom),
            call.vvv("Keepass: database keyfile - %s" % self._delete_custom),
            call.v("Keepass: database opened - %s" % self._delete_custom),
            call.vv("KeePass: entry found - %s" % self._delete_custom),
            call.v("Keepass: database saved - %s" % self._delete_custom),
            call.vv("KeePass: entry found - %s" % self._delete_custom)
        ])

    def test_delete_valid_file(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, deleted_entry = storage.delete(database_details_delete, self._delete_file, False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, attachments=[]), deleted_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_file),
            call.vvv("Keepass: database keyfile - %s" % self._delete_file),
            call.v("Keepass: database opened - %s" % self._delete_file),
            call.vv("KeePass: entry found - %s" % self._delete_file),
            call.v("Keepass: database saved - %s" % self._delete_file),
            call.vv("KeePass: entry found - %s" % self._delete_file)
        ])

    def test_delete_valid_clone(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        has_changed, deleted_entry = storage.delete(database_details_delete, self._delete_clone, False)
        self.assertTrue(has_changed)
        self.assertDictEqual(dict(self._database_entry, title="clone", username="{REF:U@I:9366B38F2EE9412FA6BAB2AB10D1F100}", password=""), deleted_entry)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_clone),
            call.vvv("Keepass: database keyfile - %s" % self._delete_clone),
            call.v("Keepass: database opened - %s" % self._delete_clone),
            call.vv("KeePass: entry found - %s" % self._delete_clone),
            call.v("Keepass: database saved - %s" % self._delete_clone),
            call.vv("KeePass: entry found - %s" % self._delete_clone)
        ])

    def test_delete_valid_no_entry_exists(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        self.assertRaises(AnsibleError, storage.delete, database_details_delete, self._delete_invalid_entry, False)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_invalid_entry),
            call.vvv("Keepass: database keyfile - %s" % self._delete_invalid_entry),
            call.v("Keepass: database opened - %s" % self._delete_invalid_entry),
            call.vv("KeePass: entry NOT found - %s" % self._delete_invalid_entry)
        ])

    def test_delete_valid_no_property_exists(self):
        storage = Storage(self._display)
        database_details_delete = self._copy_database("temp_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        self.assertRaises(AttributeError, storage.delete, database_details_delete, self._delete_invalid_property, False)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._delete_invalid_property),
            call.vvv("Keepass: database keyfile - %s" % self._delete_invalid_property),
            call.v("Keepass: database opened - %s" % self._delete_invalid_property),
            call.vv("KeePass: entry found - %s" % self._delete_invalid_property)
        ])
