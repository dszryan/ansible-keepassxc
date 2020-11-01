import base64
import os
from shutil import copy
from unittest import TestCase, mock
from unittest.mock import call
from uuid import UUID

from ansible.errors import AnsibleError
from pykeepass import PyKeePass

from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query
from ansible_collections.dszryan.keepass.plugins.module_utils.storage import Storage


class TestStorage(TestCase):

    # def setUpClass(cls) -> None:
    #     pass

    def setUp(self) -> None:
        from ansible.plugins import display
        self._search_path_valid = Query._parse("get://one/two/test", display)
        self._search_path_invalid = Query._parse("get://one/DOES_NOT_EXISTS/test", display)
        self._display = mock.Mock()
        self._database_details = {
            "location": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.kdbx"),
            "keyfile": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.keyfile"),
            "password": "scratch",
            "updatable": True
        }
        self._database_entry_uuid_valid = UUID('9366b38f-2ee9-412f-a6ba-b2ab10d1f100')
        self._database_entry_uuid_invalid = UUID('00000000-0000-0000-0000-000000000000')
        self._database_entry = {
            'title': 'test',
            'username': 'test_username',
            'password': 'test_password',
            'url': 'test_url',
            'notes': 'test_notes',
            'custom_properties': {
                'test_custom_key': 'test_custom_value'
            },
            'attachments': [
                {
                    'filename': 'scratch.keyfile',
                    'length': 2048
                }
            ]
        }

    def tearDown(self) -> None:
        pass

    # def tearDownClass(cls) -> None:
    #     pass

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
        self.assertEqual((message, False), actual)

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
        database_details_save = self._copy_database("save")
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

    # def test__entry_dump(self):
    #     self.fail()

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

    # def test__entry_upsert(self):
    #     self.fail()

    def test_get_valid_entry_dump(self):
        storage = Storage(self._display)
        actual = storage.get(self._database_details, self._search_path_valid, False)
        self.assertEqual((False, self._database_entry), actual)
        self._display.assert_has_calls([
            call.v("Keepass: database found - %s" % self._search_path_valid),
            call.vvv("Keepass: database keyfile - %s" % self._search_path_valid),
            call.v("Keepass: database opened - %s" % self._search_path_valid),
            call.vv("KeePass: entry found - %s" % self._search_path_valid)
        ])

    # def test_post(self):
    #     self.fail()
    #
    # def test_put(self):
    #     self.fail()
    #
    # def test_delete(self):
    #     self.fail()
