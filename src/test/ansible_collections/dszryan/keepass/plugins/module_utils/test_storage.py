import base64
import os
from unittest import TestCase, mock
from unittest.mock import call

from pykeepass import PyKeePass

from ansible_collections.dszryan.keepass.plugins.module_utils.storage import Storage


class TestStorage(TestCase):

    # def setUpClass(cls) -> None:
    #     pass

    def setUp(self) -> None:
        self._display = mock.Mock()
        self._storage = Storage(self._display)
        self._database_details = {
            "location": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.kdbx"),
            "keyfile": os.path.join(os.path.dirname(os.path.realpath(__file__)), "scratch.keyfile"),
            "password": "scratch",
            "updatable": True
        }
        self._query = "test"

    def tearDown(self) -> None:
        pass

    # def tearDownClass(cls) -> None:
    #     pass

    def test__get_binary_b64_encoded(self):
        message = "hello world".encode("utf16")
        base64_encoded = base64.b64encode(message)
        actual = self._storage._get_binary(base64_encoded)
        self.assertEqual((message, True), actual)

    def test__get_binary_plain_text(self):
        message = "hello world"
        actual = self._storage._get_binary(message)
        self.assertEqual((message, False), actual)

    def test__open_valid_details(self):
        self.assertEqual(self._storage._databases, {})
        actual = self._storage._open(self._database_details, self._query)
        self.assertTrue(isinstance(actual, PyKeePass))
        self.assertDictEqual({self._database_details["location"]: actual}, self._storage._databases)
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._query),
            call.vvv(u"Keepass: database keyfile - %s" % self._query),
            call.v(u"Keepass: database opened - %s" % self._query)
        ])

    def test__open_invalid_database_file(self):
        from pykeepass.exceptions import CredentialsError
        self.assertEqual(self._storage._databases, {})
        self._database_details["location"] = os.path.join(self._database_details["location"], "/INVALID")
        self.assertRaises(FileNotFoundError, self._storage._open, self._database_details, self._query)
        self.assertEqual(self._storage._databases, {})
        self._display.assert_has_calls([])

    def test__open_valid_missing_keyfile(self):
        from pykeepass.exceptions import CredentialsError
        self.assertEqual(self._storage._databases, {})
        self._database_details.pop("keyfile", None)
        self.assertRaises(CredentialsError, self._storage._open, self._database_details, self._query)
        self.assertEqual(self._storage._databases, {})
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._query)
        ])

    def test__open_valid_missing_password(self):
        from pykeepass.exceptions import CredentialsError
        self.assertEqual(self._storage._databases, {})
        self._database_details.pop("password", None)
        self.assertRaises(CredentialsError, self._storage._open, self._database_details, self._query)
        self.assertEqual(self._storage._databases, {})
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._query),
            call.vvv(u"Keepass: database keyfile - %s" % self._query)
        ])

    def test__save_valid(self):
        self.test__open_valid_details()
        self._storage._save(self._storage._databases[self._database_details["location"]], self._query)
        self._display.assert_has_calls([
            call.v(u"Keepass: database found - %s" % self._query),
            call.vvv(u"Keepass: database keyfile - %s" % self._query),
            call.v(u"Keepass: database opened - %s" % self._query),
            call.v(u"Keepass: database saved - %s" % self._query)
        ])

    def test__entry_dump(self):
        self.fail()

    def test__entry_find(self):
        self.fail()

    def test__entry_upsert(self):
        self.fail()

    def test_get(self):
        self.fail()

    def test_post(self):
        self.fail()

    def test_put(self):
        self.fail()

    def test_delete(self):
        self.fail()
