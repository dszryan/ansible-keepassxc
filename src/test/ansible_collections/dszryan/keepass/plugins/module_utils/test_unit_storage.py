import os
from unittest import TestCase, mock
from unittest.mock import call

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
        self.fail()

    def test__get_binary_plain_text(self):
        self.fail()

    def test__open_valid_details(self):
        self.fail()

    def test__open_invalid_database_file(self):
        self.fail()

    def test__open_invalid_missing_keyfile(self):
        self.fail()

    def test__open_invalid_missing_password(self):
        self.fail()

    def test__save_valid(self):
        self.fail()

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
