# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
from collections import Mapping
from typing import Union, Optional

from ansible.module_utils.common.text.converters import to_text
from ansible.parsing.vault import VaultLib
from ansible.plugins.cache import FactCache
from ansible.plugins.test.core import vault_encrypted
from ansible.utils.display import Display


class KeepassKeyCache(object):
    def __init__(self, hostname: str, details: Optional[dict], display: Display):
        self._hostname = hostname                               # type: Optional[str]
        self._profile = details.get("profile", "secure")        # type: str
        self._location = details.get("location", None)          # type: Optional[str]
        self._display = display                                 # type: Display
        self._secrets = KeepassKeyCache.get_secrets(details)    # type: Optional[bytes]
        self._display.vv(u"Keepass: transformation caching is%s possible [%s]" % (("" if self._secrets else "not "), self._location))

    @staticmethod
    def _get_name_as_key() -> str:
        return "_" + globals()["__name__"].replace(".", "_").upper()

    @staticmethod
    def get_secrets(details: Mapping) -> Optional[bytes]:
        if details.get("password", None) and vault_encrypted(details["password"]):
            return details["password"].vault.secrets
        elif details.get("transformed_key", None) and vault_encrypted(details["transformed_key"]):
            return details["transformed_key"].vault.secrets
        return None

    @property
    def is_valid(self) -> bool:
        return self._secrets is not None

    def get(self) -> Optional[bytes]:
        if not self._hostname or self._hostname.isspace() or not self._secrets or self._profile != "cached_key":
            return None
        vault = VaultLib(self._secrets)
        cache = FactCache()
        host_facts = cache.copy().get(self._hostname, {KeepassKeyCache._get_name_as_key(): []}) or {}
        keepass = ([key for key in host_facts.get(KeepassKeyCache._get_name_as_key(), []) if key.get("location", "") == self._location] or [None])[0]  # type: Union[dict, None]
        cached_key = base64.decodebytes(vault.decrypt(keepass.get("transformed_key"))) if keepass else None
        self._display.vv(u"Keepass: transformation cache key was%s found [%s]" % (("" if cached_key else "not "), self._location))
        return cached_key

    def set(self, transformed_key: bytes):
        if not self._hostname or self._hostname.isspace() or not self._secrets or self._profile != "cached_key":
            self._display.vv(u"Keepass: transformation cache key was NOT set [%s]" % self._location)
        else:
            vault = VaultLib(self._secrets)
            cache = FactCache()
            host_facts = cache.copy().get(self._hostname, {})
            keepass_list = host_facts.get(KeepassKeyCache._get_name_as_key(), [])
            keepass_list.append({"location": self._location, "transformed_key": to_text(vault.encrypt(base64.b64encode(transformed_key)))})
            host_facts[KeepassKeyCache._get_name_as_key()] = list({kp["location"]: kp for kp in keepass_list}.values())
            cache.update({self._hostname: host_facts})
            self._display.vv(u"Keepass: transformation cache key was set [%s]" % self._location)
