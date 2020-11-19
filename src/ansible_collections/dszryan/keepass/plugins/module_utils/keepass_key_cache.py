# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import json
from os import PathLike
from typing import Union, Optional, AnyStr

from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.test.core import vault_encrypted
from ansible.utils.display import Display

from ansible_collections.dszryan.keepass.plugins.module_utils.database_details import DatabaseDetails


class KeepassKeyCache(object):
    def __init__(self, display: Display, details: DatabaseDetails, hostname: Optional[str]):
        self._hostname = hostname                               # type: Optional[str]
        self._location = details.location                       # type: PathLike
        self._display = display                                 # type: Display
        self._secrets = KeepassKeyCache.get_secrets(details)    # type: Optional[bytes]
        self.has_secrets = True if self._secrets else False
        self.can_cache = self._hostname and not self._hostname.isspace() and self.has_secrets and details.profile == "throughput"
        self._display.vv(u"Keepass: transformation caching is%s possible [%s]" % (("" if self.can_cache else " not"), details.location))

    @staticmethod
    def fact_name() -> str:
        return "_".join(globals()["__name__"].split(".")[1:3])

    @staticmethod
    def get_secrets(details: DatabaseDetails) -> Optional[bytes]:
        if details.password and vault_encrypted(details.password):
            return details.password.vault.secrets
        elif details.transformed_key and vault_encrypted(details.transformed_key):
            return details.transformed_key.vault.secrets
        return None

    def get(self) -> Optional[bytes]:
        if not self.can_cache:
            return None

        from ansible.parsing.vault import VaultLib
        from ansible.vars.fact_cache import FactCache
        vault = VaultLib(self._secrets)
        cache = FactCache()
        host_ansible_local = cache.copy().get(self._hostname, {}).get("ansible_local", {}) or {}        # type: dict
        keepass_location = ([key for key in host_ansible_local.get(KeepassKeyCache.fact_name(), [])
                             if key.get("location", "") == self._location] or [None])[0]                # type: Union[dict, None]
        cached_key = base64.decodebytes(vault.decrypt(keepass_location.get("transformed_key"))) if keepass_location else None
        self._display.vv(u"Keepass: transformation cache key was%s found [%s]" % (("" if cached_key else " not"), self._location))
        return cached_key

    def set(self, transformed_key: bytes):
        if not self.can_cache:
            self._display.vv(u"Keepass: transformation cache key CANNOT be set [%s]" % self._location)
        else:
            from ansible.parsing.vault import VaultLib
            from ansible.vars.fact_cache import FactCache
            vault = VaultLib(self._secrets)
            cache = FactCache()
            host_facts = cache.copy().get(self._hostname)
            host_ansible_local = host_facts.get("ansible_local")
            keepass_list = host_ansible_local.get(KeepassKeyCache.fact_name()) or []
            keepass_list.append({"location": self._location, "transformed_key": to_text(vault.encrypt(base64.b64encode(transformed_key)))})

            host_ansible_local[KeepassKeyCache.fact_name()] = list({kp["location"]: kp for kp in keepass_list}.values())
            host_facts["ansible_local"] = host_ansible_local
            cache.update({self._hostname: host_facts})
            self._display.vv(u"Keepass: transformation cache key was set [%s]" % self._location)

    # noinspection PyBroadException
    def encrypt(self, plain_text: AnyStr) -> Optional[str]:
        result: Optional[str] = None
        try:
            from ansible.parsing.ajson import AnsibleJSONDecoder
            if plain_text:
                _ = json.loads(plain_text, cls=AnsibleJSONDecoder)
                result = plain_text
        except:
            pass
        finally:
            if not result:
                if not self._secrets:
                    result = None
                else:
                    from ansible.module_utils.common.json import AnsibleJSONEncoder
                    from ansible.parsing.vault import VaultLib
                    vault_value = dict(__ansible_vault=VaultLib(self._secrets).encrypt(plaintext=plain_text).decode())
                    result = json.dumps(vault_value, cls=AnsibleJSONEncoder, sort_keys=True, indent=4, preprocess_unsafe=True)

        return result
