# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from typing import Union

from ansible.errors import AnsibleFilterError, AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins import display

from ansible_collections.dszryan.keepass.plugins import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache
from ansible_collections.dszryan.keepass.plugins.module_utils.request_term import RequestTerm


def do_lookup(value):
    try:
        display.v(u"keepass: lookup %s" % value["lookup"])
        database_details = DatabaseDetails(display, **value["database"].copy())                                                         # type: DatabaseDetails
        key_cache = KeepassKeyCache(None, database_details, display)                                                                    # type: KeepassKeyCache
        storage = KeepassDatabase(database_details, key_cache, display)                                                                 # type: KeepassDatabase
        outcome = storage.execute(RequestTerm(display, True, value["lookup"]).query, check_mode=False, fail_silently=False)["stdout"]   # type: dict
        outcome.pop("warnings", None)
        return next(enumerate(outcome.values()))[1] if "?" in value["lookup"] else outcome                                              # type: Union[str, dict]

    except Exception as error:
        raise AnsibleFilterError(AnsibleError(message=to_native(error), orig_exc=error))


class FilterModule(object):

    # noinspection PyMethodMayBeStatic
    def filters(self):
        return {
            'lookup': do_lookup
        }
