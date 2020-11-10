# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from typing import Union, AnyStr

from ansible.errors import AnsibleFilterError, AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins import display
from ansible_collections.dszryan.keepass.plugins.common import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache
from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery


class FilterModule(object):

    # noinspection PyMethodMayBeStatic
    def filters(self):
        return {
            'lookup': FilterModule.do_lookup
        }

    @staticmethod
    def do_lookup(value):
        try:
            display.v(u"keepass: lookup %s" % value["lookup"])
            database_details = DatabaseDetails(display, **value["database"].copy())                 # type: DatabaseDetails
            key_cache = KeepassKeyCache(display, database_details, None)                            # type: KeepassKeyCache
            database = KeepassDatabase(display, database_details, key_cache)                        # type: KeepassDatabase
            query = RequestQuery(display, read_only=True, term=value["lookup"])                     # type: RequestQuery
            return database.execute(query, check_mode=False, fail_silently=False)["stdout"]         # type: Union[dict, AnyStr, None]

        except Exception as error:
            raise AnsibleFilterError(AnsibleError(message=to_native(error), orig_exc=error))
