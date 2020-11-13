# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from typing import Union, List, AnyStr

from ansible.plugins.lookup import LookupBase

from ansible_collections.dszryan.keepass.plugins.module_utils.database_details import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache
from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery

DOCUMENTATION = """
    module: lookup
    author: 
        - develop <develop@local>
    short_description: integrates with keepass/keepassxc
    description:
        - provides integration with keepass to read/write entries
    version_added: "2.10"
    options:
        _terms:
            description:
                - provided in the format '{{ action }}://{{ path }}?{{ field }}#{{ value }}'
                - for the rules governing read the respective descriptions I(action), I(path), I(field) and I(value) in M(keepass)
            required: True
            type: list
            version_added: "1.0"
        database:
            description:
                - templated value that would location a dictionary value defining the keepass database
            type: dict
            required: True
            version_added: "1.0"
        fail_silently:
            description:
                - when true, exception raised are muted and returned as part of the result.
                - when false, an exception raised will halt any further executions
            default: False
            type: bool
            choices:
                - False
                - True
    requirements:
        - pykeepass = "*"
    notes:
        - the lookup will only permit get/read operations
        - to make changes to the keepass database use the action module instead
"""

EXAMPLES = r"""
  - name: dump the whole entity
    set_fact:
      keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity, database=parent_name.read_only_database, fail_silently=false) }}"    
  - name: dump the multiple entity
    set_fact:
      keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity, get://path/to/another, database=parent_name.read_only_database, fail_silently=false) }}"    
  - name: get only one field and raise an exception if not found
    set_fact:
      keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity?field_name, database=parent_name.read_only_database, fail_silently=false) }}"    
  - name: get only one field and return the default value if not found
    set_fact:
      keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity?field_name#default_value, database=parent_name.read_only_database, fail_silently=false) }}"    
"""


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        self._display.v(u"keepass: terms %s" % terms)

        database_details = DatabaseDetails(self._display, **self.get_option("database", {}).copy())                 # type: DatabaseDetails
        key_cache = KeepassKeyCache(self._display, database_details, variables.get("inventory_hostname", None))     # type: KeepassKeyCache
        database = KeepassDatabase(self._display, database_details, key_cache)                                      # type: KeepassDatabase
        fail_silently = self.get_option("fail_silently", False)                                                     # type: bool

        return list(map(lambda term:
                        database.execute(
                            RequestQuery(self._display,
                                         read_only=True,
                                         term=term),
                            check_mode=False,
                            fail_silently=fail_silently).get("stdout", None),
                        terms))                                                                                     # type: List[Union[list, dict, AnyStr, None]]
