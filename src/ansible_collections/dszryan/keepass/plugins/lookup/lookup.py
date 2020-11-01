# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins import display
from ansible.plugins.lookup import LookupBase

from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query
from ansible_collections.dszryan.keepass.plugins.module_utils.storage import Storage

DOCUMENTATION = """
name: keepass
author: develop <develop@local>
short_description: 
description:
    - asdf
options:
  _terms:
    description: urls to query
  database:
    description: 
    type: template
  fail_silently:
    description: 
    type: bool
    default: true
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        storage = Storage(display)
        query = Query(display, storage, False, self.get_option("fail_silently"))
        database_details = self._templar.template(self.get_option("database"), fail_on_undefined=True)

        return list(map(lambda term: query.execute(database_details, term), terms))
