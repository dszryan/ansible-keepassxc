# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins import display
from ansible.plugins.lookup import LookupBase

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query

DOCUMENTATION = """
name: keepass
author: develop <develop@local>
short_description: 
description: 
options:
  _terms:
    description: 
  database:
    description: 
    type: template
  check_mode:
    description: 
    type: bool
    default: false
  fail_silently:
    description: 
    type: bool
    default: true
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        storage = KeepassDatabase(display, self.get_option("database"))
        check_mode = self._task.args.get("check_mode", False)
        fail_silently = self._task.args.get("fail_silently", True)
        storage = KeepassDatabase(display, self.get_option("database"))

        return list(map(lambda term: storage.execute(Query(term).search, check_mode=check_mode, fail_silently=fail_silently), terms))
