# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import importlib.util
import pathlib

from ansible.plugins import display
from ansible.plugins.lookup import LookupBase

DOCUMENTATION = """
name: keepass
author: 
version_added: "2.10"
short_description: 
description:
    - 
options:
  _terms:
    description: urls to query
  database:
    description: 
    type: str


"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        storage = Helper.import_util("storage", "Storage", display)
        query = Helper.import_util("query", "Query", storage, display, True, False)

        self.set_options(var_options=variables, direct=kwargs)
        database_details = self._templar.template(self.get_option("database"), fail_on_undefined=True)

        results = []
        for term in terms:
            display.v(u"Keepass: TYPE - %s" % type(term))
            results.append(query.execute(database_details, term))
        return results


class Helper(object):
    @staticmethod
    def import_util(module_name, class_name, *parameters):
        filename = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent.parent, './module_utils/' + module_name + '.py')
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, class_name)(*parameters)


# get://path/to/entry?property#default
# get://dummy
# get://dummy?password#
# get://dummy?custom1#value
# put://local/master#{username: "", password: ""}
# post://local/master#{username: "", password: ""}
# del://local/master?password
# del://local/master
