# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import importlib.util
import pathlib

from ansible.plugins.lookup import LookupBase


class Helper:
    @staticmethod
    def import_util(module_name, class_name, *parameters):
        filename = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent.parent, './module_utils/' + module_name + '.py')
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, class_name)(*parameters)


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        storage = Helper.import_util("storage", "Storage")
        query = Helper.import_util("query", "Query")

        results = []
        for term in terms:
            results.append(query.execute(storage, term, variables))

        return results
