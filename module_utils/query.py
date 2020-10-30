# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
import traceback

import jmespath
from ansible.module_utils.common.text.converters import to_native


class Query(object):
    def __init__(self, display):
        self._display = display
        self.defaults = self._defaults

    @property
    def _defaults(self):
        return {
            'database': 'keepass.ansible'
        }

    def _get(self, search):
        pattern = "(get|put|post|del)(\\+(((?!:\\/\\/)[\\S])*))?(:\\/\\/(((?!#|\\?)[\\S])*))(\\?(((?!#)[\\s\\S])*)(#([\\s\\S]*))?)?"
        matches = re.findall(pattern, search)
        self._display.vv(u"Keepass: matches - %s}" % matches)

        query = {
            'verb': matches[0][0],
            'database': matches[0][2] or self.defaults["database"],
            'path': matches[0][5],
            'property': matches[0][8] or None,
            'default_value': matches[0][11] or None,
            'default_value_is_provided': matches[0][11] != ""
        }

        if not query["verb"]:
            raise AttributeError(u"'Invalid query - no verb")
        if not query["path"]:
            raise AttributeError(u"'Invalid query - no path")
        if query["verb"] == "del" and query["default_value"] is not None:
            raise AttributeError(u"'Invalid query - cannot provide default/new value")
        if query["verb"] in ["put", "post"]:
            if query["property"] is not None:
                raise AttributeError(u"'Invalid query - cannot provide value for property")
            if query["default_value"] is None:
                raise AttributeError(u"'Invalid query - need to provide insert/update value")

        return query

    def execute(self, storage, term, variables, read_only=True, check_mode=False):
        result = {'success': True, 'changed': False, 'stdout': {}, 'stderr': {}}

        try:
            result["query"] = self._get(term)
            self._display.v(u"Keepass: query - %s}" % result["query"])

            if read_only and result["query"]["verb"] != "get":
                raise AttributeError(u"'Invalid query - incorrect verb (should be 'get') - '%s'" % result["query"]["verb"])

            execute = getattr(storage, result["query"]["verb"])
            result["stdout"] = execute(jmespath.search(result["query"]["database"], variables), result["query"], check_mode)
            result["changed"] = result["query"]["verb"] != "get"

            return result
        except Exception as error:
            result["success"] = False
            result["stderr"] = {
                'term': term,
                'traceback': traceback.format_exc(),
                'error': to_native(error)
            }
            return result
