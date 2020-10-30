# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
import traceback

import jmespath
from ansible.module_utils.common.text.converters import to_native


class Query(object):
    def __init__(self, storage, display, read_only=True, check_mode=False):
        self._storage = storage
        self._display = display
        self._read_only = read_only
        self._check_mode = check_mode

    @staticmethod
    def _parse(term):
        pattern = "(get|put|post|del)(\\+(((?!:\\/\\/)[\\S])*))?(:\\/\\/(((?!#|\\?)[\\S])*))(\\?(((?!#)[\\s\\S])*)(#([\\s\\S]*))?)?"
        matches = re.findall(pattern, term)

        return {
            'action': matches[0][0],
            'database_path': matches[0][2] or None,
            'path': matches[0][5],
            'property': matches[0][8] or None,
            'value': matches[0][11] or None,
            'value_is_provided': matches[0][11] != ""
        }

    @staticmethod
    def _validate(database, query, read_only):
        if database is None or not isinstance(database, type({})):
            raise AttributeError(u"Invalid query - no database details")
        if query.get("action", "") == "":
            raise AttributeError(u"Invalid query - no action")
        if read_only and query["action"] != "get":
            raise AttributeError(u"Invalid query - incorrect action (should be 'get')")
        if query.get("path", "") == "":
            raise AttributeError(u"Invalid query - no path")
        if query["action"] == "del" and query("value", None) is not None:
            raise AttributeError(u"Invalid query - cannot provide default/new value")
        if query["action"] in ["put", "post"]:
            if query("property", None) is not None:
                raise AttributeError(u"Invalid query - cannot provide value for property")
            if query("value", None) is None:
                raise AttributeError(u"Invalid query - need to provide insert/update value")

    def execute(self, search):
        result = {
            'success': True,
            'changed': False,
            'term':  search.get("term", None),
            'query': search.get("query", None),
            'stdout': {},
            'stderr': {}
        }

        try:
            if result["query"] is None:     # NB: called from lookup plugin
                result["query"] = self._parse(result["term"])
                search["database"] = jmespath.search(result["query"]["database_path"], search["variables"])

            Query._validate(search["database"], result["query"], self._read_only)
            self._display.v(u"Keepass: query - %s}" % result["query"])

            execute_action = getattr(self._storage, result["query"]["action"])
            result["stdout"] = execute_action(search["database"], result["query"], self._check_mode)
            result["changed"] = result["query"]["action"] != "get"

        except Exception as error:
            result["success"] = False
            result["stderr"] = {
                'traceback': traceback.format_exc(),
                'error': to_native(error)
            }

        return result
