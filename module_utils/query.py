# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re

import jmespath
from ansible.errors import AnsibleParserError
from ansible.utils.display import Display

display = Display()


class Query(object):
    def __init__(self):
        self.defaults = self.get_defaults

    def __get__(self, search):
        pattern = "(get|put|post|del)(@(((?!:\\/\\/)[\\S])*))?(:\\/\\/(((?!#|\\?)[\\S])*))(\\?(((?!#)[\\s\\S])*)(#([\\s\\S]*))?)?"
        matches = re.findall(pattern, search)
        display.vv(u"Keepass: matches - %s}" % matches)

        query = {
            'verb': matches[0][0],
            'database': matches[0][2] or self.defaults["database"],
            'path': matches[0][5],
            'property': matches[0][8] or None,
            'default_value': matches[0][11] or None,
            'default_value_is_provided': matches[0][11] != ""
        }

        if not query["verb"]:
            raise AnsibleParserError(AttributeError(u"'Invalid query - no verb '%s'" % query))
        if not query["path"]:
            raise AnsibleParserError(AttributeError(u"'Invalid query - no path '%s'" % query))

        return query

    @property
    def get_defaults(self):
        return {
            'database': 'keepass.ansible'
        }

    def execute(self, storage, term, variables, read_only=True, check_mode=False):
        result = {
            'success': True,
            'changed': False
        }

        try:
            result["query"] = self.__get__(term)
            display.v(u"Keepass: query - %s}" % result["query"])

            if read_only and result["query"]["verb"] != "get":
                raise AnsibleParserError(AttributeError(u"'Invalid query - incorrect verb '%s' (get only supported)" % result["query"]["verb"]))

            execute = getattr(storage, result["query"]["verb"])
            result["stdout"] = execute(jmespath.search(result["query"]["database"], variables), result["query"], check_mode)
            result["changed"] = result["query"]["verb"] != "get"

            return result
        except Exception as error:
            result["success"] = False
            result["stderr"] = error
            return result
