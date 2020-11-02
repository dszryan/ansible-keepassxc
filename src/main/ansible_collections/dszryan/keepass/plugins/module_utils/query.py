# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import re
import traceback

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native


class Query(object):
    def __init__(self, display, storage, check_mode=False, fail_silently=True):
        self._display = display
        self._storage = storage
        self._check_mode = check_mode
        self._fail_silently = fail_silently

    @staticmethod
    def _parse(term, display):
        pattern = "(get|put|post|del):\\/\\/([\\w/]*)(\\?([\\s\\S]*))?(#([\\s\\S]*))?"
        matches = re.findall(pattern, term)
        display.vv(u"Keepass: matches - [%s]" % matches)

        return {
            "action": matches[0][0],
            "path": matches[0][1],
            "property": (matches[0][3] if matches[0][3] != "" else None),
            "value": (json.loads(matches[0][5]) if matches[0][5] != "" else None),
            "value_is_provided": matches[0][5] != ""
        }
    # json.load(matches[0][5]) if matches[0][5] is not None else None,

    @staticmethod
    def _validate(database_details, query):
        if database_details is None or not isinstance(database_details, type({})):
            raise AttributeError(u"Invalid query - no database details")
        if query.get("action", "") == "":
            raise AttributeError(u"Invalid query - no action")
        if not database_details.get("updatable", False) and query["action"] != "get":
            raise AttributeError(u"Invalid query - database is not 'updatable'")
        if query.get("path", "") == "":
            raise AttributeError(u"Invalid query - no path")
        if query["action"] == "del" and query("value", None) is not None:
            raise AttributeError(u"Invalid query - cannot provide default/new value")
        if query["action"] in ["put", "post"]:
            if query("property", None) is not None:
                raise AttributeError(u"Invalid query - cannot provide value for property")
            if query("value", None) is None:
                raise AttributeError(u"Invalid query - need to provide insert/update value")
            if query["value"].get("title", None) is not None:
                raise AttributeError(u"Invalid query - title is already provided in path")

    def execute(self, database_details, query):
        return_value = {
            "changed": False,
            "failed": False,
            "outcome": {
                "query": query,
                "result": {}
            }
        }

        try:
            if not isinstance(query, type({})):
                self._display.v(u"Keepass: term - %s" % query)
                return_value["outcome"]["query"] = self._parse(query, self._display)

            Query._validate(database_details, return_value["outcome"]["query"])
            self._display.v(u"Keepass: query - %s" % return_value["outcome"]["query"])

            execute_action = getattr(self._storage, return_value["outcome"]["query"]["action"])
            return_value["changed"], return_value["outcome"]["result"] = \
                execute_action(database_details, return_value["outcome"]["query"], self._check_mode)

        except Exception as error:
            return_value["failed"] = True
            return_value["outcome"]["result"] = {
                "traceback": traceback.format_exc(),
                "error": to_native(error)
            }

            if not self._fail_silently:
                raise AnsibleParserError(AnsibleError(return_value))

        return return_value
