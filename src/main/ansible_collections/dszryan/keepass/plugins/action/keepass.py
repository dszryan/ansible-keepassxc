# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins import display
from ansible.plugins.action import ActionBase
from ansible_collections.dszryan.keepass.plugins.module_utils.storage import Storage
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query


class ActionModule(ActionBase):

    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("database", "term", "action", "path", "property", "default", "upsert", "check_mode", "fail_silently"))

    _search_args = ["action", "path", "property", "default", "upsert"]

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        storage = Storage(display)
        query = Query(display, storage, self._task.args.get("check_mode", False), self._task.args.get("fail_silently", False))
        if self._task.args.get("term", None) is not None and self._search_args in self._task.args.keys():
            raise AnsibleParserError(AnsibleError(u"'term' is mutually exclusive with %s" % self._search_args))

        search = self._task.args["term"] if self._task.args.get("term", None) is not None else {
            "action": self._task.args.get("action", None),
            "path": self._task.args.get("path", None),
            "property": self._task.args.get("property", None) or None,
            "value": (self._task.args.get("default", None) if self._task.args.get("action", None) == "get" else self._task.args.get("upsert", None)) or None,
            "value_is_provided": (self._task.args.get("default", None) if self._task.args.get("action", None) == "get" else self._task.args.get("upsert", None)) is not None
        }

        return query.execute(self._task.args.get("database", None), search)
