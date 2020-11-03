# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins import display
from ansible.plugins.action import ActionBase

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.search import Search
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query


class ActionModule(ActionBase):

    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("database", "term", "action", "path", "field", "value", "check_mode", "fail_silently"))
    _search_args = ["action", "path", "field", "value"]

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        if self._task.args.get("term", None) is not None and len(set(self._search_args).intersection(set(self._task.args.keys()))) > 0:
            raise AnsibleParserError(AnsibleError(u"'term' is mutually exclusive with %s" % self._search_args))

        search = Query(self._task.args["term"]).search if self._task.args.get("term", None) is not None else \
            Search(action=self._task.args.get("action", None),
                   path=self._task.args.get("path", None),
                   field=self._task.args.get("field", None),
                   value=self._task.args.get("value", None),
                   value_was_provided=self._task.args.get("value", None) is not None)

        return KeepassDatabase(display, self._task.args.get("database", None)).\
            execute(search, self._task.args.get("check_mode", False), self._task.args.get("fail_silently", False))
