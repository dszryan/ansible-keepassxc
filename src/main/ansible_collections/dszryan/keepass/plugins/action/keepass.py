# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins import display
from ansible.plugins.action import ActionBase

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.search import Search
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query

DOCUMENTATION = """
module: keepass
short_description: integrates with keepass/keepassxc
description:e
  - provides integration with keepass to read/write entries
version_added: "2.4"
author:
  - develop <develop@local>
options:
  database:
    description:
      - templated value that would return the following structure
      - for the sample below, the value would be: {{ parent_name.read_only_database }} or {{ parent_name.updatable_database }}
      # ---
        parent_name:
          read_only_database:
            location: path of the database
            password: !vault |
                $ANSIBLE_VAULT;1.1;AES256 ...
            keyfile: path to the keyfile
            transformed_key:
            updatable: false    # this is the default value when not provided and and would only support I(action=get)
          updatable_database:
            location: path of the database
            password: !vault |
                $ANSIBLE_VAULT;1.1;AES256 ...
            keyfile: path to the keyfile
            transformed_key:
            updatable: true    # when explicitly provided as true, the database would support I(action=post), I(action=put) amd I(action=del)
    type: dict
  term:
    description:
      - provided in the format '{{ action }}://{{ path }}?{{ field }}#{{ value }}'
      - for the rules governing read the respective descriptions I(action), I(path), I(field) and I(value).
      - Mutually exclusive with I(action), I(path), I(), I(field) and I(value).
    type: str
    version_added: "1.0"
  action:
    description:
      - the action to perform on the keepass database
      - get is equivalent to select
      - post is equivalent to insert.
      - put is equivalent to upsert
      - del is equivalent to delete
      - Mutually exclusive with I(term).
    default: get
    choices:
      - get
      - post
      - put
      - del
    type: str
    version_added: "1.0"
  path:
    description:
      - the complete path to the entry in the database
      - it includes the title of the database
      - Mutually exclusive with I(term).
    type: str
    version_added: "1.0"
  field:
    description:
      - the field on the entry, can be a native property, custom property or name of the file in the entry
      - If I(action=get), when absent the whole entry is dumped and if supplied only the field value is returned
      - If I(action=del), when absent the whole entry is deleted and if supplied only the field value is cleared
      - Mutually exclusive with I(term) and I(action=post) and I(action=put)
    type: str
    version_added: "1.0"
  value:
    description:
      - If I(action=get), if an entry is found and it the field has no value, the default (str) value is returned. else an exception is raised.
      - If I(action=post) or I(action=put), the value provided (json) is used to update the database.
      - Required if I(action=post) or I(action=put)
      - Mutually exclusive with I(term) and I(action=del).
    type: str or json
    version_added: "1.0"
  check_mode:
    description:
      - ensures all operation do not affect the database
      - If I(action=post) or I(action=put) or I(action=del), operations are performed mocked and not changes are made to the database.
      - If I(action=get), I(value) is ignored and an exception is raised if the field is none or empty.
    default: false
    choices:
      - false
      - true
    type: bool
    version_added: "1.0"
  fail_silently:
    description:
      - when true, exception raised are muted and returned as part of the result.
      - when false, an exception raised will halt any further executions
    default: false
    choices:
      - false
      - true
    type: bool
    version_added: "1.0"
requirements:
  - pykeepass = "*"
"""

EXAMPLES = """
- name: dump the whole entity
  keepass:
    term: get://path/to/entity    
- name: get only one field and raise an exception if not found
  keepass:
    term: get://path/to/entity?field_name
- name: get only one field and return the default value if not found
  keepass:
    term: get://path/to/entity?field_name#default_value
- name: insert an entity, throw an exception if value already exists. note json requires " for delimitation and cannot replaced with ' or `
  keepass:
    term: post://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }
- name: upsert an entity, overwrite if already exists. note json requires " for delimitation and cannot replaced with ' or `
  keepass:
    term: put://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }
- name: delete an entity. raise an exception if not exists
  keepass:
    term: del://path/to/entity
- name: clear a field, raise an exception if the entity does not exists or the field does not exists or has no value
  keepass:
    term: del://path/to/entity?field
"""

RETURN = """
result:
  description: the result of the query execution
  type: complex
  contains:
    search:
      description: the query that was executed
    result:
      description: when not failed the result of the query. and when failed and fail_silently the error details
"""


class ActionModule(ActionBase):

    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("database", "term", "action", "path", "field", "value", "check_mode", "fail_silently"))
    _search_args = ["action", "path", "field", "value"]

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        display.vvv("keepass: args - %s" % list(({key: value} for key, value in self._task.args.items() if key != "database")))
        if self._task.args.get("term", None) is not None and len(set(self._search_args).intersection(set(self._task.args.keys()))) > 0:
            raise AnsibleParserError(AnsibleError(u"'term' is mutually exclusive with %s" % self._search_args))

        search = Query(display, False, self._task.args["term"]).search if self._task.args.get("term", None) is not None else \
            Search(display=display,
                   read_only=False,
                   action=self._task.args.get("action", None),
                   path=self._task.args.get("path", None),
                   field=self._task.args.get("field", None),
                   value=self._task.args.get("value", None),
                   value_was_provided=self._task.args.get("value", None) is not None)

        return KeepassDatabase(display, self._task.args.get("database", None)).\
            execute(search, self._task.args.get("check_mode", False), self._task.args.get("fail_silently", False))
