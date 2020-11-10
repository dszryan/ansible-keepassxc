# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import traceback

from ansible.errors import AnsibleParserError, AnsibleError
from ansible_collections.dszryan.keepass.plugins.common import DatabaseDetails
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_key_cache import KeepassKeyCache
from ansible_collections.dszryan.keepass.plugins.module_utils.request_query import RequestQuery

# noinspection PyBroadException
try:
    JMESPATH_IMP_ERR = None
    import jmespath
except Exception as import_error:
    JMESPATH_IMP_ERR = traceback.format_exc()
    JMESPATH_IMP_EXP = import_error

from ansible.plugins.action import ActionBase


DOCUMENTATION = """
    module: keepass
    short_description: integrates with keepass/keepassxc
    description:
        - provides integration with keepass to read/write entries
    version_added: "2.10"
    author:
        - develop <develop@local>
    options:
        database:
            description:
                - jmespath that points to a dictionary with the database details (sample below)
                -
                - (sample database details definition)
                - keepass_dbs:
                -   read_only_database:
                -     location: path of the database
                -     password: !vault |
                -         $ANSIBLE_VAULT;1.1;AES256 ...
                -     keyfile: path to the keyfile
                -     transformed_key: None
                -     profile: throughput
                -     updatable: false        # this is the default value when not provided and and would only support I(action=get)
                -   updatable_database:
                -     location: path of the database
                -     password: !vault |
                -         $ANSIBLE_VAULT;1.1;AES256 ...
                -     keyfile: path to the keyfile
                -     transformed_key: None
                -     profile: uncached
                -     updatable: true        # when explicitly provided as true, the database would support I(action=post), I(action=put) amd I(action=del)
            type: str
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
        - jmespath = "*"
        - pykeepass = "*"
"""

EXAMPLES = """
  - name: dump the whole entity
    keepass:
      term: get://path/to/entity
      database: keepass_dbs.read_only_database
  - name: get only one field and raise an exception if not found
    keepass:
      term: get://path/to/entity?field_name
      database: keepass_dbs.read_only_database
  - name: get only one field and return the default value if not found
    keepass:
      term: get://path/to/entity?field_name#default_value
      database: keepass_dbs.read_only_database
  - name: insert an entity, throw an exception if value already exists. note json requires " for delimitation and cannot replaced with ' or `
    keepass:
      term: post://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }
      database: keepass_dbs.updatable_database
  - name: upsert an entity, overwrite if already exists. note json requires " for delimitation and cannot replaced with ' or `
    keepass:
      term: put://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }
      database: keepass_dbs.updatable_database
  - name: delete an entity. raise an exception if not exists
    keepass:
      term: del://path/to/entity
      database: keepass_dbs.updatable_database
  - name: clear a field, raise an exception if the entity does not exists or the field does not exists or has no value
    keepass:
      term: del://path/to/entity?field
      database: keepass_dbs.updatable_database
"""

RETURN = """
    query:
        description: the query that was executed
        returned: always
        type: dict
        contains:
            read_only:
                description: an indication if write operations are supported
                returned: always
                type: bool
            action:
                description: the action requested
                returned: success
                type: str
            path:
                description: path to the entry
                returned: success
                type: str
            field:
                description: trace back to the raised exception
                returned: success, when provided
                type: str
            value:
                description: the value provided (default value for get operation, insert value for post, upsert value for put)
                returned: success, when provided
                type: str
    stdout:
        description: dictionary representing the requested data
        returned: success
        type: dict
    stderr:
        description: exception details, when and exception was raised and fail_silently is set
        returned: not success and I(fail_silently=True)
        type: dict
        contains:
            trace:
                description: trace back to the raised exception
                returned: always
                type: str
            error:
                description: the original exception that was raised
                returned: always
                type: str
"""


class ActionModule(ActionBase):

    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("database", "term", "action", "path", "field", "value", "fail_silently"))
    # _search_args = ["action", "path", "field", "value"]

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        super(ActionModule, self).run(tmp, task_vars)
        if JMESPATH_IMP_ERR:
            raise AnsibleParserError(AnsibleError(message=JMESPATH_IMP_ERR, orig_exc=JMESPATH_IMP_EXP))

        self._display.v(u"keepass: args - %s" % self._task.args.items())
        database_details = DatabaseDetails(self._display, **jmespath.search(self._task.args.get("database", None), task_vars).copy())   # type: DatabaseDetails
        key_cache = KeepassKeyCache(self._display, database_details, task_vars.get('inventory_hostname', None))                         # type: KeepassKeyCache
        database = KeepassDatabase(self._display, database_details, key_cache)                                                          # type: KeepassDatabase
        query = RequestQuery(self._display,
                             read_only=False,
                             term=self._task.args.get("term", None),
                             action=self._task.args.get("action", None),
                             path=self._task.args.get("path", None),
                             field=self._task.args.get("field", None),
                             value=self._task.args.get("value", None))                                                                  # type: RequestQuery

        return database.execute(query, self._play_context.check_mode, self._task.args.get("fail_silently", False))                      # type: dict
