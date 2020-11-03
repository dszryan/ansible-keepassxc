# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.plugins import display
from ansible.plugins.lookup import LookupBase

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query

DOCUMENTATION = """
module: lookup
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
  _terms:
    description:
      - provided in the format '{{ action }}://{{ path }}?{{ field }}#{{ value }}'
      - for the rules governing read the respective descriptions I(action), I(path), I(field) and I(value) in M(keepass)
    type: list
    required: true
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
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: dump the multiple entity
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity, get://path/to/another, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: get only one field and raise an exception if not found
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity?field_name, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: get only one field and return the default value if not found
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', get://path/to/entity?field_name#default_value, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: insert an entity, throw an exception if value already exists. note json requires " for delimitation and cannot replaced with ' or `
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', post://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: upsert an entity, overwrite if already exists. note json requires " for delimitation and cannot replaced with ' or `
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', put://path/to/entity#{"username": "value", "custom": "value", "attachments": [{"filename": "file content as base64k encoded"}] }, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: delete an entity. raise an exception if not exists
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', del://path/to/entity, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
- name: clear a field, raise an exception if the entity does not exists or the field does not exists or has no value
  set_fact:
    keepass: "{{ lookup('dszryan.keepass.lookup', del://path/to/entity?field, database=parent_name.read_only_database, check_mode=false, fail_silently=false) }}"    
"""

RETURN = """
outcome:
  description: the outcome of the query execution
  type: complex
  contains:
    search:
      description: the query that was executed
    result:
      description: when not failed the result of the query. and when failed and fail_silently the error details
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        storage = KeepassDatabase(display, self.get_option("database"))
        check_mode = self._task.args.get("check_mode", False)
        fail_silently = self._task.args.get("fail_silently", True)
        storage = KeepassDatabase(display, self.get_option("database"))

        return list(map(lambda term: storage.execute(Query(term).search, check_mode=check_mode, fail_silently=fail_silently), terms))
