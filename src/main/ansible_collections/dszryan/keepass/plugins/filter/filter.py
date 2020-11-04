# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleFilterError
from ansible.plugins import display

from ansible_collections.dszryan.keepass.plugins.module_utils.keepass_database import KeepassDatabase
from ansible_collections.dszryan.keepass.plugins.module_utils.query import Query


def do_lookup(value):
    if not isinstance(value, dict) or value.get("database", None) is None or value.get("lookup", None) is None:
        raise AnsibleFilterError("must be a dictionary providing the following elements database (must a valid database description) and lookup")
    display.vvv("keepass: lookup %s" % value["lookup"])
    outcome = KeepassDatabase(display, value["database"]).execute(Query(display, True, value["lookup"]).search, check_mode=False, fail_silently=False)["result"]["outcome"]
    return next(enumerate(outcome.values()))[1] if "?" in value["lookup"] else outcome


class FilterModule(object):

    def filters(self):
        return {
            'lookup': do_lookup,
        }
