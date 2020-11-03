# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import re

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.dszryan.keepass.plugins.module_utils.search import Search


class Query(object):
    _PATTERN = u"(get|put|post|del)?:\\/\\/(((?![#\\?])[\\s\\S])*)(\\?(((?!#)[\\s\\S])*))?(#(.*))?"

    def __init__(self, term):
        self.term = term

    @property
    def search(self):
        try:
            find_all = re.findall(Query._PATTERN, self.term)
            if len(find_all) != 1 or len(find_all[0]) != 8:
                raise AttributeError(u"Invalid term provided [%s]-[%s]" % (self.term, find_all))

            matches = find_all[0]
            return Search(
                action=matches[0] if matches[0] != "" else None,
                path=matches[1] if matches[1] != "" else None,
                field=matches[4] if matches[4] != "" else None,
                value=json.loads(matches[7]) if matches[7] != "" else matches[7],
                value_was_provided=matches[6] != ""
            )
        except AttributeError as error:
            raise AnsibleParserError(AnsibleError(message=to_native(error), orig_exc=error))

    def __str__(self):
        return json.dumps(self.__dict__)
