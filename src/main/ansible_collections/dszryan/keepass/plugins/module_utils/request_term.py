# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import re

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display

from ansible_collections.dszryan.keepass.plugins.module_utils import RequestQuery


class RequestTerm(object):

    _PATTERN = re.compile(u"(get|put|post|del)?:\\/\\/(((?![#\\?])[\\s\\S])*)(\\?(((?!#)[\\s\\S])*))?(#(.*))?")     # type: re

    def __init__(self, display: Display, read_only: bool, term: str):
        self._display = display         # type: Display
        self.read_only = read_only      # type: bool
        self.term = term                # type: str

    @property
    def query(self) -> RequestQuery:
        try:
            find_all = RequestTerm._PATTERN.findall(self.term)
            self._display.vvvv(u"Keepass: find_all - [%s]" % find_all)
            if len(find_all) != 1 or len(find_all[0]) != 8:
                raise AttributeError(u"Invalid term provided [%s]-[%s]" % (self.term, find_all))

            matches = find_all[0]
            self._display.vvv(u"Keepass: matches - [%s]" % to_native(matches))
            return RequestQuery(
                display=self._display,
                read_only=self.read_only,
                action=matches[0] if matches[0] != "" else None,
                path=matches[1] if matches[1] != "" else None,
                field=matches[4] if matches[4] != "" else None,
                value=matches[7] if matches[6] != "" else None
            )
        except AttributeError as error:
            raise AnsibleParserError(AnsibleError(message=to_native(error), orig_exc=error))

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
