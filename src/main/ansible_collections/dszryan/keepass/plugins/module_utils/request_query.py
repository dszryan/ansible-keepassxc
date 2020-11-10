# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import re
from ast import literal_eval
from typing import Optional, Union

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display

TERM_PATTERN = re.compile(u"(?P<get_with_params>((?P<get>get)(?P<params>\\+[\\s\\S]*)?)|(?P<post>post)|(?P<put>put)|(?P<del>del))?://(?P<path>((?![#?])[\\s\\S])*)(\\?(?P<field>((?!#)[\\s\\S])*))?(#(?P<value>.*))?")  # type: re


class RequestQuery(object):
    read_only = False               # type: bool
    action = ""                     # type: Optional[str]
    path = ""                       # type: Optional[str]
    arguments = {"first": True}     # type: dict
    field = ""                      # type: Optional[str]
    value = None                    # type: Union[dict, str, None]

    def __init__(self, display: Display, read_only: bool, **entries):
        display.vv(u"Keepass: raw request - %s" % entries)
        self._update(read_only, **entries)
        self._validate()
        display.vv(u"Keepass: request is valid - %s" % self.__str__())

    def _update(self, read_only: bool, **entries):
        self.read_only = read_only
        if entries.get("term", None):
            match = TERM_PATTERN.search(entries.get("term"))
            self.action = next(action for action in match.group("get_with_params", "post", "put", "del") if action)
            self.path = match.group("path")
            self.field = match.group("field")
            self.value = match.group("value")

        entries.pop("term", None)
        self.__dict__.update(**entries)

        if self.path:
            self.arguments = dict(
                self.arguments,
                path="/".join(self.path.split("/")[:-1]),
                title=self.path.split("/")[-1]
            )

        if self.action:
            match = TERM_PATTERN.search(self.action + "://")
            self.action = next(action for action in match.group("get", "post", "put", "del") if action)
            self.arguments = {
                **self.arguments,
                **dict((param[0], literal_eval(param[1])) for param in map(lambda item: item.split("="), (match.group("params") or "=").strip("+").split("+")) if param[0])
            }

        if self.value and self.value.startswith('{'):
            self.value = json.loads(self.value)

    def _validate(self) -> None:
        try:
            if not self.action or self.action.isspace():
                raise AttributeError(u"Invalid request - no action")
            if self.read_only and self.action != "get":
                raise AttributeError(u"Invalid request - only get operations supported")
            if self.arguments.get("path", None) is None:
                raise AttributeError(u"Invalid request - no path")
            if not self.arguments.get("title", None) or self.arguments.get("title").isspace():
                raise AttributeError(u"Invalid request - no title")
            if self.action == "del" and self.value:
                raise AttributeError(u"Invalid request - cannot provide default/new value")
            if self.action in ["put", "post"]:
                if self.field:
                    raise AttributeError(u"Invalid request - cannot provide value for property")
                if not self.value:
                    raise AttributeError(u"Invalid request - need to provide insert/update value")
                if not isinstance(self.value, dict):
                    raise AttributeError(u"Invalid request - need to provide insert/update as a json")
                else:
                    if self.value.get("path", None):
                        raise AttributeError(u"Invalid request - path is already provided")
                    if self.value.get("title", None):
                        raise AttributeError(u"Invalid request - title is already provided")
        except AttributeError as error:
            raise AnsibleParserError(AnsibleError(message=to_native(error), orig_exc=error))

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
