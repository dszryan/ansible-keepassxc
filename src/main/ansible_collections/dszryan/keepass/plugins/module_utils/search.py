# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Union

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native


class Search(object):
    def __init__(self, display, read_only: bool, action: str, path: str, field: str, value: dict, value_was_provided: bool):
        self.read_only = read_only                                                                      # type: bool
        self.action = action                                                                            # type: str
        self.path = path                                                                                # type: str
        self.field = field                                                                              # type: str
        self.value = json.loads(value) if isinstance(value, str) and value.startswith('{') else value   # type: Union[str, dict]
        self.value_was_provided = value_was_provided                                                    # type: bool
        self._validate()
        display.vvv(u"Keepass: valid search - %s" % self.__str__())

    def _validate(self):
        try:
            if self.action is None or self.action == "":
                raise AttributeError(u"Invalid query - no action")
            if self.read_only and self.action != "get":
                raise AttributeError(u"Invalid query - only get operations supported")
            if self.path is None or self.path == "":
                raise AttributeError(u"Invalid query - no path")
            if self.action == "del" and not (self.value is None or self.value == ""):
                raise AttributeError(u"Invalid query - cannot provide default/new value")
            if self.action in ["put", "post"]:
                if self.field is not None or self.field == "":
                    raise AttributeError(u"Invalid query - cannot provide value for property")
                if not self.value_was_provided:
                    raise AttributeError(u"Invalid query - need to provide insert/update value")
                if not isinstance(self.value, dict):
                    raise AttributeError(u"Invalid query - need to provide insert/update as a json")
                else:
                    if self.value.get("path", None) is not None:
                        raise AttributeError(u"Invalid query - path is already provided")
                    if self.value.get("title", None) is not None:
                        raise AttributeError(u"Invalid query - title is already provided")
        except AttributeError as error:
            raise AnsibleParserError(AnsibleError(message=to_native(error), orig_exc=error))

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
