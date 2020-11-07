# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Union, Optional

from ansible.errors import AnsibleParserError, AnsibleError
from ansible.module_utils.common.text.converters import to_native


class RequestQuery(object):
    def __init__(self, display, read_only: bool, action: str, path: str, field: Optional[str], value: Union[dict, str, None]):
        self.read_only = read_only                                                      # type: bool
        self.action = action                                                            # type: str
        self.path = path                                                                # type: str
        self.field = field                                                              # type: Optional[str]
        self.value = json.loads(value) if value and value.startswith('{') else value    # type: Union[dict, str, None]
        self._validate()
        display.vvv(u"Keepass: valid request - %s" % self.__str__())

    def _validate(self):
        try:
            if not self.action or self.action.isspace():
                raise AttributeError(u"Invalid request - no action")
            if self.read_only and self.action != "get":
                raise AttributeError(u"Invalid request - only get operations supported")
            if not self.path or self.path.isspace():
                raise AttributeError(u"Invalid request - no path")
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
