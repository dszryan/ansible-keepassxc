# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Union, List, Tuple, AnyStr

from ansible.module_utils.common.text.converters import to_native


class RequestResult(object):
    def __init__(self, query: dict, warnings: List[str] = None):
        self.changed = False    # type: bool
        self.failed = False     # type: bool
        self.query = query      # type: dict
        if warnings:
            self.warnings = warnings

    def success(self, result: Tuple[bool, Union[list, dict, AnyStr, None]]):
        self.changed = result[0]
        setattr(self, "stdout", result[1])

    def fail(self, result: Tuple[str, Exception]):
        self.failed = True
        setattr(self, "stderr", {
            "trace": to_native(result[0]),
            "message": to_native(result[1])
        })

    def __str__(self) -> str:
        return json.dumps(self.__dict__)
