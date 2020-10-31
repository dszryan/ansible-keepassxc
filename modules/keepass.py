import importlib
import json
import pathlib

from ansible.module_utils.basic import AnsibleModule
from ansible.plugins import display

DOCUMENTATION = """
name: keepass
author: 
version_added: "2.10"
short_description: 
description:
"""


def __main__():
    module = AnsibleModule(
        argument_spec=dict(
            database=dict(type="template", required=True),
            action=dict(type="str", required=True, default="select", choices=["select", "insert", "update", "delete"]),
            path=dict(type="str", required=True),
            property=dict(type="str", required=False, default=None),
            default=dict(type="str", required=False, default=None),
            upsert=dict(type=type({}), required=False, default=None),
            fail_silently=dict(type="bool", required=False, default=False)
        ),
        supports_check_mode=True,
        required_if=[
            ("action", "insert", ["property"], False),
            ("action", "insert", ["upsert"], True),

            ("action", "update", ["property"], False),
            ("action", "update", ["upsert"], True),

            ("action", "delete", ["default", "upsert"], False)
        ]
    )

    storage = Helper.import_util("storage", "Storage", display)
    query = Helper.import_util("query", "Query", storage, display, module.check_mode, True)
    search = {
        "action": module.params["action"],
        "path": module.params["path"],
        "property": module.params["property"],
        "value": module.params["default"] if module.params["action"] == "get" else module.params["upsert"],
        "value_is_provided": (module.params["default"] if module.params["action"] == "get" else module.params["upsert"]) != ""
    }

    result = query.execute(module.params["database"], search)
    (module.fail_json if not module.params["fail_silently"] and result["stderr"] != {} else module.exit_json)(msg=json.dumps(result))


class Helper:
    @staticmethod
    def import_util(module_name, class_name, *parameters):
        filename = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent, "./module_utils/" + module_name + ".py")
        spec = importlib.util.spec_from_file_location(module_name, filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, class_name)(*parameters)
