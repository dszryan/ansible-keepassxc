# import importlib
# import pathlib
#
# from ansible.module_utils.basic import AnsibleModule
#
#
# class Helper:
#     @staticmethod
#     def import_util(module_name, class_name, *parameters):
#         filename = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent, './module_utils/' + module_name + '.py')
#         spec = importlib.util.spec_from_file_location(module_name, filename)
#         module = importlib.util.module_from_spec(spec)
#         spec.loader.exec_module(module)
#         return getattr(module, class_name)(*parameters)
#
#
# def __main__():
#     module=AnsibleModule(
#         argument_spec=dict(
#             action=dict(type='str', required=True, default='select', choices=['select', 'insert', 'update', 'delete']),
#             database=dict(type=type({}), required=True),
#             path=dict(type='str', required=True),
#             property=dict(type='str', required=False, default=None),
#             default=dict(type='str', required=False, default=None),
#             upsert=dict(type=type({}), required=False, default=None)
#         ),
#         supports_check_mode=True,
#         required_if=[
#             ('action', 'insert', ['property'], False),
#             ('action', 'insert', ['upsert'], True),
#
#             ('action', 'update', ['property'], False),
#             ('action', 'update', ['upsert'], True),
#
#             ('action', 'delete', ['default', 'upsert'], False)
#         ]
#     )
#
#
#
#     module.exit_json(None)
#
#     # if module.check_mode:
#     #     # Check if any changes would be made but don't actually make those changes
#     #     # module.exit_json(changed=check_if_system_state_would_be_changed())
#     #     module.exit_json(changed=False)
