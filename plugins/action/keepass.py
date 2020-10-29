

# class ActionModule(ActionBase):
#     def run(self, tmp=None, task_vars=None):
#         super(ActionModule, self).run(tmp, task_vars)
#         module_args = self._task.args.copy()
#         # module_return = self._execute_module(module_name='setup',
#         #                                      module_args=module_args,
#         #                                      task_vars=task_vars, tmp=tmp)
#         # ret = dict()
#         # remote_date = None
#         # if not module_return.get('failed'):
#         #     for key, value in module_return['ansible_facts'].items():
#         #         if key == 'ansible_date_time':
#         #             remote_date = value['iso8601']
#
#         # if remote_date:
#         #     remote_date_obj = datetime.strptime(remote_date, '%Y-%m-%dT%H:%M:%SZ')
#         #     time_delta = datetime.now() - remote_date_obj
#         #     ret['delta_seconds'] = time_delta.seconds
#         #     ret['delta_days'] = time_delta.days
#         #     ret['delta_microseconds'] = time_delta.microseconds
#
#         return {}
#
#
# def __main__():
#     module = AnsibleModule(
#         argument_spec=dict(
#             state=dict(default='present', choices=['present', 'absent']),
#             name=dict(required=True),
#             enabled=dict(required=True, type='bool'),
#             something=dict(aliases=['whatever'])
#         ),
#         supports_check_mode=True
#     )
#
#     if module.check_mode:
#         # Check if any changes would be made but don't actually make those changes
#         # module.exit_json(changed=check_if_system_state_would_be_changed())
#         module.exit_json(changed=False)
