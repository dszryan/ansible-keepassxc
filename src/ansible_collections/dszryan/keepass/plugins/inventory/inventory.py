# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
from typing import Dict, List

from ansible.inventory.data import InventoryData
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible.parsing.dataloader import DataLoader
from ansible.parsing.yaml.objects import AnsibleMapping
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.utils.display import Display


DOCUMENTATION = """
    name: inventory
    plugin_type: inventory
    author: 
        - develop <develop@local>
    short_description: integrates with keepass/keepassxc
    description:
        - provides integration with keepass to read/write entries
    version_added: "2.10"
    options:
        plugin:
            description: Name of the plugin
            required: true
            choices: ['inventory']
        database:
            description: database details
            required: true
            type: dict
        generator:
            description: defines inventory
            required: true
            type: yaml
"""


class InventoryModule(BaseInventoryPlugin):
    NAME = 'inventory'
    database_details: dict
    generator: AnsibleMapping

    def _do_template(self, pattern, variables):
        self.templar.available_variables = variables
        return json.loads(self.templar.do_template(pattern))

    def _build(self, inventory_yaml: List[Dict]):
        group_item: Dict
        for group_item in inventory_yaml:
            current_group = Group(group_item.get("name"))
            current_group.__setstate__(group_item)
            added_group = self.inventory.add_group(current_group.name)
            for (name, value) in current_group.vars.items():
                self.inventory.set_variable(current_group.name, name, value)

            for parent_item in current_group.parent_groups:
                added_parent = self.inventory.add_group(parent_item.name)
                self.inventory.add_child(added_parent, added_group)
                added_group = added_parent

            for host_item in current_group.hosts:
                current_host = Host(host_item.get("name"))
                current_host.__setstate__(host_item)
                self.inventory.add_host(current_host.name, current_group.name)
                for (name, value) in current_host.vars.items():
                    self.inventory.set_variable(current_host.name, name, value)

    def parse(self, inventory: InventoryData, loader: DataLoader, path: str, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._read_config_data(path)
        self.database_details = self.get_option("database")
        self.generator = self.get_option("generator")

        generator_vars = dict(self.generator["vars"], database=self.database_details, inventory_hostname="localhost")
        inventory_yaml = self._do_template(self.generator["inventory"], generator_vars)
        self._build(inventory_yaml)
