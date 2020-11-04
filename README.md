# ansible-keepassxc

- ## purpose
     read and write to a keepass/keepassxc file from within an ansible playbook

- ## usage

  - ### requirements
      ```
      #!/bin/bash
      pip install pykeepass --user
      ```
    
  - ### install
    ```
    #!/bin/bash
    ansible-galaxy collection install git+https://github.com/dszryan/ansible-keepass.git,main
    ```
    
  - ### run
    
    #### sample vars
    ```
    ---
    keepass:
      ansible:
        location: ~/keepass/readonly.kbdx
        password: !vault |
                    $ANSIBLE_VAULT;1.1;AES256 ....
      scratch:
        location: ~/keepass/updateable.kbdx
        keyfile: ~/keepass/keyfile
        updatable: true

    configuration:
      first_secret_password:
        database: "{{ keepass.ansible }}"
        lookup: get://first_secret?password
    ```
    
    #### sample playbook
    ```
    ---
    - hosts: host_that_can_access_the_keepass_databases_at_said_locations
      collections:
        - dszryan.keepass
      tasks:
        - name: using the lookup plugin
          debug:
            msg: "{{ lookup('dszryan.keepass.lookup', 'get://first_secret', 'get://second/secret', database=keepass.ansible, fail_silently=true) }}"

        - name: using the filter plugin
          debug:
            msg: "{{ configuration.first_secret_password | dszryan.keepass.lookup }}"

        - name: using the action plugin
          keepass:
            database: "{{ keepass.scratch }}"
            action: put
            path: dummy
            value: '{ "custom": "value" }'
          register: register_keepass
        - name: debug
          debug:
            msg: "{{ register_keepass }}"    
    ```

- ## documentation
  available in detail as part of the [module](https://github.com/dszryan/ansible-keepassxc/blob/main/src/main/ansible_collections/dszryan/keepass/plugins/action/keepass.py) definition

- ## development
  - checkout to your local ansible project as submodule 
    ```
    #!/bin/bash
    mkdir -p ./submodule && \
    git submodule add -f https://github.com/dszryan/ansible-keepass.git ./submodule
    ```
  - build locally
    ```
    #!/bin/bash
    cd ./submodule/ansible-keepassxc/src/main/ansible_collections/dszryan/keepass && \
    ansible-galaxy collection build -f && \
    cd -
    ```
  - install locally
    ```
    #!/bin/bash
    cd ./submodule/ansible-keepassxc/src/main/ansible_collections/dszryan/keepass && \
    mkdir -p ./collection && \
    ansible-galaxy collection install -f $(ls -t dszryan-keepass-*.tar.gz | head -n1) -p ./collection && \
    cd -
    ```
  - configure ansible collections path
    ```
    # ./ansible.cfg
    [defaults]
    collections_paths = submodule/ansible-keepassxc/src/main/ansible_collections/dszryan/keepass/collection:~/.ansible/collections:/usr/share/ansible/collections
    ```
