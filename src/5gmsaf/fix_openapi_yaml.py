#!/usr/bin/python3
#
# 5G-MAG Reference Tools: 5GMS Application Function OpenAPI YAML sanitizer
# ========================================================================
#
# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#
# This is part of the 5G-MAG Reference Tools 5GMS AF. This script modifies the
# OpenAPI YAML in a directory so that it will work with the openapi-generator
# v5.2.0 (as used by the open5gs project).
#
'''Fix OpenAPI YAML

This script will take a pointer to a directory of .yaml files and will check
each file for structures that are not handled correctly by the
openapi-generator v5.2.0.

Specifically at this stage this is just removing the catch-all future
expansion strings for enumerated types. This will change YAML such as

  field:
    anyOf:
      - type: string
        enum: [TYPE1, TYPE2, TYPE3, ...]
      - type: string
        description: >
            Catch all for future expansion

...to...

  field:
    type: string
    enum: [TYPE1, TYPE2, TYPE3, ...]

This will allow openapi-generator to treat this as an enumeration instead of
an anonymous object.
'''

import glob
import logging
import os
import os.path
import sys
import yaml

log = logging.getLogger('fix-openapi-yaml')

def collapse_enum(anyof_value):
    if isinstance(anyof_value, list) and len(anyof_value) == 2 and 'type' in anyof_value[0] and 'type' in anyof_value[1] and anyof_value[0]['type'] == 'string' and anyof_value[1]['type'] == 'string' and ('enum' in anyof_value[0] or 'enum' in anyof_value[1]):
        if 'enum' in anyof_value[0]:
            return anyof_value[0]
        else:
            return anyof_value[1]
    return anyof_value

def strip_enum_future_proof(node):
    changed = False
    if isinstance(node, dict):
        for key,value in node.items():
            if key == 'anyOf':
                value = collapse_enum(value)
                if isinstance(value, dict):
                    del node['anyOf']
                    node.update(value)
                    changed = True
                    break
            else:
                if strip_enum_future_proof(value):
                    changed = True
    elif isinstance(node, list):
        for value in node:
            if strip_enum_future_proof(value):
                changed = True
    return changed

def fix_openapi_file(filename):
    changed = False
    with open(filename, 'r') as infile:
        try:
            api = yaml.load(infile, Loader=yaml.SafeLoader)
            if strip_enum_future_proof(api):
                log.info("Changing %s...", filename)
                changed = True
                with open(filename+'.tmp', 'w') as outfile:
                    outfile.write(yaml.dump(api, Dumper=yaml.SafeDumper))
                os.replace(filename+'.tmp', filename)
        except Exception as e:
            log.warning('Failed to update %s: %s', filename, str(e))
    return changed

def main():
    if len(sys.argv) != 2:
        log.error('Incorrect command line arguments')
        sys.stderr.write('Syntax: %s <OpenAPI-directory>\n'%os.path.basename(sys.argv[0]))
        return 1

    openapi_dir = sys.argv[1]

    fixed_files = 0
    for filename in glob.glob(os.path.join(openapi_dir,'*.yaml')):
        if fix_openapi_file(filename):
            fixed_files += 1

    log.info('Modified %i files',fixed_files)

    return 0

if __name__ == "__main__":
    sys.exit(main())
