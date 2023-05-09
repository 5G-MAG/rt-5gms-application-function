# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#

build_tests = open5gs_project.get_variable('build_tests')

#subdir('nf-server')
subdir('bsf')
if build_tests
    subdir('tests')
endif
