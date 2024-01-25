/*
 * License: 5G-MAG Public License (v1.0)
 * Author: David Waring
 * Copyright: (C) 2023 British Broadcasting Corporation
 *
 * For full license terms please see the LICENSE file distributed with this
 * program. If this file is missing then the license can be retrieved from
 * https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

/* Open5GS includes */
#include "test-common.h"
#include "af/sbi-path.h"

/* Unit test includes */
#include "pcf-cache-test.h"
#include "sai-cache-test.h"
#include "utilities-test.h"

#include "tests.h"

static struct {
    abts_suite *(*func)(abts_suite *suite);
} alltests[] = {
    {test_pcf_cache},
    {test_sai_cache},
    {test_utilities}
};

abts_suite *tests_run(abts_suite *suite)
{
    int i;

    for (i=0; i<(sizeof(alltests)/sizeof(alltests[0])); i++) {
	suite = alltests[i].func(suite);
    }

    return suite;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
