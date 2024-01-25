/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "context.h"
#include "network-assistance-delivery-boost.h"

void msaf_network_assistance_delivery_boost_set(void)
{
    msaf_network_assistance_delivery_boost_t *delivery_boost = NULL;
    delivery_boost = ogs_calloc(1, sizeof(msaf_network_assistance_delivery_boost_t));
    ogs_assert(delivery_boost);
    delivery_boost->delivery_boost_min_dl_bit_rate = ogs_sbi_bitrate_from_string(MIN_DL_BIT_RATE);
    delivery_boost->delivery_boost_period = BOOST_PERIOD;
    msaf_self()->config.network_assistance_delivery_boost = delivery_boost;
}

void msaf_network_assistance_delivery_boost_set_from_config(uint64_t delivery_boost_min_dl_bit_rate, int delivery_boost_period)
{
    msaf_self()->config.network_assistance_delivery_boost->delivery_boost_min_dl_bit_rate = delivery_boost_min_dl_bit_rate;
    msaf_self()->config.network_assistance_delivery_boost->delivery_boost_period = delivery_boost_period;
}

void msaf_network_assistance_delivery_boost_free(void) {
    if (msaf_self()->config.network_assistance_delivery_boost)
    {
        ogs_free(msaf_self()->config.network_assistance_delivery_boost);
    }
}

int is_ue_allowed_to_request_delivery_boost(msaf_network_assistance_session_t *na_sess) {
    
    if(na_sess->active_delivery_boost)
	    return 0;

    //Placeholder to implement any further restrictions here
    
    return 1;
}

