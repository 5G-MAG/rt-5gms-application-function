/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2023 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#ifndef MSAF_NETWORK_ASSISTANCE_DELIVERY_BOOST_H
#define MSAF_NETWORK_ASSISTANCE_DELIVERY_BOOST_H

#include "network-assistance-session.h"

#define MIN_DL_BIT_RATE "1 Mbps"
#define BOOST_PERIOD 30

#ifdef __cplusplus
extern "C" {
#endif

typedef struct msaf_network_assistance_session_s msaf_network_assistance_session_t;	

typedef struct msaf_network_assistance_delivery_boost_s {
    uint64_t delivery_boost_min_dl_bit_rate;
    int delivery_boost_period;
} msaf_network_assistance_delivery_boost_t;

extern void msaf_network_assistance_delivery_boost_set(void);
extern void msaf_network_assistance_delivery_boost_set_from_config(uint64_t delivery_boost_min_dl_bit_rate, int delivery_boost_period);
extern void msaf_network_assistance_delivery_boost_free(void);
extern int is_ue_allowed_to_request_delivery_boost(msaf_network_assistance_session_t *na_sess);

#ifdef __cplusplus
}
#endif

#endif /* MSAF_NETWORK_ASSISTANCE_DELIVERY_BOOST_H */
