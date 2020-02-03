/*
 * ndpi_protocol_ids.h
 *
 * Copyright (C) 2011-19 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __NDPI_API_H__

#endif

#ifndef __NDPI_PROTOCOLS_DEFAULT_H__
#define __NDPI_PROTOCOLS_DEFAULT_H__

#define NDPI_DETECTION_SUPPORT_IPV6
#define NDPI_PROTOCOL_SIZE                  2

typedef enum {
  NDPI_PROTOCOL_UNKNOWN               = 0,



  NDPI_PROTOCOL_WHATSAPP_CALL         = 45, /* WhatsApp video ad audio calls go here */

  NDPI_PROTOCOL_WHATSAPP_FILES        = 242, /* Videos, pictures, voice messages... */
  NDPI_PROTOCOL_WHATSAPP              = 142,
  NDPI_PROTOCOL_FACEBOOK              = 119,
NDPI_PROTOCOL_GITHUB                = 203,
#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_protocol_ids.h"
#endif  

  /*
    IMPORTANT
    before allocating a new identifier please fill up
    one of those named NDPI_PROTOCOL_FREE_XXX and not used
    (placeholders to avoid protocol renumbering)
  */

  /* IMPORTANT:NDPI_LAST_IMPLEMENTED_PROTOCOL MUST BE THE LAST ELEMENT */
  NDPI_LAST_IMPLEMENTED_PROTOCOL
} ndpi_protocol_id_t;

#define NDPI_PROTOCOL_NO_MASTER_PROTO    NDPI_PROTOCOL_UNKNOWN
#define NDPI_MAX_SUPPORTED_PROTOCOLS     NDPI_LAST_IMPLEMENTED_PROTOCOL
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS    (NDPI_NUM_BITS-NDPI_LAST_IMPLEMENTED_PROTOCOL)
#endif
