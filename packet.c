/*
 * ProFTPD - mod_snmp packet routines
 * Copyright (c) 2008-2011 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * $Id$
 */

#include "mod_snmp.h"
#include "packet.h"

struct snmp_packet *snmp_packet_create(pool *p) {
  struct snmp_packet *pkt;
  pool *sub_pool;

  sub_pool = pr_pool_create_sz(p, 128);
  pr_pool_tag(sub_pool, "SNMP packet pool");

  pkt = pcalloc(sub_pool, sizeof(struct snmp_packet));
  pkt->pool = sub_pool;

  /* Allocate the request data buffer for now; leave the response data
   * buffer to be allocated later.
   */

  pkt->req_datalen = SNMP_PACKET_MAX_LEN;
  pkt->req_data = palloc(sub_pool, pkt->req_datalen);

  pkt->resp_datalen = SNMP_PACKET_MAX_LEN;
  pkt->resp_data = palloc(sub_pool, pkt->resp_datalen);

  return pkt;
}
