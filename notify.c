/*
 * ProFTPD - mod_snmp notification routines
 * Copyright (c) 2008-2012 TJ Saunders
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
 */

#include "mod_snmp.h"
#include "msg.h"
#include "pdu.h"
#include "smi.h"
#include "asn1.h"
#include "packet.h"
#include "db.h"
#include "stacktrace.h"
#include "notify.h"

static const char *trace_channel = "snmp.notify";

static oid_t get_oid(unsigned int notify_id, unsigned int *oidlen) {
  return 0;
}

int snmp_notify_generate(const char *community, unsigned int notify_id) {
  config_rec *c;
  pr_netaddr_t *notify_addr;
  unsigned char *notify_data;
  size_t notify_datalen;
  const char *notify_community;
  int res;

  errno = ENOSYS;
  return -1;
}
