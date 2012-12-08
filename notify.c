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

static struct snmp_packet *get_notify_pkt(pool *p, const char *community,
    pr_netaddr_t *dst_addr, pr_netaddr_t *src_addr) {
  struct snmp_packet *pkt = NULL;

  pkt = snmp_packet_create(p);
  pkt->snmp_version = SNMP_PROTOCOL_VERSION_2;
  pkt->community = (char *) community;
  pkt->community_len = strlen(community);
  pkt->remote_addr = dst_addr;

  pkt->resp_pdu = snmp_pdu_create(pkt->pool, SNMP_PDU_TRAP_V2);
  pkt->resp_pdu->err_code = 0;
  pkt->resp_pdu->err_idx = 0;
  pkt->resp_pdu->request_id = snmp_notify_get_request_id();

  /* XXX set first varbind to sysUptime.0 (1.3.6.1.2.1.1.3.0, TimeTicks)
   *  (defined in RFC 3418).
   *
   */

  /* XXX set second varbind to snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0, OID)
   *  (defined in RFC 3418).
   *
   */

  return pkt;
}

int snmp_notify_generate(pool *p, int sockfd, const char *community,
    pr_netaddr_t *src_addr, unsigned int notify_id) {
  config_rec *c;
  pr_netaddr_t *notify_addr;
  unsigned char *notify_data;
  size_t notify_datalen;
  const char *notify_community;
  char *notify_name;
  struct snmp_packet *pkt;
  int res;

  pkt = get_notify_pkt(p, community, notify_addr, src_addr);

  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "writing %s SNMP notification for %s, community = '%s', request ID %ld, "
    "request type '%s'", notify_name,
    snmp_msg_get_versionstr(pkt->snmp_version), pkt->community,
    pkt->resp_pdu->request_id,
    snmp_pdu_get_request_type_desc(pkt->resp_pdu->request_type));

  res = snmp_msg_write(pkt->pool, &(pkt->resp_data), &(pkt->resp_datalen),
    pkt->community, pkt->community_len, pkt->snmp_version, pkt->resp_pdu);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error writing %s SNMP notification to UDP packet: %s", notify_name,
      strerror(xerrno));

    destroy_pool(pkt->pool);
    errno = xerrno;
    return -1;
  }

  if (sockfd < 0) {
    /* XXX Need to open our own socket to the receiver. */
  }

  snmp_packet_write(p, sockfd, pkt);
  destroy_pool(pkt->pool);

  errno = ENOSYS;
  return -1;
}

long snmp_notify_get_request_id(void) {
  long request_id;

#ifdef HAVE_RANDOM
  request_id = random();
#else
  request_id = rand();
#endif /* HAVE_RANDOM */

  return request_id;
}

void snmp_notify_poll_cond(void) {
  /* XXX Poll for notify conditions here, based on the criteria configured
   * for various notification receivers.
   */
}
