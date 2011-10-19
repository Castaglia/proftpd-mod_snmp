/*
 * ProFTPD - mod_snmp MIB support
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
#include "asn1.h"
#include "mib.h"
#include "smi.h"
#include "db.h"
#include "stacktrace.h"

/* This table maps the OIDs in the PROFTPD-MIB to the database field where
 * that value is stored.
 *
 * SNMP conventions identify a MIB object using "x.y", where "x" is the OID
 * and "y" is the instance identifier.  We don't have any rows of data, just
 * scalars, so the instance identifier will always be zero for our MIB
 * objects.
 */

static struct snmp_mib snmp_mibs[] = {
  { { }, 0, 0, NULL, NULL, 0 },

  /* Daemon MIBs */
  { { SNMP_MIB_DAEMON_OID_SOFTWARE, 0 },
    SNMP_MIB_DAEMON_OIDLEN_SOFTWARE + 1, 
    SNMP_DB_DAEMON_F_SOFTWARE,
    SNMP_MIB_NAME_PREFIX "daemon.software",
    SNMP_MIB_NAME_PREFIX "daemon.software.0",
    SNMP_SMI_STRING },

  { { SNMP_MIB_DAEMON_OID_VERSION, 0 },
    SNMP_MIB_DAEMON_OIDLEN_VERSION + 1,
    SNMP_DB_DAEMON_F_VERSION,
    SNMP_MIB_NAME_PREFIX "daemon.version",
    SNMP_MIB_NAME_PREFIX "daemon.version.0",
    SNMP_SMI_STRING },

  { { SNMP_MIB_DAEMON_OID_ADMIN, 0 },
    SNMP_MIB_DAEMON_OIDLEN_ADMIN + 1, 
    SNMP_DB_DAEMON_F_ADMIN,
    SNMP_MIB_NAME_PREFIX "daemon.admin",
    SNMP_MIB_NAME_PREFIX "daemon.admin.0",
    SNMP_SMI_STRING },

  { { SNMP_MIB_DAEMON_OID_UPTIME, 0 },
    SNMP_MIB_DAEMON_OIDLEN_UPTIME + 1,
    SNMP_DB_DAEMON_F_UPTIME,
    SNMP_MIB_NAME_PREFIX "daemon.uptime",
    SNMP_MIB_NAME_PREFIX "daemon.uptime.0",
    SNMP_SMI_TIMETICKS },

  { { SNMP_MIB_DAEMON_OID_VHOST_COUNT, 0 },
    SNMP_MIB_DAEMON_OIDLEN_VHOST_COUNT + 1,
    SNMP_DB_DAEMON_F_VHOST_COUNT,
    SNMP_MIB_NAME_PREFIX "daemon.vhostCount",
    SNMP_MIB_NAME_PREFIX "daemon.vhostCount.0",
    SNMP_SMI_INTEGER },

  { { SNMP_MIB_DAEMON_OID_CONN_COUNT, 0 },
    SNMP_MIB_DAEMON_OIDLEN_CONN_COUNT + 1,
    SNMP_DB_DAEMON_F_CONN_COUNT,
    SNMP_MIB_NAME_PREFIX "daemon.connectionCount",
    SNMP_MIB_NAME_PREFIX "daemon.connectionCount.0",
    SNMP_SMI_GAUGE32 },

  { { SNMP_MIB_DAEMON_OID_CONN_TOTAL, 0 },
    SNMP_MIB_DAEMON_OIDLEN_CONN_TOTAL + 1,
    SNMP_DB_DAEMON_F_CONN_TOTAL,
    SNMP_MIB_NAME_PREFIX "daemon.connectionTotal",
    SNMP_MIB_NAME_PREFIX "daemon.connectionTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_DAEMON_OID_CONN_REFUSED_TOTAL, 0 },
    SNMP_MIB_DAEMON_OIDLEN_CONN_REFUSED_TOTAL + 1,
    SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL,
    SNMP_MIB_NAME_PREFIX "daemon.connectionRefusedTotal",
    SNMP_MIB_NAME_PREFIX "daemon.connectionRefusedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_DAEMON_OID_RESTART_COUNT, 0 },
    SNMP_MIB_DAEMON_OIDLEN_RESTART_COUNT + 1, 
    SNMP_DB_DAEMON_F_RESTART_COUNT,
    SNMP_MIB_NAME_PREFIX "daemon.restartCount",
    SNMP_MIB_NAME_PREFIX "daemon.restartCount.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_DAEMON_OID_SEGFAULT_COUNT, 0 },
    SNMP_MIB_DAEMON_OIDLEN_SEGFAULT_COUNT + 1, 
    SNMP_DB_DAEMON_F_SEGFAULT_COUNT,
    SNMP_MIB_NAME_PREFIX "daemon.segfaultCount",
    SNMP_MIB_NAME_PREFIX "daemon.segfaultCount.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_DAEMON_OID_MAXINST_COUNT, 0 },
    SNMP_MIB_DAEMON_OIDLEN_MAXINST_COUNT + 1,
    SNMP_DB_DAEMON_F_MAXINST_COUNT,
    SNMP_MIB_NAME_PREFIX "daemon.maxInstancesLimitCount",
    SNMP_MIB_NAME_PREFIX "daemon.maxInstancesLimitCount.0",
    SNMP_SMI_COUNTER32 },

  /* ftp.sessions MIBs */
  { { SNMP_MIB_FTP_SESS_OID_SESS_COUNT, 0 },
    SNMP_MIB_FTP_SESS_OIDLEN_SESS_COUNT + 1,
    SNMP_DB_FTP_SESS_F_SESS_COUNT,
    SNMP_MIB_NAME_PREFIX "ftp.sessions.sessionCount",
    SNMP_MIB_NAME_PREFIX "ftp.sessions.sessionCount.0",
    SNMP_SMI_GAUGE32 },

  { { SNMP_MIB_FTP_SESS_OID_SESS_TOTAL, 0 },
    SNMP_MIB_FTP_SESS_OIDLEN_SESS_TOTAL + 1,
    SNMP_DB_FTP_SESS_F_SESS_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.sessions.sessionTotal",
    SNMP_MIB_NAME_PREFIX "ftp.sessions.sessionTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_SESS_OID_CMD_INVALID_TOTAL, 0 },
    SNMP_MIB_FTP_SESS_OIDLEN_CMD_INVALID_TOTAL + 1,
    SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.sessions.commandInvalidTotal",
    SNMP_MIB_NAME_PREFIX "ftp.sessions.commandInvalidTotal.0",
    SNMP_SMI_COUNTER32 },

  /* ftp.logins MIBs */
  { { SNMP_MIB_FTP_LOGINS_OID_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ERR_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ERR_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_ERR_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginFailedTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginFailedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ERR_BAD_USER_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ERR_BAD_USER_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginBadUserTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginBadUserTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ERR_BAD_PASSWD_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ERR_BAD_PASSWD_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginBadPasswordTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginBadPasswordTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ERR_GENERAL_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ERR_GENERAL_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginGeneralErrorTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.loginGeneralErrorTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ANON_COUNT, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ANON_COUNT + 1,
    SNMP_DB_FTP_LOGINS_F_ANON_COUNT,
    SNMP_MIB_NAME_PREFIX "ftp.logins.anonLoginCount",
    SNMP_MIB_NAME_PREFIX "ftp.logins.anonLoginCount.0",
    SNMP_SMI_GAUGE32 },

  { { SNMP_MIB_FTP_LOGINS_OID_ANON_TOTAL, 0 },
    SNMP_MIB_FTP_LOGINS_OIDLEN_ANON_TOTAL + 1,
    SNMP_DB_FTP_LOGINS_F_ANON_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.logins.anonLoginTotal",
    SNMP_MIB_NAME_PREFIX "ftp.logins.anonLoginTotal.0",
    SNMP_SMI_COUNTER32 },

  /* ftp.dataTransfers MIBs */
  { { SNMP_MIB_FTP_XFERS_OID_DIR_LIST_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_DIR_LIST_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.dirListTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.dirListTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_DIR_LIST_ERR_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_DIR_LIST_ERR_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.dirListFailedTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.dirListFailedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_FILE_UPLOAD_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_FILE_UPLOAD_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileUploadTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileUploadTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_FILE_UPLOAD_ERR_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_FILE_UPLOAD_ERR_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileUploadFailedTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileUploadFailedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_FILE_DOWNLOAD_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_FILE_DOWNLOAD_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileDownloadTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileDownloadTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_FILE_DOWNLOAD_ERR_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_FILE_DOWNLOAD_ERR_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileDownloadFailedTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.fileDownloadFailedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_KB_UPLOAD_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_KB_UPLOAD_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.kbUploadTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.kbUploadTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_XFERS_OID_KB_DOWNLOAD_TOTAL, 0 },
    SNMP_MIB_FTP_XFERS_OIDLEN_KB_DOWNLOAD_TOTAL + 1,
    SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.kbDownloadTotal",
    SNMP_MIB_NAME_PREFIX "ftp.dataTransfers.kbDownloadTotal.0",
    SNMP_SMI_COUNTER32 },

  /* ftp.timeouts MIBs */
  { { SNMP_MIB_FTP_TIMEOUTS_OID_IDLE_TOTAL, 0 },
    SNMP_MIB_FTP_TIMEOUTS_OIDLEN_IDLE_TOTAL + 1,
    SNMP_DB_FTP_TIMEOUTS_F_IDLE_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.idleTimeoutTotal",
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.idleTimeoutTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_TIMEOUTS_OID_LOGIN_TOTAL, 0 },
    SNMP_MIB_FTP_TIMEOUTS_OIDLEN_LOGIN_TOTAL + 1,
    SNMP_DB_FTP_TIMEOUTS_F_LOGIN_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.loginTimeoutTotal",
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.loginTimeoutTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_TIMEOUTS_OID_NOXFER_TOTAL, 0 },
    SNMP_MIB_FTP_TIMEOUTS_OIDLEN_NOXFER_TOTAL + 1,
    SNMP_DB_FTP_TIMEOUTS_F_NOXFER_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.noTransferTimeoutTotal",
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.noTransferTimeoutTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_FTP_TIMEOUTS_OID_STALLED_TOTAL, 0 },
    SNMP_MIB_FTP_TIMEOUTS_OIDLEN_STALLED_TOTAL + 1,
    SNMP_DB_FTP_TIMEOUTS_F_STALLED_TOTAL,
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.stalledTimeoutTotal",
    SNMP_MIB_NAME_PREFIX "ftp.timeouts.stalledTimeoutTotal.0",
    SNMP_SMI_COUNTER32 },

  /* snmp MIBs */
  { { SNMP_MIB_SNMP_OID_PKTS_RECVD_TOTAL, 0 },
    SNMP_MIB_SNMP_OIDLEN_PKTS_RECVD_TOTAL + 1, 
    SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL,
    SNMP_MIB_NAME_PREFIX "snmp.packetsReceivedTotal",
    SNMP_MIB_NAME_PREFIX "snmp.packetsReceivedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_SNMP_OID_PKTS_SENT_TOTAL, 0 },
    SNMP_MIB_SNMP_OIDLEN_PKTS_SENT_TOTAL + 1,
    SNMP_DB_SNMP_F_PKTS_SENT_TOTAL,
    SNMP_MIB_NAME_PREFIX "snmp.packetsSentTotal",
    SNMP_MIB_NAME_PREFIX "snmp.packetsSentTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_SNMP_OID_TRAPS_SENT_TOTAL, 0 },
    SNMP_MIB_SNMP_OIDLEN_TRAPS_SENT_TOTAL + 1, 
    SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL,
    SNMP_MIB_NAME_PREFIX "snmp.trapsSentTotal",
    SNMP_MIB_NAME_PREFIX "snmp.trapsSentTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_SNMP_OID_PKTS_AUTH_ERR_TOTAL, 0 },
    SNMP_MIB_SNMP_OIDLEN_PKTS_AUTH_ERR_TOTAL + 1,
    SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL,
    SNMP_MIB_NAME_PREFIX "snmp.packetsAuthFailedTotal",
    SNMP_MIB_NAME_PREFIX "snmp.packetsAuthFailedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { SNMP_MIB_SNMP_OID_PKTS_DROPPED_TOTAL, 0 },
    SNMP_MIB_SNMP_OIDLEN_PKTS_DROPPED_TOTAL + 1,
    SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL,
    SNMP_MIB_NAME_PREFIX "snmp.packetsDroppedTotal",
    SNMP_MIB_NAME_PREFIX "snmp.packetsDroppedTotal.0",
    SNMP_SMI_COUNTER32 },

  { { }, 0, 0, NULL, NULL, 0 }
};

/* We only need to look this up once. */
static int snmp_mib_max_idx = -1;

int snmp_mib_get_idx(oid_t *mib_oid, unsigned int mib_oidlen,
    int *lacks_instance_id, int flags) {
  register unsigned int i;
  int mib_idx = -1;

  if (lacks_instance_id != NULL) {
    *lacks_instance_id = FALSE;
  }

  if (flags & SNMP_MIB_LOOKUP_FL_NO_INSTANCE_ID) {
    /* In this case, the caller is requesting that we treat the given OID
     * as not having an instance identifier.
     *
     * This is done to handle the case where we received e.g.
     * "GetNext 1.2.3", and the next OID is "1.2.3.0".
     *
     * If we find a match, we return the index of the matching entry.
     */

    for (i = 1; snmp_mibs[i].mib_oidlen != 0; i++) {
      if (snmp_mibs[i].mib_oidlen == (mib_oidlen + 1)) {
        if (memcmp(snmp_mibs[i].mib_oid, mib_oid,
            mib_oidlen * sizeof(oid_t)) == 0) {
          mib_idx = i;

          if (lacks_instance_id != NULL) {
            *lacks_instance_id = TRUE;
          }

          break;
        }
      }
    }

  } else {
    for (i = 1; snmp_mibs[i].mib_oidlen != 0; i++) {
      if (snmp_mibs[i].mib_oidlen == mib_oidlen) {
        if (memcmp(snmp_mibs[i].mib_oid, mib_oid,
            mib_oidlen * sizeof(oid_t)) == 0) {
          mib_idx = i;
          break;
        }
      }

      /* Check for the case where the given OID might be missing the final
       * ".0" instance identifier.  This is done to support the slightly
       * more user-friendly NO_SUCH_INSTANCE exception for SNMPv2/SNMPv3
       * responses.
       */
      if (snmp_mibs[i].mib_oidlen == (mib_oidlen + 1)) {
        if (memcmp(snmp_mibs[i].mib_oid, mib_oid,
            mib_oidlen * sizeof(oid_t)) == 0) {
          if (lacks_instance_id != NULL) {
            *lacks_instance_id = TRUE;
          }

          break;
        }
      }
    }
  }

  if (mib_idx < 0) {
    errno = ENOENT;
  }

  return mib_idx;
}

int snmp_mib_get_max_idx(void) {
  register unsigned int i;

  if (snmp_mib_max_idx >= 0) {
    return snmp_mib_max_idx;
  }

  for (i = 1; snmp_mibs[i].mib_oidlen != 0; i++);

  /* We subtract one, since the for loop iterates one time more than
   * necessary, in order to find the end-of-loop condition.
   */
  snmp_mib_max_idx = i-1;

  return snmp_mib_max_idx;
}

struct snmp_mib *snmp_mib_get_by_idx(unsigned int mib_idx) {
  if (mib_idx > snmp_mib_get_max_idx()) {
    errno = EINVAL;
    return NULL;
  }

  return &snmp_mibs[mib_idx];
}

struct snmp_mib *snmp_mib_get_by_oid(oid_t *mib_oid, unsigned int mib_oidlen,
    int *lacks_instance_id) {
  int mib_idx;

  mib_idx = snmp_mib_get_idx(mib_oid, mib_oidlen, lacks_instance_id, 0);
  if (mib_idx < 0) {
    return NULL;
  }

  return snmp_mib_get_by_idx(mib_idx); 
}
