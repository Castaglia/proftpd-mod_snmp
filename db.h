/*
 * ProFTPD - mod_snmp database tables
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
 *
 * $Id$
 */

#include "mod_snmp.h"

#ifndef MOD_SNMP_DB_H
#define MOD_SNMP_DB_H

/* Database IDs */
#define SNMP_DB_ID_UNKNOWN		0
#define SNMP_DB_ID_DAEMON		1
#define SNMP_DB_ID_FTP			2
#define SNMP_DB_ID_SNMP			3
#define SNMP_DB_ID_SSL			4
#define SNMP_DB_ID_SSH			5
#define SNMP_DB_ID_SQL			6
#define SNMP_DB_ID_QUOTA		7
#define SNMP_DB_ID_BAN			8
#define SNMP_DB_ID_GEOIP		9

extern int snmp_table_ids[];

/* daemon database fields */
#define SNMP_DB_DAEMON_F_SOFTWARE				1
#define SNMP_DB_DAEMON_F_VERSION				2
#define SNMP_DB_DAEMON_F_ADMIN					3
#define SNMP_DB_DAEMON_F_UPTIME					4
#define SNMP_DB_DAEMON_F_VHOST_COUNT				5
#define SNMP_DB_DAEMON_F_CONN_COUNT				6
#define SNMP_DB_DAEMON_F_CONN_TOTAL				7
#define SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL			8
#define SNMP_DB_DAEMON_F_RESTART_COUNT				9
#define SNMP_DB_DAEMON_F_SEGFAULT_COUNT				10
#define SNMP_DB_DAEMON_F_MAXINST_COUNT				11

/* ftp.sesssions database fields */
#define SNMP_DB_FTP_SESS_F_SESS_COUNT				12
#define SNMP_DB_FTP_SESS_F_SESS_TOTAL				13
#define SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL			14

/* ftp.logins database fields */
#define SNMP_DB_FTP_LOGINS_F_TOTAL				15
#define SNMP_DB_FTP_LOGINS_F_ERR_TOTAL				16
#define SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL			17
#define SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL		18
#define SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL			19
#define SNMP_DB_FTP_LOGINS_F_ANON_COUNT				20
#define SNMP_DB_FTP_LOGINS_F_ANON_TOTAL				21

/* ftp.dataTransfers database fields */
#define SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL			22
#define SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL			23
#define SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL			24
#define SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL		25
#define SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL			26
#define SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL		27
#define SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL			28
#define SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL			29

/* ftp.timeouts database fields */
#define SNMP_DB_FTP_TIMEOUTS_F_IDLE_TOTAL			30
#define SNMP_DB_FTP_TIMEOUTS_F_LOGIN_TOTAL			31
#define SNMP_DB_FTP_TIMEOUTS_F_NOXFER_TOTAL			32
#define SNMP_DB_FTP_TIMEOUTS_F_STALLED_TOTAL			33

/* snmp database fields */
#define SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL				34
#define SNMP_DB_SNMP_F_PKTS_SENT_TOTAL				35
#define SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL				36
#define SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL			37
#define SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL			38

/* XXX ssl database fields */

/* XXX ssh database fields */

/* XXX sql database fields */

/* XXX quota database fields */

/* XXX ban database fields */

/* XXX geoip database fields */

const char *snmp_db_get_fieldstr(pool *p, unsigned int field);

int snmp_db_rlock(unsigned int field);
int snmp_db_wlock(unsigned int field);
int snmp_db_unlock(unsigned int field);

int snmp_db_close(pool *p, int db_id);
int snmp_db_open(pool *p, int db_id);
int snmp_db_get_value(pool *p, unsigned int field, int32_t *int_value,
  char **str_value, size_t *str_valuelen);
int snmp_db_incr_value(pool *p, unsigned int field, int32_t incr);

/* Used to reset/clear counters. */
int snmp_db_reset_value(pool *p, unsigned int field);

/* Configure the SNMPTables path to use as the root/parent directory for the
 * various database table files.
 */
int snmp_db_set_root(const char *path);

#endif
