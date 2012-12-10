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
 */

#include "mod_snmp.h"

#ifndef MOD_SNMP_DB_H
#define MOD_SNMP_DB_H

/* Database IDs */
#define SNMP_DB_ID_UNKNOWN		0
#define SNMP_DB_ID_NOTIFY		1
#define SNMP_DB_ID_CONN			2
#define SNMP_DB_ID_DAEMON		3
#define SNMP_DB_ID_FTP			4
#define SNMP_DB_ID_SNMP			5
#define SNMP_DB_ID_TLS			6
#define SNMP_DB_ID_SSH			7
#define SNMP_DB_ID_SFTP			8
#define SNMP_DB_ID_SCP			9
#define SNMP_DB_ID_SQL			10
#define SNMP_DB_ID_QUOTA		11
#define SNMP_DB_ID_BAN			12
#define SNMP_DB_ID_GEOIP		13

extern int snmp_table_ids[];

/* Miscellaneous non-proftpd database "fields" */
#define SNMP_DB_NOTIFY_F_SYS_UPTIME				1

/* connection database fields */
#define SNMP_DB_CONN_F_SERVER_NAME				11
#define SNMP_DB_CONN_F_SERVER_ADDR				12
#define SNMP_DB_CONN_F_SERVER_PORT				13
#define SNMP_DB_CONN_F_CLIENT_ADDR				14
#define SNMP_DB_CONN_F_CLIENT_PORT				15
#define SNMP_DB_CONN_F_PID					16
#define SNMP_DB_CONN_F_USER_NAME				17
#define SNMP_DB_CONN_F_PROTOCOL					18

/* daemon database fields */
#define SNMP_DB_DAEMON_F_SOFTWARE				101
#define SNMP_DB_DAEMON_F_VERSION				102
#define SNMP_DB_DAEMON_F_ADMIN					103
#define SNMP_DB_DAEMON_F_UPTIME					104
#define SNMP_DB_DAEMON_F_VHOST_COUNT				105
#define SNMP_DB_DAEMON_F_CONN_COUNT				106
#define SNMP_DB_DAEMON_F_CONN_TOTAL				107
#define SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL			108
#define SNMP_DB_DAEMON_F_RESTART_COUNT				109
#define SNMP_DB_DAEMON_F_SEGFAULT_COUNT				110
#define SNMP_DB_DAEMON_F_MAXINST_COUNT				111

/* ftp.sessions database fields */
#define SNMP_DB_FTP_SESS_F_SESS_COUNT				120
#define SNMP_DB_FTP_SESS_F_SESS_TOTAL				121
#define SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL			122

/* ftp.logins database fields */
#define SNMP_DB_FTP_LOGINS_F_TOTAL				130
#define SNMP_DB_FTP_LOGINS_F_ERR_TOTAL				131
#define SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL			132
#define SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL		133
#define SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL			134
#define SNMP_DB_FTP_LOGINS_F_ANON_COUNT				135
#define SNMP_DB_FTP_LOGINS_F_ANON_TOTAL				136

/* ftp.dataTransfers database fields */
#define SNMP_DB_FTP_XFERS_F_DIR_LIST_COUNT			140
#define SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL			141
#define SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL			142
#define SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_COUNT			143
#define SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL			144
#define SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL		145
#define SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_COUNT			146
#define SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL			147
#define SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL		148
#define SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL			149
#define SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL			150

/* ftp.timeouts database fields */
#define SNMP_DB_FTP_TIMEOUTS_F_IDLE_TOTAL			180
#define SNMP_DB_FTP_TIMEOUTS_F_LOGIN_TOTAL			181
#define SNMP_DB_FTP_TIMEOUTS_F_NOXFER_TOTAL			182
#define SNMP_DB_FTP_TIMEOUTS_F_STALLED_TOTAL			183

/* snmp database fields */
#define SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL				200
#define SNMP_DB_SNMP_F_PKTS_SENT_TOTAL				201
#define SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL				202
#define SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL			203
#define SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL			204

/* ftps.tlsSessions database fields */
#define SNMP_DB_FTPS_SESS_F_SESS_COUNT				310
#define SNMP_DB_FTPS_SESS_F_SESS_TOTAL				311
#define SNMP_DB_FTPS_SESS_F_CTRL_HANDSHAKE_ERR_TOTAL		312
#define SNMP_DB_FTPS_SESS_F_DATA_HANDSHAKE_ERR_TOTAL		313

/* ftps.tlsLogins database fields */
#define SNMP_DB_FTPS_LOGINS_F_TOTAL				320
#define SNMP_DB_FTPS_LOGINS_F_ERR_TOTAL				321

/* ftps.tlsDataTransfers database fields */
#define SNMP_DB_FTPS_XFERS_F_DIR_LIST_COUNT			330
#define SNMP_DB_FTPS_XFERS_F_DIR_LIST_TOTAL			331
#define SNMP_DB_FTPS_XFERS_F_DIR_LIST_ERR_TOTAL			332
#define SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_COUNT			333
#define SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_TOTAL			334
#define SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_ERR_TOTAL		335
#define SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_COUNT		336
#define SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_TOTAL		337
#define SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL		338
#define SNMP_DB_FTPS_XFERS_F_KB_UPLOAD_TOTAL			339
#define SNMP_DB_FTPS_XFERS_F_KB_DOWNLOAD_TOTAL			340

/* ssh.sshSessions database fields */
#define SNMP_DB_SSH_SESS_F_KEX_ERR_TOTAL			400
#define SNMP_DB_SSH_SESS_F_COMPRESS_TOTAL			401

/* ssh.sshSessions.sshAuth database fields */
#define SNMP_DB_SSH_AUTH_F_HOSTBASED_TOTAL			450
#define SNMP_DB_SSH_AUTH_F_HOSTBASED_ERR_TOTAL			451
#define SNMP_DB_SSH_AUTH_F_KBDINT_TOTAL				452
#define SNMP_DB_SSH_AUTH_F_KBDINT_ERR_TOTAL			453
#define SNMP_DB_SSH_AUTH_F_PASSWD_TOTAL				454
#define SNMP_DB_SSH_AUTH_F_PASSWD_ERR_TOTAL			455
#define SNMP_DB_SSH_AUTH_F_PUBLICKEY_TOTAL			456
#define SNMP_DB_SSH_AUTH_F_PUBLICKEY_ERR_TOTAL			457

/* ssh.sshLogins database fields */
#define SNMP_DB_SSH_LOGINS_F_LOGIN_TOTAL			490
#define SNMP_DB_SSH_LOGINS_F_LOGIN_ERR_TOTAL			491

/* sftp.sftpSessions database fields */
#define SNMP_DB_SFTP_SESS_F_SESS_COUNT				500
#define SNMP_DB_SFTP_SESS_F_SESS_TOTAL				501

/* sftp.sftpDataTransfers database fields */
#define SNMP_DB_SFTP_XFERS_F_DIR_LIST_COUNT			530
#define SNMP_DB_SFTP_XFERS_F_DIR_LIST_TOTAL			531
#define SNMP_DB_SFTP_XFERS_F_DIR_LIST_ERR_TOTAL			532
#define SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_COUNT			533
#define SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_TOTAL			534
#define SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL		535
#define SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_COUNT		536
#define SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_TOTAL		537
#define SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL		538
#define SNMP_DB_SFTP_XFERS_F_KB_UPLOAD_TOTAL			539
#define SNMP_DB_SFTP_XFERS_F_KB_DOWNLOAD_TOTAL			540

/* scp.scpSessions database fields */
#define SNMP_DB_SCP_SESS_F_SESS_COUNT				600
#define SNMP_DB_SCP_SESS_F_SESS_TOTAL				601

/* scp.scpDataTransfers database fields */
#define SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_COUNT			630
#define SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_TOTAL			631
#define SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_ERR_TOTAL		632
#define SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_COUNT			633
#define SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_TOTAL			634
#define SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL		635
#define SNMP_DB_SCP_XFERS_F_KB_UPLOAD_TOTAL			636
#define SNMP_DB_SCP_XFERS_F_KB_DOWNLOAD_TOTAL			637

/* XXX sql database fields */

/* XXX quota database fields */

/* XXX ban database fields */

/* XXX geoip database fields */

/* For a given field ID, return the database ID. */
int snmp_db_get_field_db_id(unsigned int field);

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
