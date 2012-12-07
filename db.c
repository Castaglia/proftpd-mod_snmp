/*
 * ProFTPD - mod_snmp database storage
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
#include "db.h"

/* On some platforms, this may not be defined.  On AIX, for example, this
 * symbol is only defined when _NO_PROTO is defined, and _XOPEN_SOURCE is 500.
 * How annoying.
 */
#ifndef MAP_FAILED
# define MAP_FAILED	((void *) -1)
#endif

#define SNMP_MAX_LOCK_ATTEMPTS		10

int snmp_table_ids[] = {
  SNMP_DB_ID_DAEMON,
  SNMP_DB_ID_FTP,
  SNMP_DB_ID_SNMP,

  /* XXX Not supported just yet */
#if 0
  SNMP_DB_ID_SSL,
  SNMP_DB_ID_SSH,
  SNMP_DB_ID_SQL,
  SNMP_DB_ID_QUOTA,
  SNMP_DB_ID_BAN,
  SNMP_DB_ID_GEOIP,
#endif

  SNMP_DB_ID_UNKNOWN
};

static const char *snmp_db_root = NULL;

static const char *trace_channel = "snmp.db";

struct snmp_field_info {
  unsigned int field;
  int db_id;
  off_t field_start;
  size_t field_len;
  const char *field_name;
};

static struct snmp_field_info snmp_fields[] = {

  /* Daemon fields */
  { SNMP_DB_DAEMON_F_SOFTWARE, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_SOFTWARE" },
  { SNMP_DB_DAEMON_F_VERSION, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_VERSION" },
  { SNMP_DB_DAEMON_F_ADMIN, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_ADMIN" },
  { SNMP_DB_DAEMON_F_UPTIME, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_UPTIME" },
  { SNMP_DB_DAEMON_F_VHOST_COUNT, SNMP_DB_ID_DAEMON, 0,
    sizeof(uint32_t), "DAEMON_F_VHOST_COUNT" },
  { SNMP_DB_DAEMON_F_CONN_COUNT, SNMP_DB_ID_DAEMON, 4,
    sizeof(uint32_t), "DAEMON_F_CONN_COUNT" },
  { SNMP_DB_DAEMON_F_CONN_TOTAL, SNMP_DB_ID_DAEMON, 8,
    sizeof(uint32_t), "DAEMON_F_CONN_TOTAL" },
  { SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL, SNMP_DB_ID_DAEMON, 12,
    sizeof(uint32_t), "DAEMON_F_CONN_REFUSED_TOTAL" },
  { SNMP_DB_DAEMON_F_RESTART_COUNT, SNMP_DB_ID_DAEMON, 16,
    sizeof(uint32_t), "DAEMON_F_RESTART_COUNT" },
  { SNMP_DB_DAEMON_F_SEGFAULT_COUNT, SNMP_DB_ID_DAEMON, 20,
    sizeof(uint32_t), "DAEMON_F_SEGFAULT_COUNT" },
  { SNMP_DB_DAEMON_F_MAXINST_COUNT, SNMP_DB_ID_DAEMON, 24,
    sizeof(uint32_t), "DAEMON_F_MAXINST_COUNT" },

  /* ftp.sessions fields */
  { SNMP_DB_FTP_SESS_F_SESS_COUNT, SNMP_DB_ID_FTP, 0,
    sizeof(uint32_t), "FTP_SESS_F_SESS_COUNT" },
  { SNMP_DB_FTP_SESS_F_SESS_TOTAL, SNMP_DB_ID_FTP, 4,
    sizeof(uint32_t), "FTP_SESS_F_SESS_TOTAL" },
  { SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL, SNMP_DB_ID_FTP, 8,
    sizeof(uint32_t), "FTP_SESS_F_CMD_INVALID_TOTAL" },

  /* ftp.logins fields */
  { SNMP_DB_FTP_LOGINS_F_TOTAL, SNMP_DB_ID_FTP, 12,
    sizeof(uint32_t), "FTP_LOGINS_F_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_TOTAL, SNMP_DB_ID_FTP, 16,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL, SNMP_DB_ID_FTP, 20,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_BAD_USER_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL, SNMP_DB_ID_FTP, 24,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL, SNMP_DB_ID_FTP, 28,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_GENERAL_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ANON_COUNT, SNMP_DB_ID_FTP, 32,
    sizeof(uint32_t), "FTP_LOGINS_F_ANON_COUNT" },
  { SNMP_DB_FTP_LOGINS_F_ANON_TOTAL, SNMP_DB_ID_FTP, 36,
    sizeof(uint32_t), "FTP_LOGINS_F_ANON_TOTAL" },

  /* ftp.dataTransfers fields */
  { SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL, SNMP_DB_ID_FTP, 40,
    sizeof(uint32_t), "FTP_XFERS_F_DIR_LIST_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL, SNMP_DB_ID_FTP, 44,
    sizeof(uint32_t), "FTP_XFERS_F_DIR_LIST_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL, SNMP_DB_ID_FTP, 48,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_UPLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, SNMP_DB_ID_FTP, 52,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL, SNMP_DB_ID_FTP, 56,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_DOWNLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, SNMP_DB_ID_FTP, 60,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL, SNMP_DB_ID_FTP, 64,
    sizeof(uint32_t), "FTP_XFERS_F_KB_UPLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL, SNMP_DB_ID_FTP, 68,
    sizeof(uint32_t), "FTP_XFERS_F_KB_DOWNLOAD_TOTAL" },

  /* ftp.timeouts fields */
  { SNMP_DB_FTP_TIMEOUTS_F_IDLE_TOTAL, SNMP_DB_ID_FTP, 72,
    sizeof(uint32_t), "FTP_TIMEOUTS_F_IDLE_TOTAL" },
  { SNMP_DB_FTP_TIMEOUTS_F_LOGIN_TOTAL, SNMP_DB_ID_FTP, 76,
    sizeof(uint32_t), "FTP_TIMEOUTS_F_LOGIN_TOTAL" },
  { SNMP_DB_FTP_TIMEOUTS_F_NOXFER_TOTAL, SNMP_DB_ID_FTP, 80,
    sizeof(uint32_t), "FTP_TIMEOUTS_F_NOXFER_TOTAL" },
  { SNMP_DB_FTP_TIMEOUTS_F_STALLED_TOTAL, SNMP_DB_ID_FTP, 84,
    sizeof(uint32_t), "FTP_TIMEOUTS_F_STALLED_TOTAL" },

  /* snmp fields */
  { SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL, SNMP_DB_ID_SNMP, 0,
    sizeof(uint32_t), "SNMP_F_PKTS_RECVD_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_SENT_TOTAL, SNMP_DB_ID_SNMP, 4,
    sizeof(uint32_t), "SNMP_F_PKTS_SENT_TOTAL" },
  { SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL, SNMP_DB_ID_SNMP, 8,
    sizeof(uint32_t), "SNMP_F_TRAPS_SENT_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL, SNMP_DB_ID_SNMP, 12,
    sizeof(uint32_t), "SNMP_F_PKTS_AUTH_ERR_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL, SNMP_DB_ID_SNMP, 16,
    sizeof(uint32_t), "SNMP_F_PKTS_DROPPED_TOTAL" },

  { 0, -1, 0, 0 }
};

struct snmp_db_info {
  int db_id;
  int db_fd;
  const char *db_name;
  char *db_path;
  void *db_data;
  size_t db_datasz;
};

static struct snmp_db_info snmp_dbs[] = {
  { SNMP_DB_ID_UNKNOWN, -1, NULL, NULL, 0 },

  /* Seven numeric fields only in this table: 7 x 4 bytes = 28 bytes */
  { SNMP_DB_ID_DAEMON, -1, "daemon.dat", NULL, NULL, 28 },

  /* The size of the ftp table is calculated as:
   *
   *  3 session fields       x 4 bytes = 12 bytes
   *  7 login fields         x 4 bytes = 28 bytes
   *  8 data transfer fields x 4 bytes = 32 bytes
   *  4 timeout fields       x 4 bytes = 16 bytes
   *
   * for a total of 88 bytes.
   */
  { SNMP_DB_ID_FTP, -1, "ftp.dat", NULL, NULL, 88 },

  /* Five numeric fields only in this table: 5 x 4 bytes = 20 bytes */
  { SNMP_DB_ID_SNMP, -1, "snmp.dat", NULL, NULL, 20 },

#if 0
  { SNMP_DB_ID_SSL, -1, "ssl.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_SSH, -1, "ssh.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_SQL, -1, "sql.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_QUOTA, -1, "quota.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_BAN, -1, "ban.dat", NULL, NULL, 0 }

  { SNMP_DB_ID_GEOIP, -1, "geoip.dat", NULL, NULL, 0 }
#endif

  { -1, -1, NULL, NULL, 0 },
};

/* For a given field ID, return the database ID. */
static int get_field_db_id(unsigned int field) {
  register unsigned int i;
  int db_id = -1;

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      db_id = snmp_fields[i].db_id;
      break;
    }
  }

  if (db_id < 0) {
    errno = ENOENT;
  }

  return db_id;
}

/* For the given field, provision the corresponding lock start and len
 * values, for the byte-range locking.
 */
static int get_field_range(unsigned int field, off_t *field_start,
    size_t *field_len) {
  register unsigned int i;
  int field_idx = -1;

  if (field_start == NULL &&
      field_len == NULL) {
    /* Nothing to do here. */
    return 0;
  }

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      field_idx = i;
      break;
    }
  }

  if (field_idx < 0) {
    errno = ENOENT;
    return -1;
  }

  if (field_start != NULL) {
    *field_start = snmp_fields[field_idx].field_start;
  }

  if (field_len != NULL) {
    *field_len = snmp_fields[field_idx].field_len;
  }

  return 0;
}

static const char *get_lock_type(struct flock *lock) {
  const char *lock_type;

  switch (lock->l_type) {
    case F_RDLCK:
      lock_type = "read";
      break;

    case F_WRLCK:
      lock_type = "write";
      break;

    case F_UNLCK:
      lock_type = "unlock";
      break;

    default:
      lock_type = "[unknown]";
  }

  return lock_type;
}

const char *snmp_db_get_fieldstr(pool *p, unsigned int field) {
  register unsigned int i;
  char fieldstr[256];
  int db_id = -1;
  const char *db_name = NULL, *field_name = NULL;

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      db_id = snmp_fields[i].db_id;
      field_name = snmp_fields[i].field_name;
      break;
    }
  }

  if (db_id < 0) {
    return NULL;
  }

  db_name = snmp_dbs[db_id].db_name;

  memset(fieldstr, '\0', sizeof(fieldstr));
  snprintf(fieldstr, sizeof(fieldstr)-1, "%s (%d) [%s (%d)]",
    field_name, field, db_name, db_id);
  return pstrdup(p, fieldstr);
}

int snmp_db_rlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_RDLCK;
  lock.l_whence = SEEK_SET;

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to read-lock field %u db ID %d table '%s' "
    "(fd %d start %lu len %lu)", nattempts, field, db_id,
    snmp_dbs[db_id].db_path, db_fd, (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "read-lock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to read-lock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire read-lock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "read-lock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_wlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to write-lock field %u db ID %d table '%s' "
    "(fd %d start %lu len %lu)", nattempts, field, db_id,
    snmp_dbs[db_id].db_path, db_fd, (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "write-lock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to write-lock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire write-lock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "write-lock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_unlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_UNLCK;
  lock.l_whence = SEEK_SET;

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to unlock field %u table '%s' (fd %d start %lu len %lu)",
    nattempts, field, snmp_dbs[db_id].db_path, db_fd,
    (unsigned long) lock.l_start, (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "unlock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to unlock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire unlock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "unlock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_open(pool *p, int db_id) {
  int db_fd, mmap_flags, res, xerrno;
  char *db_path;
  size_t db_datasz;
  void *db_data;

  if (db_id < 0) {
    errno = EINVAL;
    return -1;
  }

  /* First, see if the database is already opened. */
  if (snmp_dbs[db_id].db_path != NULL) {
    return 0;
  }

  pr_trace_msg(trace_channel, 19,
    "opening db ID %d (db root = %s, db name = %s)", db_id, snmp_db_root,
    snmp_dbs[db_id].db_name);

  db_path = pdircat(p, snmp_db_root, snmp_dbs[db_id].db_name, NULL);

  PRIVS_ROOT
  db_fd = open(db_path, O_RDWR|O_CREAT, 0600);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (db_fd < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error opening SNMPTable '%s': %s", db_path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  /* Make sure the fd isn't one of the big three. */
  res = pr_fs_get_usable_fd(db_fd);
  if (res >= 0) {
    db_fd = res;
  }

  snmp_dbs[db_id].db_fd = db_fd;
  snmp_dbs[db_id].db_path = db_path;

  db_datasz = snmp_dbs[db_id].db_datasz;

  /* Truncate the table first; any existing data should be deleted. */
  if (ftruncate(db_fd, 0) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error truncating SNMPTable '%s' to size 0: %s", db_path,
      strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  /* Seek to the desired table size (actually, one byte less than the desired
   * size) and write a single byte, so that there's enough allocated backing
   * store on the filesystem to support the ensuing mmap() call.
   */
  if (lseek(db_fd, db_datasz, SEEK_SET) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error seeking to %lu in table '%s': %s",
      (unsigned long) db_datasz-1, db_path, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  if (write(db_fd, "", 1) != 1) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error writing single byte to table '%s': %s", db_path, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  mmap_flags = MAP_SHARED;
#if defined(MAP_ANONYMOUS)
  /* Linux */
  mmap_flags |= MAP_ANONYMOUS;

  /* According to some of the Linux man pages, use of the MAP_ANONYMOUS flag
   * requires (for some implementations) that the fd be -1, since it will
   * effectively be ignored.
   */
  db_fd = -1;

#elif defined(MAP_ANON)
  /* FreeBSD, MacOSX, Solaris, others? */
  mmap_flags |= MAP_ANON;
#endif

  db_data = mmap(NULL, db_datasz, PROT_READ|PROT_WRITE, mmap_flags, db_fd, 0);
  if (db_data == MAP_FAILED) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error mapping table '%s' size %lu into memory: %s", db_path,
      (unsigned long) db_datasz, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  snmp_dbs[db_id].db_data = db_data;

  /* Make sure the data are zeroed. */
  memset(db_data, 0, db_datasz);

  return 0;
}

int snmp_db_close(pool *p, int db_id) {
  int db_fd, res;
  void *db_data;

  if (db_id < 0) {
    errno = EINVAL;
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;

  if (db_data != NULL) {
    size_t db_datasz;

    db_datasz = snmp_dbs[db_id].db_datasz;

    if (munmap(db_data, db_datasz) < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 1,
        "error unmapping SNMPTable '%s' from memory: %s",
        pdircat(p, snmp_db_root, snmp_dbs[db_id].db_path, NULL),
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  snmp_dbs[db_id].db_data = NULL;

  db_fd = snmp_dbs[db_id].db_fd;
  res = close(db_fd);
  if (res < 0) {
    return -1;
  }

  snmp_dbs[db_id].db_fd = -1;
  return 0;
}

int snmp_db_get_value(pool *p, unsigned int field, int32_t *int_value,
    char **str_value, size_t *str_valuelen) {
  void *db_data, *field_data;
  int db_id, res;
  off_t field_start;
  size_t field_len;

  switch (field) {
    case SNMP_DB_DAEMON_F_SOFTWARE:
      *str_value = "proftpd";
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_VERSION:
      *str_value = "ProFTPD Version " PROFTPD_VERSION_TEXT " (built at " BUILD_STAMP ")";
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_ADMIN:
      *str_value = main_server->ServerAdmin; 
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_UPTIME: {
      struct timeval now_tv;

      /* TimeTicks are in hundredths of seconds since start time. */
      gettimeofday(&now_tv, NULL);

      *int_value = (int32_t) (((now_tv.tv_sec - snmp_start_tv.tv_sec) * 100) +
        ((now_tv.tv_usec - snmp_start_tv.tv_usec) / 10000));

      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;
    }

    default:
      break;
  }

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_rlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);
  memmove(int_value, field_data, field_len);

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "read value %lu for field %s", (unsigned long) *int_value,
     snmp_db_get_fieldstr(p, field));
  return 0;
}

int snmp_db_incr_value(pool *p, unsigned int field, int32_t incr) {
  uint32_t orig_val, new_val;
  int db_id, res;
  void *db_data, *field_data;
  off_t field_start;
  size_t field_len;

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_wlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);
  memmove(&new_val, field_data, field_len);
  orig_val = new_val;

  if (orig_val == 0 &&
      incr < 0) {
    /* If we are in fact decrementing a value, and that value is
     * already zero, then do nothing.
     */

    res = snmp_db_unlock(field);
    if (res < 0) {
      return -1;
    }

    pr_trace_msg(trace_channel, 19,
      "value already zero for field %s (%d), not decrementing by %ld",
      snmp_db_get_fieldstr(p, field), field, (long) incr);
    return 0;
  }

  new_val += incr;
  memmove(field_data, &new_val, field_len);

#if 0
  res = msync(field_data, field_len, MS_SYNC);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "msync(2) error for field %s (%d): %s",
      snmp_db_get_fieldstr(p, field), field, strerror(errno));  
  }
#endif

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "wrote value %lu (was %lu) for field %s (%d)", (unsigned long) new_val,
    (unsigned long) orig_val, snmp_db_get_fieldstr(p, field), field);
  return 0;
}

int snmp_db_reset_value(pool *p, unsigned int field) {
  uint32_t val;
  int db_id, res;
  void *db_data, *field_data;
  off_t field_start;
  size_t field_len;

  db_id = get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_wlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);

  val = 0;
  memmove(field_data, &val, field_len);

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "reset value to 0 for field %s", snmp_db_get_fieldstr(p, field));
  return 0;
}

int snmp_db_set_root(const char *db_root) {
  if (db_root == NULL) {
    errno = EINVAL;
    return -1;
  }

  snmp_db_root = db_root;
  return 0;
}
