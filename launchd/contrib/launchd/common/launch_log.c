/*
 * Launchd logger functions
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "launch_log.h"

static int log_fd;
static int log_inited = 0;
static int lock = 0;

static char *get_logfile();
static char *get_timestamp(void);
static void get_lock(void);
static void release_lock(void);

/*
 * Initialize logging.
 */
void
log_init()
{
	char *logfile = get_logfile();
	if ((log_fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND)) == -1) {
		syslog(LOG_ERR, "error logging init");
		log_inited = 0;
	} else {
		syslog(LOG_INFO, "logging initialized");
		log_inited = 1;
	}
	free(logfile);
}

/*
 * Log information message.
 */
void
log_info(const char *format, ...)
{
	va_list ap;
	char *tmp_msg, *new_msg;

	if (!log_inited)
		return;
	get_lock();
	va_start(ap, format);
	vasprintf(&tmp_msg, format, ap);
	asprintf(&new_msg, "%s INFO: %s\n", get_timestamp(), tmp_msg);
	write(log_fd, new_msg, strlen(new_msg));
	free(tmp_msg);
	free(new_msg);
	va_end(ap);
	release_lock();
}

/*
 * Log error message.
 */
void
log_err(const char *format, ...)
{
	va_list ap;
	char *tmp_msg, *new_msg;

	if (!log_inited)
		return;
	get_lock();
	va_start(ap, format);
	vasprintf(&tmp_msg, format, ap);
	asprintf(&new_msg, "%s ERROR: %s\n", get_timestamp(), tmp_msg);
	write(log_fd, new_msg, strlen(new_msg));
	free(tmp_msg);
	free(new_msg);
	release_lock();
}

/*
 * Close logging file.
 */
void log_close(void)
{
	if (!log_inited)
		return;

	close(log_fd);
	log_inited = 0;
}

/*
 * Determine the log file name.
 *   - pid1 = PID1_LOGFILE
 *   - non-pid1 filename = {NONROOT_LOGDIR}_<PID>.log
 *
 *   * the caller is responsible for freeing the allocated string
 */
static char *
get_logfile()
{
	char *logfile;
	if (getpid() == 1) {
		asprintf(&logfile, "%s", PID1_LOGFILE);
	} else {
		asprintf(&logfile, "%s/launchd_%d.log", NONROOT_LOGDIR, getpid());
	}
	return (logfile);
}

/*
 * Checks if logging is initialized.
 */
int
is_log_inited()
{
	return (log_inited);
}


static time_t now;

/*
 * Get current timestamp.
 */
static char *
get_timestamp(void)
{
	char *timestamp;

	(void)time(&now);
	timestamp = ctime(&now);

	/* remove newline */
	timestamp[24] = '\0';

	/* exclude day of the week */
	timestamp+=4;

	return (timestamp);
}

/*
 * Acquire lock.
 */
static void
get_lock(void)
{
	while (lock > 0);;
	lock++;
}

/*
 * Release lock.
 */
static void
release_lock(void)
{
	lock--;
}
