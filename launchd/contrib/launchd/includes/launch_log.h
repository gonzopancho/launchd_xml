#ifndef _LOG_H
#define _LOG_H

#define PID1_LOGFILE    "/var/log/launchd.log"
#define NONROOT_LOGDIR  "/tmp"

void log_init(void);
void log_info(const char *, ...);
void log_err(const char *, ...);
void log_close(void);
int is_log_inited();

#endif /* _LOG_H */
