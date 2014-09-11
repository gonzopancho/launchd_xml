/*
 * Copyright 2006 Infoweapons Corporation
 */

/*
 * $FreeBSD$
 *
 * Copyright (c) 2005 R. Tyler Ballance <tyler@tamu.edu> All rights reserved.
 *
 */

/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <ttyent.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <err.h>
#include <termios.h>
#include <libutil.h>
#ifdef _SQL_CONF_
#include <solidb.h> /* equivalent to sqlited.h */
#endif

#include "launch.h"
#include "launch_priv.h"
#include "launchd.h"
#include "launchd_core_logic.h"
#include "launchd_unix_ipc.h"

#ifdef _SQL_CONF_
#include "launch_sb_if.h"
#endif

#include "launch_log.h"
#include "launch_util.h"

extern char **environ;

static void async_callback(void);
static void signal_callback(void *, struct kevent *);
static void fs_callback(void);
static void readcfg_callback(void *, struct kevent *);

static kq_callback kqasync_callback = (kq_callback)async_callback;
static kq_callback kqsignal_callback = signal_callback;
static kq_callback kqfs_callback = (kq_callback)fs_callback;
static kq_callback kqreadcfg_callback = readcfg_callback;
static kq_callback kqshutdown_callback = (kq_callback)launchd_shutdown;

#ifdef _SQL_CONF_
static void load_sbconf(void);
static void set_configdefaults(void);
#endif

#ifdef PID1_REAP_ADOPTED_CHILDREN
static void pid1waitpid(void);
#endif
static void pid1_magic_init(bool sflag, bool vflag, bool xflag,
			    bool dflag);
static struct jobcb *conceive_firstborn(char *argv[],
					const char *session_user);
static void mount_devfs(void);
static void usage(FILE *where);

static void loopback_setup(void);
static void workaround3048875(int argc, char *argv[]);
static void testfd_or_openfd(int fd, const char *path, int flags);

static int mainkq = 0;
static int asynckq = 0;
static pid_t readcfg_pid = 0;
static bool re_exec_in_single_user_mode = false;
static char *pending_stdout = NULL;
static char *pending_stderr = NULL;
static struct jobcb *fbj = NULL;
sigset_t blocked_signals;
bool shutdown_in_progress = false;
int batch_disabler_count = 0;

#ifdef _SQL_CONF_
/* solidbase config data */
static char *sbuser = NULL;
static char *sbpass = NULL;
static char *sbhost = NULL;
static int  sbport = 0;
static char *sbdb  = NULL;
static char *sbconf = NULL;
#endif

extern int clang;

int main(int argc, char *argv[])
{
	static const int sigigns[] = { SIGHUP, SIGINT, SIGPIPE, SIGALRM,
				       SIGTERM, SIGURG, SIGTSTP, SIGTSTP,
				       SIGCONT, /*SIGCHLD,*/SIGTTIN,
				       SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ,
				       SIGVTALRM, SIGPROF, SIGWINCH,
				       SIGINFO, SIGUSR1, SIGUSR2 };
	bool sflag = false, xflag = false, vflag = false, dflag = false;
	const char *session_type = NULL;
	const char *session_user = NULL;
	const char *optargs = NULL;
	struct kevent kev;
	size_t i;
	int ch, ker;

	/* main() phase one: sanitize the process */

	if (getpid() == 1) {
		workaround3048875(argc, argv);
	} else {
		int sigi, fdi, dts = getdtablesize();
		sigset_t emptyset;

		for (fdi = STDERR_FILENO + 1; fdi < dts; fdi++) {
#ifdef __BUILD_DARWIN
			launchd_assumes(close(fdi) == 0);
#else
			/* SolidBSD/FreeBSD expects a '-1' for
			 *  the invalid descriptors.
			 */
			launchd_assumes(close(fdi) == -1);
#endif
		}
		for (sigi = 1; sigi < NSIG; sigi++)
			launchd_assumes(signal(sigi,SIG_DFL) != SIG_ERR);
		sigemptyset(&emptyset);
		launchd_assumes(sigprocmask(SIG_SETMASK,
					    &emptyset, NULL) == 0);
	}

	testfd_or_openfd(STDIN_FILENO, _PATH_DEVNULL, O_RDONLY);
	testfd_or_openfd(STDOUT_FILENO, _PATH_DEVNULL, O_WRONLY);
	testfd_or_openfd(STDERR_FILENO, _PATH_DEVNULL, O_WRONLY);

	/* main phase two: parse arguments */

	if (getpid() == 1) {
		optargs = "svx";
	} else if (getuid() == 0) {
		optargs = "S:U:dh";
	} else {
		optargs = "dh";
	}

	while ((ch = getopt(argc, argv, optargs)) != -1) {
		switch (ch) {
			/* what type of session we're creating */
		case 'S': session_type = optarg; break;
			/* which user to create a session as */
		case 'U': session_user = optarg; break;
			/* daemonize
			 * for PID 1 - devfs 
			 */
		case 'd': dflag = true;   break;
			/* single user */        
		case 's': sflag = true;   break;
			/* safe boot */
		case 'x': xflag = true;   break;
			/* verbose boot */
		case 'v': vflag = true;   break;
			/* help */
		case 'h': usage(stdout);  break;
			/* we should do something with the global optopt
			 * variable here */
		case '?': 
		default:
			fprintf(stderr, "ignoring unknown arguments\n");
			usage(stderr);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	/* Initialize the root boot_strap. 
	 * For non-MACH systems, this will keeps the jobs list.
	 */
	init_root_bootstrap();

	if ((session_type && !session_user) 
	    || (!session_user && session_type)) {
		fprintf(stderr, "-S and -U must be used together\n");
		exit(EXIT_FAILURE);
	}

	/* main phase three: if we need to become a user, do so ASAP */
	
	if (session_user) {
		struct passwd *pwe = getpwnam(session_user);
		uid_t u = pwe ? pwe->pw_uid : 0;
		gid_t g = pwe ? pwe->pw_gid : 0;
		
		if (pwe == NULL) {
			fprintf(stderr, "lookup of user %s failed!\n",
				session_user);
			exit(EXIT_FAILURE);
		}

		launchd_assert(initgroups(session_user, g) != -1);

		launchd_assert(setgid(g) != -1);

		launchd_assert(setuid(u) != -1);

#ifdef _SQL_CONF_
		if (getpid() != 1)
			sbuser = strdup(pwe->pw_name);
#endif
	} 

#ifdef _SQL_CONF_
	/* set config for solidbase */
	load_sbconf();
#endif

	/* main phase four: get the party started */

	if ((getpid() != 1) && dflag)
		launchd_assumes(daemon(0, 0) == 0);

	openlog(getprogname(),
		LOG_CONS|(getpid() != 1 ? LOG_PID|LOG_PERROR : 0),
		LOG_LAUNCHD);
	setlogmask(LOG_UPTO(LOG_NOTICE));

	launchd_assert((mainkq = kqueue()) != -1);

	launchd_assert((asynckq = kqueue()) != -1);
	
	launchd_assert(kevent_mod(asynckq, EVFILT_READ, EV_ADD, 0, 0,
				  &kqasync_callback) != -1);

	sigemptyset(&blocked_signals);

	for (i = 0; i < (sizeof(sigigns) / sizeof(int)); i++) {
		launchd_assumes(kevent_mod(sigigns[i], EVFILT_SIGNAL,
					   EV_ADD, 0, 0,
					   &kqsignal_callback) != -1);
		sigaddset(&blocked_signals, sigigns[i]);
		launchd_assumes(signal(sigigns[i], SIG_IGN) != SIG_ERR);
	}

	/* Signal SIGCHLD will not be ignored so that wait* function
	 * calls can be used.
	 */
	launchd_assert(kevent_mod(SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0,
				  &kqsignal_callback) != -1);

	if (argv[0] || (session_type != NULL 
			&& 0 == strcasecmp(session_type, "tty")))
		fbj = conceive_firstborn(argv, session_user);

	if (NULL == getenv("PATH"))
		setenv("PATH", _PATH_STDPATH, 1);

	if (getpid() == 1) {
		pid1_magic_init(sflag, vflag, xflag, dflag);
	} else {
		ipc_server_init();
	}

	/* do this after pid1_magic_init() to not catch ourselves
	 * mounting stuff
	 */
	launchd_assumes(kevent_mod(0, EVFILT_FS, EV_ADD, 0, 0,
				   &kqfs_callback) != -1);

	if (session_type) {
		pid_t pp = getppid();

		/* As a per session launchd, we need to exit if our
		 *  parent dies.
		 * Normally, in Unix, SIGHUP would cause us to exit, but
		 *  we're a daemon, and daemons use SIGHUP to signal the
		 *  need to reread configuration files. "Weee."
		 */

		if (pp == 1)
			exit(EXIT_SUCCESS);

		ker = kevent_mod(pp, EVFILT_PROC, EV_ADD, 0, 0,
				 &kqshutdown_callback);

		if (ker == -1)
			exit(launchd_assumes(errno == ESRCH)
			     ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	/* for pid 1, /etc/rc is executed first */
	if (getpid() != 1) {
#ifdef _SQL_CONF_
		reload_launchd_config_sql();
#else
		reload_launchd_config_plist();
#endif
	}

	if (fbj)
		job_start(fbj);

	for (;;) {
		if (getpid() == 1 && readcfg_pid == 0)
			init_pre_kevent();

		if (shutdown_in_progress && total_children == 0) {
			job_remove_all();

			shutdown_in_progress = false;

			if (getpid() != 1) {
				exit(EXIT_SUCCESS);
			} else if (re_exec_in_single_user_mode) {
				re_exec_in_single_user_mode = false;
				launchd_assumes(execl(LAUNCHD_PATH,
						      LAUNCHD_PATH,
						      "-s", NULL) != -1);
			}
		}

		if (launchd_assumes(kevent(mainkq, NULL, 0, &kev, 1,
					   NULL) == 1))
			(*((kq_callback *)kev.udata))(kev.udata, &kev);
	}
}

#ifdef _SQL_CONF_
/*
 * Load the launchd-solidbase configuration file.
 */
static void 
load_sbconf(void)
{
	int fd;
	char *portstr;
	properties head_prop;
	static char *sbconfig = PID1LAUNCHDSB_CONF;
	const char *home = getenv("HOME");

	set_configdefaults();
	if (home)
		asprintf(&sbconfig, "%s/%s", home, LAUNCHDSB_CONF);

	if ((fd = open(sbconfig, O_RDONLY)) == -1) {
		/* stick to default settings */
		fprintf(stderr, "using defaults for solidbase access\n");
		syslog(LOG_ERR, "missing config file : %s", sbconfig);
		return;
	}

	head_prop = properties_read(fd);

	/* if not set in config file, the default is used */
	set_cfvalue(head_prop, SBUSER, &sbuser);
	set_cfvalue(head_prop, SBHOST, &sbhost);
	set_cfvalue(head_prop, SBDB, &sbdb);
	set_cfvalue(head_prop, SBCONF, &sbconf);

	set_cfvalue(head_prop, SBPORT, &portstr);
	sbport = (int)strtol(portstr, (char **)NULL, 10);

	/* special case for password
	 *   - if not in config file, prompt from user
	 *   * more like a security issue because it is stored in cleartext
	 */
	if ((set_cfvalue(head_prop, SBPASS, &sbpass)) == 0) {
		if (getpid() != 1)
			sbpass = input_sbpass(sbuser);
		/* leave as default if not set in config file */
	}

	properties_free(head_prop);
	close(fd);
	return;
}

/*
 * Set default configuration for solidbase access.
 */
static void
set_configdefaults(void)
{
	if (getpid() == 1) {
		sbuser = "admin";
		sbpass = "admin123";
		sbhost = DEF_PID1_SBHOST;
		sbport = DEF_PID1_SBPORT;
		sbdb = DEF_SBDB;
		sbconf = PID1_CONF;

	} else {
		if (sbuser == NULL) {
			sbuser = getlogin();
		}
		sbpass = "";
		sbhost = DEF_SBHOST;
		sbport = DEF_SBPORT;
		sbdb = DEF_SBDB;
		sbconf = get_confname(sbuser);

	}
	return;
}

#endif

static void pid1_magic_init(bool sflag, bool vflag, bool xflag,
			    bool dflag)
{
#ifdef _BUILD_DARWIN_
	int memmib[2] = { CTL_HW, HW_MEMSIZE };
#else
	int memmib[2] = { CTL_HW, HW_REALMEM };
#endif
	int mvnmib[2] = { CTL_KERN, KERN_MAXVNODES };
	int hnmib[2] = { CTL_KERN, KERN_HOSTNAME };
	uint64_t mem = 0;
	uint32_t mvn;
	size_t memsz = sizeof(mem);
#ifdef KERN_TFP
	struct group *tfp_gr;
		
	if (launchd_assumes((tfp_gr = getgrnam("procview")) != NULL)) {
		int tfp_r_mib[3] = { CTL_KERN, KERN_TFP,
				     KERN_TFP_READ_GROUP };
		gid_t tfp_r_gid = tfp_gr->gr_gid;
		launchd_assumes(sysctl(tfp_r_mib, 3, NULL, NULL,
				       &tfp_r_gid, sizeof(tfp_r_gid))
				!= -1);
	}

	if (launchd_assumes((tfp_gr = getgrnam("procmod")) != NULL)) {
		int tfp_rw_mib[3] = { CTL_KERN, KERN_TFP,
				      KERN_TFP_RW_GROUP };
		gid_t tfp_rw_gid = tfp_gr->gr_gid;
		launchd_assumes(sysctl(tfp_rw_mib, 3, NULL, NULL,
				       &tfp_rw_gid, sizeof(tfp_rw_gid))
				!= -1);
	}
#endif

	setpriority(PRIO_PROCESS, 0, -1);

	if (setsid() == -1)
		syslog(LOG_ERR, "setsid(): %m");

	if (chdir("/") == -1)
		syslog(LOG_ERR, "chdir(\"/\"): %m");

	if (sysctl(memmib, 2, &mem, &memsz, NULL, 0) == -1) {
		syslog(LOG_WARNING, "sysctl(\"%s\"): %m", "hw.physmem");
	} else {
		mvn = mem / (64 * 1024) + 1024;
		if (sysctl(mvnmib, 2, NULL, NULL, &mvn,
			   sizeof(mvn)) == -1)
			syslog(LOG_WARNING, "sysctl(\"%s\"): %m",
			       "kern.maxvnodes");
	}
	if (sysctl(hnmib, 2, NULL, NULL, "localhost",
		   sizeof("localhost")) == -1)
		syslog(LOG_WARNING, "sysctl(\"%s\"): %m",
		       "kern.hostname");

	if (setlogin("root") == -1)
		syslog(LOG_ERR, "setlogin(\"root\"): %m");

	loopback_setup();

#ifdef _BUILD_DARWIN
	if (mount("fdesc", "/dev", MNT_UNION, NULL) == -1)
		syslog(LOG_ERR, "mount(\"%s\", \"%s\", ...): %m",
		       "fdesc", "/dev/");
#else
	if (dflag)
		mount_devfs();
#endif
	/* Run fsck before mounting local fs. */
	if (!sflag) 
		fsck_all();

	/* MOVED TO fsck_callback() */
	/* Mount local filesystems earlier to use UNIX file sockets. */
	// mount_localfs();

	init_boot(sflag, vflag, xflag);
}

/**
 * Mount devfs.
 *  Note: Copied from *BSD init.c.
 */
static void mount_devfs(void)
{
	struct iovec iov[4];
	char *s;
	int i;
	
	iov[0].iov_base = "fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = "devfs";
	iov[1].iov_len = sizeof("devfs");
	iov[2].iov_base = "fspath";
	iov[2].iov_len = sizeof("fspath");
	/* 
	 * Try to avoid the trailing slash in _PATH_DEV.
	 * Be *very* defensive.
	 */
	s = strdup(_PATH_DEV);
	if (s != NULL) {
		i = strlen(s);
		if (i > 0 && s[i - 1] == '/')
			s[i - 1] = '\0';
		iov[3].iov_base = s;
		iov[3].iov_len = strlen(s) + 1;
	} else {
		iov[3].iov_base = _PATH_DEV;
		iov[3].iov_len = sizeof(_PATH_DEV);
	}
	nmount(iov, 4, 0);
	if (s != NULL)
		free(s);
}

void usage(FILE *where)
{
	const char *opts = "[-d]";

	if (getuid() == 0)
		opts = "[-d] [-S <type> -U <user>]";

	fprintf(where, "%s: %s [-- command [args ...]]\n", getprogname(),
		opts);

	fprintf(where, "\t-d          Daemonize.\n");
	fprintf(where, "\t-h          This usage statement.\n");

	if (getuid() == 0) {
		fprintf(where, "\t-S <type>   What type of session to create (Aqua, tty or X11).\n");
		fprintf(where, "\t-U <user>   Which user to create the session as.\n");
	}
	
	if (where == stdout)
		exit(EXIT_SUCCESS);
}

int kevent_mod(uintptr_t ident, short filter, u_short flags,
	       u_int fflags, intptr_t data, void *udata)
{
	struct kevent kev;
	int q = mainkq;

	if (EVFILT_TIMER == filter || EVFILT_VNODE == filter)
		q = asynckq;

	if (flags & EV_ADD && !launchd_assumes(udata != NULL)) {
		errno = EINVAL;
		return -1;
	}
#if 0  /* Commented because a call to /etc/rc requires this kevent
	* registration. 
	*/
#ifdef PID1_REAP_ADOPTED_CHILDREN
		if (filter == EVFILT_PROC && getpid() == 1)
			return 0;
#endif
#endif
	EV_SET(&kev, ident, filter, flags, fflags, data, udata);
	return kevent(q, &kev, 1, NULL, 0, NULL);
}


#ifdef PID1_REAP_ADOPTED_CHILDREN
int pid1_child_exit_status = 0;
static void pid1waitpid(void)
{
	pid_t p;

	while ((p = waitpid(-1, &pid1_child_exit_status, WNOHANG)) > 0) {
	        if (p == readcfg_pid) {
			readcfg_callback(NULL, NULL);
		} 
#ifdef _BUILD_DARWIN_		
		else if (!job_reap_pid(p)) {
/* this function is defined in Darwin's init.c, not ours :( */
			init_check_pid(p);
		}
#endif
	}
}
#endif

void
launchd_shutdown(void)
{
	shutdown_in_progress = true;

	/* end logging */
	log_close();

	launchd_assumes(close(asynckq) != -1);

	job_remove_all();

	if (getpid() == 1)
		catatonia();
}

void
launchd_single_user(void)
{
	int tries;

	launchd_shutdown();

	kill(-1, SIGTERM);

	for (tries = 0; tries < 10; tries++) {
		sleep(1);
		if (kill(-1, 0) == -1 && errno == ESRCH)
			goto out;
	}

	syslog(LOG_WARNING, "Gave up waiting for processes to exit while going to single user mode, sending SIGKILL");
	kill(-1, SIGKILL);

out:
	re_exec_in_single_user_mode = true;
}

static void signal_callback(void *obj __attribute__((unused)),
			    struct kevent *kev)
{
	int howto = 0;
	bool reboot = false;

	switch (kev->ident) {
	case SIGHUP:
		if (getpid() == 1)
			update_ttys();
		break;
	case SIGUSR2:
		howto = RB_POWEROFF;
	case SIGUSR1:
		howto |= RB_HALT;
	case SIGINT:
		reboot = true;
	case SIGTERM:
		launchd_shutdown();
		if (getpid() == 1)
			death(reboot, howto);
		break;
#ifdef PID1_REAP_ADOPTED_CHILDREN
	case SIGCHLD:
		if (getpid() == 1) 
			pid1waitpid();
		break;
#endif
	case SIGTSTP:
		if (getpid() == 1)
			catatonia();
		break;
	case SIGALRM:
		clang = 1;
		break;
	default:
		break;
	} 
}

static void fs_callback(void)
{

#ifdef _BUILD_DARWIN
	static bool mounted_volfs = false;

	if (1 != getpid())
		mounted_volfs = true;
#endif /* _BUILD_DARWIN */

	if (pending_stdout) {
		int fd = open(pending_stdout, O_CREAT|O_APPEND|O_WRONLY,
			      DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDOUT_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stdout);
			pending_stdout = NULL;
		}
	}
	if (pending_stderr) {
		int fd = open(pending_stderr, O_CREAT|O_APPEND|O_WRONLY,
			      DEFFILEMODE);
		if (fd != -1) {
			launchd_assumes(dup2(fd, STDERR_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			free(pending_stderr);
			pending_stderr = NULL;
		}
	}

#ifdef _BUILD_DARWIN
	if (!mounted_volfs) {
		int r = mount("volfs", VOLFSDIR, MNT_RDONLY, NULL);

		if (-1 == r && errno == ENOENT) {
			mkdir(VOLFSDIR, ACCESSPERMS 
			      & ~(S_IWUSR|S_IWGRP|S_IWOTH));
			r = mount("volfs", VOLFSDIR, MNT_RDONLY, NULL);
		}

		if (-1 == r) {
			syslog(LOG_WARNING,
			       "mount(\"%s\", \"%s\", ...): %m", "volfs",
			       VOLFSDIR);
		} else {
			mounted_volfs = true;
		}
	}
#endif /* _BUILD_DARWIN */

	ipc_server_init();
}

static void readcfg_callback(void *obj __attribute__((unused)),
			     struct kevent *kev __attribute__((unused)))
{
	int status;

#ifdef PID1_REAP_ADOPTED_CHILDREN
	if (getpid() == 1) {
		status = pid1_child_exit_status;
#ifdef _SQL_CONF_
		/* send SIGUSR1 to solidbase for inet IF */
		enable_solidbase_inet();
#endif
	}
	else
#endif
		if (!launchd_assumes(waitpid(readcfg_pid, &status, 0) != -1))
			return;

	readcfg_pid = 0;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited with status: %d", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited abnormally: %s", strsignal(WTERMSIG(status)));
	} else {
		syslog(LOG_WARNING, "Unable to read launchd.conf: launchctl exited abnormally");
	}
}

#ifdef _SQL_CONF_
/**
 * Loads/reloads the configuration files by calling launchctl.
 *
 */
void reload_launchd_config_sql(void)
{
	int spair1[2], spair2[2];
	launchd_assumes(socketpair(AF_UNIX, SOCK_STREAM, 0, 
				   spair1) == 0);
	launchd_assumes(socketpair(AF_UNIX, SOCK_STREAM, 0,
				   spair2) == 0);
	readcfg_pid = launchd_fork();
	if (readcfg_pid == 0) {
		/* child process */
		/* socket pair 1: used for trusted connection */
		char nbuf[100];
		launchd_assumes(close(spair1[0]) == 0);
		sprintf(nbuf, "%d", spair1[1]);
		setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
		/* socket pair 2: used for reading launchctl commands 
		 *    from launchd parent process
		 */
		launchd_assumes(close(spair2[0]) == 0);
		launchd_assumes(dup2(spair2[1], STDIN_FILENO) != -1);
		launchd_assumes(close(spair2[1]) == 0);
		log_info("invoking launchctl");
		launchd_assumes(execl(LAUNCHCTL_SQL_PATH, 
				      LAUNCHCTL_SQL_PATH,
				      NULL) != -1);
		exit(EXIT_FAILURE);
	} else if (readcfg_pid == -1) {
		/* error in fork() */
		launchd_assumes(close(spair1[0]) == 0);
		launchd_assumes(close(spair1[1]) == 0);
		launchd_assumes(close(spair2[0]) == 0);
		launchd_assumes(close(spair2[1]) == 0);
		syslog(LOG_ERR, "fork(): %m");
		log_err("fork error in reload_launchd_config_sql()");
		readcfg_pid = 0;
	} else {
		/* parent process */
		sqlited *db;
		char *sbcmd;
		launchd_assumes(close(spair1[1]) == 0);
		ipc_open(_fd(spair1[0]), NULL);
		launchd_assumes(kevent_mod(readcfg_pid, 
					   EVFILT_PROC, 
					   EV_ADD, NOTE_EXIT, 0, 
					   &kqreadcfg_callback) != -1);
		/* write to launchctl's STDIN here */
		launchd_assumes(close(spair2[1]) == 0);
		db = connect_sb(sbuser, sbpass, sbhost, sbport, sbdb);

		if (db != NULL) {
			/* send 'setsbacct' */
			asprintf(&sbcmd, "setsbacct %s %s %s %d\n", sbuser,
				 sbpass, sbhost, sbport);
			log_info("%s", sbcmd);
			if (write(spair2[0], sbcmd, strlen(sbcmd)) == -1)
				log_err("socket write error: %d", errno);

			if ((load_initrc_jobs(db, sbconf,
					      spair2[0])) != SQLITED_OK) {
				DEBUG_PRINT("DB Error: Fall-back to plist!");
				log_err("DB Error: Fall-back to plist!");
				reload_launchd_config_plist();
			} else {
				/* successful initial configuration */
			}
			free(sbcmd);
		} else {
			log_err("Failure connecting to DB");
			launchd_assumes(close(spair1[0]) == 0);
			launchd_assumes(close(spair2[0]) == 0);
			exit(1);
		}

		close(spair2[0]);
		sqlited_close(db);
	}
}
#endif

void reload_launchd_config_plist(void)
{
	struct stat sb;
	static char *ldconf = PID1LAUNCHD_CONF;
	const char *h = getenv("HOME");

	if (h && ldconf == PID1LAUNCHD_CONF)
		asprintf(&ldconf, "%s/%s", h, LAUNCHD_CONF);

	if (!ldconf)
		return;

	if (lstat(ldconf, &sb) == 0) {
		int spair[2];
		launchd_assumes(socketpair(AF_UNIX, SOCK_STREAM, 0, 
					   spair) == 0);
		readcfg_pid = launchd_fork();
		if (readcfg_pid == 0) {
			char nbuf[100];
			launchd_assumes(close(spair[0]) == 0);
			sprintf(nbuf, "%d", spair[1]);
			setenv(LAUNCHD_TRUSTED_FD_ENV, nbuf, 1);
			int fd = open(ldconf, O_RDONLY);
			if (fd == -1) {
				syslog(LOG_ERR, "open(\"%s\"): %m", 
				       ldconf);
				exit(EXIT_FAILURE);
			}
			launchd_assumes(dup2(fd, STDIN_FILENO) != -1);
			launchd_assumes(close(fd) == 0);
			launchd_assumes(execl(LAUNCHCTL_PLIST_PATH, 
					      LAUNCHCTL_PLIST_PATH, 
					      NULL) != -1);
			exit(EXIT_FAILURE);
		} else if (readcfg_pid == -1) {
			launchd_assumes(close(spair[0]) == 0);
			launchd_assumes(close(spair[1]) == 0);
			syslog(LOG_ERR, "fork(): %m");
			readcfg_pid = 0;
		} else {
			launchd_assumes(close(spair[1]) == 0);
			ipc_open(_fd(spair[0]), NULL);
			launchd_assumes(kevent_mod(readcfg_pid, 
					 EVFILT_PROC, 
					 EV_ADD, NOTE_EXIT, 0, 
					 &kqreadcfg_callback) != -1);
		}
	}
}

struct jobcb *conceive_firstborn(char *argv[], const char *session_user)
{
	launch_data_t d = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_t args = launch_data_alloc(LAUNCH_DATA_ARRAY);
	launch_data_t l = launch_data_new_string("launchd.firstborn");
	struct jobcb *j;
	size_t i;

	if (argv[0] == NULL && session_user) {
		launch_data_t ed = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		struct passwd *pw = getpwnam(session_user);
		const char *sh = (pw && pw->pw_shell) ? pw->pw_shell : _PATH_BSHELL;
		const char *wd = (pw && pw->pw_dir) ? pw->pw_dir : NULL;
		const char *un = (pw && pw->pw_name) ? pw->pw_name : NULL;
		const char *tty, *ttyn = ttyname(STDIN_FILENO);
		char *p, arg0[PATH_MAX] = "-";

		strcpy(arg0 + 1, (p = strrchr(sh, '/')) ?  p + 1 : sh);

		if (wd) {
			launch_data_dict_insert(d, launch_data_new_string(wd), LAUNCH_JOBKEY_WORKINGDIRECTORY);
			launch_data_dict_insert(ed, launch_data_new_string(wd), "HOME");
		}
		if (sh) {
			launch_data_dict_insert(ed, launch_data_new_string(sh), "SHELL");
		}
		if (un) {
			launch_data_dict_insert(ed, launch_data_new_string(un), "USER");
			launch_data_dict_insert(ed, launch_data_new_string(un), "LOGNAME");
		}
		if (ttyn && NULL == getenv("TERM")) {
			struct ttyent *t;
			const char *term;

			if ((tty = strrchr(ttyn, '/')))
				tty++;
			else
				tty = ttyn;

			if ((t = getttynam(tty)))
				term = t->ty_type;
			else
				term = "su"; /* I don't know why login(8) defaulted to this value... */

			launch_data_dict_insert(ed, launch_data_new_string(term), "TERM");
		}

		launch_data_dict_insert(d, launch_data_new_string(sh), LAUNCH_JOBKEY_PROGRAM);
		launch_data_dict_insert(d, ed, LAUNCH_JOBKEY_ENVIRONMENTVARIABLES);
		launch_data_array_set_index(args, launch_data_new_string(arg0), 0);
	} else {
		for (i = 0; *argv; argv++, i++)
			launch_data_array_set_index(args, launch_data_new_string(*argv), i);
	}

	launch_data_dict_insert(d, args, LAUNCH_JOBKEY_PROGRAMARGUMENTS);
	launch_data_dict_insert(d, l, LAUNCH_JOBKEY_LABEL);
	launch_data_dict_insert(d, launch_data_new_bool(true), LAUNCH_JOBKEY_FIRSTBORN);

	j = job_import(d);

	launch_data_free(d);

	return j;
}

static void loopback_setup(void)
{
	struct ifaliasreq ifra;
	struct in6_aliasreq ifra6;
	struct ifreq ifr;
	int s, s6;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	launchd_assumes((s = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	launchd_assumes((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) != -1);

	if (launchd_assumes(ioctl(s, SIOCGIFFLAGS, &ifr) != -1)) {
		ifr.ifr_flags |= IFF_UP;
		launchd_assumes(ioctl(s, SIOCSIFFLAGS, &ifr) != -1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if (launchd_assumes(ioctl(s6, SIOCGIFFLAGS, &ifr) != -1)) {
		ifr.ifr_flags |= IFF_UP;
		launchd_assumes(ioctl(s6, SIOCSIFFLAGS, &ifr) != -1);
	}

	memset(&ifra, 0, sizeof(ifra));
	strcpy(ifra.ifra_name, "lo0");

	((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr = htonl(IN_CLASSA_NET);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_len = sizeof(struct sockaddr_in);

	launchd_assumes(ioctl(s, SIOCAIFADDR, &ifra) != -1);

	memset(&ifra6, 0, sizeof(ifra6));
	strcpy(ifra6.ifra_name, "lo0");

	ifra6.ifra_addr.sin6_family = AF_INET6;
	ifra6.ifra_addr.sin6_addr = in6addr_loopback;
	ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_prefixmask.sin6_family = AF_INET6;
	memset(&ifra6.ifra_prefixmask.sin6_addr, 0xff, sizeof(struct in6_addr));
	ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	launchd_assumes(ioctl(s6, SIOCAIFADDR_IN6, &ifra6) != -1);
 
	launchd_assumes(close(s) == 0);
	launchd_assumes(close(s6) == 0);
}

/* this is a workaround for an openfirmware bug */
void
workaround3048875(int argc, char *argv[])
{
#ifdef _BUILD_DARWIN_
	int i;
	char **ap, *newargv[100], *p = argv[1];

	if (argc == 1 || argc > 2)
		return;

	newargv[0] = argv[0];
	for (ap = newargv + 1, i = 1; ap < &newargv[100]; ap++, i++) {
		if ((*ap = strsep(&p, " \t")) == NULL)
			break;
		if (**ap == '\0') {
			*ap = NULL;
			break;
		}
	}

	if (argc == i)
		return;

	execv(newargv[0], newargv);
#endif
}

#ifdef _BUILD_DARWIN_
void
launchd_SessionCreate(void)
{
	OSStatus (*sescr)(SessionCreationFlags flags,
			  SessionAttributeBits attributes);
	void *seclib;

	if (launchd_assumes((seclib = dlopen(SECURITY_LIB,
					     RTLD_LAZY)) != NULL)) {
		if (launchd_assumes((sescr = dlsym(seclib, "SessionCreate")) != NULL))
			launchd_assumes(sescr(0, 0) == noErr);
		launchd_assumes(dlclose(seclib) != -1);
	}
}
#endif

void
async_callback(void)
{
	struct timespec timeout = { 0, 0 };
	struct kevent kev;

	if (launchd_assumes(kevent(asynckq, NULL, 0, &kev, 1,
				   &timeout) == 1))
		(*((kq_callback *)kev.udata))(kev.udata, &kev);
}

void
testfd_or_openfd(int fd, const char *path, int flags)
{
	int tmpfd;

	if (-1 != (tmpfd = dup(fd))) {
		launchd_assumes(close(tmpfd) == 0);
	} else {
		if (-1 == (tmpfd = open(path, flags))) {
			syslog(LOG_ERR, "open(\"%s\", ...): %m", path);
		} else if (tmpfd != fd) {
			launchd_assumes(dup2(tmpfd, fd) != -1);
			launchd_assumes(close(tmpfd) == 0);
		}
	}
}

launch_data_t                   
launchd_setstdio(int d, launch_data_t o)
{
	launch_data_t resp = launch_data_new_errno(0);

	if (launch_data_get_type(o) == LAUNCH_DATA_STRING) {
		char **where = &pending_stderr;

		if (d == STDOUT_FILENO)
			where = &pending_stdout;
		if (*where)
			free(*where);
		*where = strdup(launch_data_get_string(o));
	} else if (launch_data_get_type(o) == LAUNCH_DATA_FD) {
		launchd_assumes(dup2(launch_data_get_fd(o), d) != -1);
	} else {
		launch_data_set_errno(resp, EINVAL);
	}

	return resp;
}

void
batch_job_enable(bool e, struct conncb *c)
{
	if (e && c->disabled_batch) {
		batch_disabler_count--;
		c->disabled_batch = 0;
		if (batch_disabler_count == 0)
			kevent_mod(asynckq, EVFILT_READ, EV_ENABLE, 0, 0,
				   &kqasync_callback);
	} else if (!e && !c->disabled_batch) {
		if (batch_disabler_count == 0)
			kevent_mod(asynckq, EVFILT_READ, EV_DISABLE, 0,
				   0, &kqasync_callback);
		batch_disabler_count++;
		c->disabled_batch = 1;
	}
}       

#ifndef _BUILD_DARWIN_
/** 
 * launch_fork() does essentially what the 
 * fork_with_bootstrap_port() function in MacOS' launchd
 * source code, sans the mach-based calls
 */
pid_t launchd_fork() {
        static pthread_mutex_t forklock = PTHREAD_MUTEX_INITIALIZER;
        pid_t r;
        size_t i;

        pthread_mutex_lock(&forklock);

        sigprocmask(SIG_BLOCK, &blocked_signals, NULL);

        r = fork();
        
        if (r <= 0) {
                for (i = 0; i <= NSIG; i++) {
                        if (sigismember(&blocked_signals, i))
                                signal(i, SIG_DFL);
                }
        }               
                        
        sigprocmask(SIG_UNBLOCK, &blocked_signals, NULL);
                
        pthread_mutex_unlock(&forklock);
                        
        return r;
}              
#endif
