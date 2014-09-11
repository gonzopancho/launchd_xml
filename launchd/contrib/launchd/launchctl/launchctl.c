 /*
 * Copyright 2006, 2007 Infoweapons Corporation
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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>

#if !defined(_BUILD_DARWIN_) && !defined(_XML_CONF_) && !defined(_SQL_CONF_)
/* include libutil.h for basic property parsing on FreeBSD */
#include <libutil.h>
#endif

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <syslog.h>
#include <readline/readline.h>
#include <readline/history.h>

#ifdef _SQL_CONF_
#include <solidb.h> /* equivalent to sqlited.h */
#endif

#include <libutil.h>

/*
 * This includes the Zeroconf headers, so launchctl(1) can start the 
 * 'advertising' end of Zeroconf for daemons (ssh, xinetd, etc)
 */
 
#include "launch.h"
#include "launchd.h"
#include "launch_priv.h"

#ifdef _SQL_CONF_
#include "launch_sb_if.h"
#endif

#include "launch_log.h"
#include "launch_util.h"

#define LAUNCH_SECDIR "/tmp/launch-XXXXXX"
/* launchd(8) specific definitions */
#define LAUNCH_PROPERTY_LABEL   "Label"
#define LAUNCH_PROPERTY_PATH    "Path"
#define LAUNCH_PROPERTY_FLAGS   "Flags"
#define LAUNCH_PROPERTY_LENGTH  128

#ifdef _SQL_CONF_
static void load_sbconf(void);
static void set_configdefaults(bool pid1);
#endif

static bool launch_data_array_append(launch_data_t a, launch_data_t o);
static void distill_config_file(launch_data_t);
static void sock_dict_cb(launch_data_t what, const char *key,
			 void *context);
static void sock_dict_edit_entry(launch_data_t tmp, const char *key, 
				 launch_data_t fdarray, 
				 launch_data_t thejob);
static void readpath(const char *, launch_data_t, launch_data_t, 
		     bool editondisk, bool load, bool forceload);
static int demux_cmd(int argc, char *const argv[]);
static void submit_job_pass(launch_data_t jobs);
static void do_mgroup_join(int fd, int family, int socktype,
			   int protocol, const char *mgroup);

/* 
 * Mac OS X/Darwin related functions (for backwards compat.)
 */
#ifdef _BUILD_DARWIN_
static launch_data_t CF2launch_data(const void *);
static launch_data_t read_plist_file(const char *file, bool editondisk, 
				     bool load);
static CFPropertyListRef CreateMyPropertyListFromFile(const char *);
static void WriteMyPropertyListToFile(CFPropertyListRef, const char *);
static launch_data_t do_rendezvous_magic(const struct addrinfo *res, 
					 const char *serv);
#else /* ! _BUILD_DARWIN_ */
/* FreeBSD related functions (for forwards compat? :P */
static launch_data_t read_conf_file(const char *);
#if !defined(_XML_CONF_) && !defined(_SQL_CONF_)
static launch_data_t Conf2launch_data(void *);
#endif /* !_XML_CONF_ && !_SQL_CONF_ */
#endif /* _BUILD_DARWIN_ */

static int load_and_unload_cmd(int argc, char *const argv[]);
static int start_stop_remove_cmd(int argc, char *const argv[]);

#if !defined(_BUILD_DARWIN_) && !defined(_XML_CONF_) && !defined(_SQL_CONF_)
static int quickstart_cmd(int argc, char *const argv[]);
#endif /* !_BUILD_DARWIN_ && !_XML_CONF_ && !_SQL_CONF_ */

static int submit_cmd(int argc, char *const argv[]);
static int list_cmd(int argc, char *const argv[]);
static int setenv_cmd(int argc, char *const argv[]);
static int unsetenv_cmd(int argc, char *const argv[]);
static int getenv_and_export_cmd(int argc, char *const argv[]);
static int limit_cmd(int argc, char *const argv[]);
static int stdio_cmd(int argc, char *const argv[]);
static int fyi_cmd(int argc, char *const argv[]);
static int logupdate_cmd(int argc, char *const argv[]);
static int umask_cmd(int argc, char *const argv[]);
static int getrusage_cmd(int argc, char *const argv[]);
static int help_cmd(int argc, char *const argv[]);
static int exit_cmd(int argc, char *const argv[]);

#ifdef _SQL_CONF_
static int setsbacct_cmd(int argc, char *const argv[]);
static void setsbacct_defaults(void);
#endif

static const struct {
	const char *name;
	int (*func)(int argc, char *const argv[]);
	const char *desc;
} cmds[] = {
	{ "load",	load_and_unload_cmd,	"Load configuration files and/or directories" },
	{ "unload",	load_and_unload_cmd,	"Unload configuration files and/or directories" },
//	{ "reload",	reload_cmd,		"Reload configuration files and/or directories" },
	{ "start",      start_stop_remove_cmd,  "Start specified job" },
	//{ "quickstart", quickstart_cmd,		"Load and start specified"},
	{ "stop",       start_stop_remove_cmd,  "Stop specified job" },
	{ "submit",     submit_cmd,             "Submit a job from the command line" },
	//{ "remove",     start_stop_remove_cmd,  "Remove/stop specified job" },
	{ "list",	list_cmd,		"List jobs and information about jobs" },
	{ "setenv",	setenv_cmd,		"Set an environmental variable in launchd" },
	{ "unsetenv",	unsetenv_cmd,		"Unset an environmental variable in launchd" },
	{ "getenv",	getenv_and_export_cmd,	"Get an environmental variable from launchd" },
	{ "export",	getenv_and_export_cmd,	"Export shell settings from launchd" },
	{ "limit",	limit_cmd,		"View and adjust launchd resource limits" },
	{ "stdout",	stdio_cmd,		"Redirect launchd's standard out to the given path" },
	{ "stderr",	stdio_cmd,		"Redirect launchd's standard error to the given path" },
	{ "shutdown",	fyi_cmd,		"Prepare for system shutdown" },
	{ "singleuser",	fyi_cmd,		"Switch to single-user mode" },
	{ "reloadttys",	fyi_cmd,		"Reload /etc/ttys" },
	{ "getrusage",	getrusage_cmd,		"Get resource usage statistics from launchd" },
	{ "log",	logupdate_cmd,		"Adjust the logging level or mask of launchd" },
	{ "umask",	umask_cmd,		"Change launchd's umask" },
	{ "help",	help_cmd,		"This help output" },
	{"exit", 	exit_cmd, 		"Exit launchctl" },
#ifdef _SQL_CONF_
	{"setsbacct",   setsbacct_cmd,          "Sets the user/password for solidbase"},
#endif
};

static bool istty = false;

#ifdef _SQL_CONF_
/* solidbase config data */
static char *sbuser = NULL;
static char *sbpass = NULL;
static char *sbhost = NULL;
static int  sbport = 0;
static char *sbdb  = NULL;
static char *sbconf = NULL;
#endif

int main(int argc, char *const argv[])
{
	char *l;
	int retval;

	if (!is_log_inited())
		log_init();

	if (argc > 1) {
		retval = demux_cmd(argc - 1, argv + 1);
		log_close();
		exit(retval);
	}

	istty = isatty(STDIN_FILENO);

	/* jmp - if library is missing, should it even compile?? */
	if (NULL == readline) {
		fprintf(stderr, "missing library: readline\n");
		log_close();
		exit(EXIT_FAILURE);
	}

	/* insecure - this is vulnerable to buffer overflow 
	 *  e.g. 101+ space-separated strings
	 */
	while ((l = readline(istty ? "launchd% " : NULL))) {
		char *inputstring = l, *argv2[100], **ap = argv2;
		int i = 0;

		while ((*ap = strsep(&inputstring, " \t"))) {
			if (**ap != '\0') {
				ap++;
				i++;
			}
		}

		if (i > 0)
			demux_cmd(i, argv2);
		free(l);
	}

	if (istty)
		fputc('\n', stdout);

	log_close();
	exit(EXIT_SUCCESS);
}

static int demux_cmd(int argc, char *const argv[])
{
	size_t i;

	optind = 1;
	optreset = 1;
	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++) {
		if (!strcmp(cmds[i].name, argv[0]))
			return cmds[i].func(argc, argv);
	}
	syslog(LOG_INFO, "unknown subcommand: %s", argv[0]);
	fprintf(stderr, "%s: unknown subcommand \"%s\"\n", getprogname(),
		argv[0]);
	return 1;
}

static int unsetenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, msg;

	if (argc != 2) {
		fprintf(stderr, "%s usage: unsetenv <key>\n", 
			getprogname());
		return 1;
	}
	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_new_string(argv[1]);
	launch_data_dict_insert(msg, tmp, 
				LAUNCH_KEY_UNSETUSERENVIRONMENT);
	resp = launch_msg(msg);
	launch_data_free(msg);
	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"%s\"): %s\n", 
			LAUNCH_KEY_UNSETUSERENVIRONMENT, 
			strerror(errno));
	}

	return 0;
}

static int setenv_cmd(int argc, char *const argv[])
{
	launch_data_t resp, tmp, tmpv, msg;

	if (argc != 3) {
		fprintf(stderr, "%s usage: setenv <key> <value>\n", 
			getprogname());
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	tmpv = launch_data_new_string(argv[2]);
	launch_data_dict_insert(tmp, tmpv, argv[1]);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETUSERENVIRONMENT);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"%s\"): %s\n",
			LAUNCH_KEY_SETUSERENVIRONMENT, strerror(errno));
	}

	return 0;
}

static void print_launchd_env(launch_data_t obj, const char *key, 
			      void *context)
{
	bool *is_csh = context;

	/* XXX escape the double quotes */
	if (*is_csh)
		fprintf(stdout, "setenv %s \"%s\";\n", key, 
			launch_data_get_string(obj));
	else
		fprintf(stdout, "%s=\"%s\"; export %s;\n", key, 
			launch_data_get_string(obj), key);
}

static void print_key_value(launch_data_t obj, const char *key, 
			    void *context)
{
	const char *k = context;

	if (!strcmp(key, k))
		fprintf(stdout, "%s\n", launch_data_get_string(obj));
}

static int getenv_and_export_cmd(int argc, char *const argv[] __attribute__((unused)))
{
	launch_data_t resp, msg;
	bool is_csh = false;
	char *k;
	
	if (!strcmp(argv[0], "export")) {
		char *s = getenv("SHELL");
		if (s)
			is_csh = strstr(s, "csh") ? true : false;
	} else if (argc != 2) {
		fprintf(stderr, "%s usage: getenv <key>\n", 
			getprogname());
		return 1;
	}

	k = argv[1];

	msg = launch_data_new_string(LAUNCH_KEY_GETUSERENVIRONMENT);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp) {
		if (!strcmp(argv[0], "export"))
			launch_data_dict_iterate(resp, print_launchd_env,
						 &is_csh);
		else
			launch_data_dict_iterate(resp, 
						 print_key_value, k);
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(\"" LAUNCH_KEY_GETUSERENVIRONMENT "\"): %s\n", strerror(errno));
	}
	return 0;
}

static void unloadjob(launch_data_t job)
{
	launch_data_t resp, tmp, tmps, msg;
	int e;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_alloc(LAUNCH_DATA_STRING);
	tmps = launch_data_dict_lookup(job, LAUNCH_JOBKEY_LABEL);

	if (!tmps) {
		fprintf(stderr, "%s: Error: Missing Key: %s\n", 
			getprogname(), LAUNCH_JOBKEY_LABEL);
		return;
	}

	launch_data_set_string(tmp, launch_data_get_string(tmps));
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_REMOVEJOB);
	resp = launch_msg(msg);
	launch_data_free(msg);
	if (!resp) {
		fprintf(stderr, "%s: Error: launch_msg(): %s\n", 
			getprogname(), strerror(errno));
		return;
	}
	if (LAUNCH_DATA_ERRNO == launch_data_get_type(resp)) {
		if ((e = launch_data_get_errno(resp)))
			fprintf(stderr, "%s\n", strerror(e));
	}
	launch_data_free(resp);
}

#ifndef _BUILD_DARWIN_

#ifdef _XML_CONF_
/*
 * Reads the configuration file.
 * Note: Calling function must check for NULL in return value.
 */
static launch_data_t read_conf_file(const char *file)
{
	launch_data_t r; 
	int fd;
	
	if ((fd = open(file, O_RDONLY)) == -1) {
		return NULL;
	}
	r = plist_to_launchdata(fd);	
	close(fd);
	return r;
}
#elif defined(_SQL_CONF_)
/*
 * Reads the configuration file.
 * Note: Calling function must check for NULL in return value.
 */
static launch_data_t read_conf_file(const char *file)
{
	sqlited *db;
	sqlited_result *result;
	int tbl_retval;
	char ***table;
	sqlited_int64 rows;
	unsigned int fields;
	char *querystr;
	launch_data_t retdata = NULL;

	/* if sbuser is set, then this is not from launchd invocation */
	if (sbuser == NULL) {
		load_sbconf();
	}
		
	db = connect_sb(sbuser, sbpass, sbhost, sbport, sbdb);
	if (db == NULL) {
		syslog(LOG_ERR, "connect to SQLITEDBMS failed");
		DEBUG_PRINT("connect to SQLITEDBMS failed");
		return (NULL);
	} else {
		/* successful connection */
	}

	if ((asprintf(&querystr, "SELECT * FROM %s", file)) == -1) {
		syslog(LOG_ERR, "memory allocation failed");
		return (NULL);
	} else {
		/* allocation of query string successful */
	}

	tbl_retval = get_table_data(db, querystr, &result, &table, &rows,
				    &fields);
	if (tbl_retval == SQLITED_OK) {
		retdata = cnv_sdbms_to_launch(table, rows);
#ifdef DEBUG_MODE
		launch_data_dump(retdata);
#endif
	}

	free(querystr);
	sqlited_close(db);
	return (retdata);
}

/* 
 * Load the launchd-solidbase configuration file 
 */
static void
load_sbconf(void)
{
	int fd;
	char *portstr;
	properties head_prop;
	char *sbconfig = PID1LAUNCHDSB_CONF; 
	const char *home = getenv("HOME");
	const char *socket_env = getenv(LAUNCHD_SOCKET_ENV);

	if (socket_env && home) {
		asprintf(&sbconfig, "%s/%s", home, LAUNCHDSB_CONF);
		set_configdefaults(false);
	} else {
		set_configdefaults(true);
	}

	DEBUG_PRINT("config file: ");
	DEBUG_PRINT(sbconfig);

        if ((fd = open(sbconfig, O_RDONLY)) == -1) {
                /* stick to default settings */
                fprintf(stderr, "using defaults for solidbase access\n");
                syslog(LOG_INFO, "missing config file : %s", sbconfig);
                return;
        }

	head_prop = properties_read(fd);

        /* if not set in config file, the default is used */
        set_cfvalue(head_prop, SBUSER, &sbuser);
	DEBUG_PRINT(sbuser);
        set_cfvalue(head_prop, SBHOST, &sbhost);
	DEBUG_PRINT(sbhost);
        set_cfvalue(head_prop, SBDB, &sbdb);
	DEBUG_PRINT(sbdb);
        set_cfvalue(head_prop, SBCONF, &sbconf);
	DEBUG_PRINT(sbconf);

        set_cfvalue(head_prop, SBPORT, &portstr);
	sbport = (int)strtol(portstr, (char **)NULL, 10);

        /* special case for password
         *   - if not in config file, prompt from user
         *   * more like a security issue because it is stored in cleartext
         */
        if ((set_cfvalue(head_prop, SBPASS, &sbpass)) == 0) {
                sbpass = input_sbpass(sbuser);
        }

	properties_free(head_prop);
	close(fd);
        return;
} /* load_sbconf */

/*
 * Set default values for solidbase access.
 */
static void
set_configdefaults(bool pid1)
{
        if (pid1) {
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

#else /* !_XML_CONF_ */
/*
 * Need to clean for non-standard coding convention. (jmp)
 */
static launch_data_t read_conf_file(const char *file) 
{
	/* fill this with an array of launch_data_t structs */
	launch_data_t r; 
	properties conf_props; // libutil.h and -lutil are required for this..
	int fd;
	
	fd = open(file, O_RDONLY);

	if (fd == -1)
		return NULL; /* calling function must check for a NULL pointer */
		
	conf_props = properties_read(fd); /* read in config data */

	r = Conf2launch_data(conf_props);	
		
	close(fd);

	return r;
}

/* This function should mimic CF2launch_data in how it creates
 * a launch_data_t data structure from the contents of a .plist file
 */
static launch_data_t Conf2launch_data(void *prop) 
{
	bool fflag = true;
	char *label, *path, *flags;

	launch_data_t job = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	
	label = malloc(sizeof(char) * LAUNCH_PROPERTY_LENGTH);
	path = malloc(sizeof(char) * LAUNCH_PROPERTY_LENGTH);
	flags = malloc(sizeof(char) * LAUNCH_PROPERTY_LENGTH);

	// retrieve appropriate data and assign to correct vars
	if ((label = property_find((properties)(prop), 
				   LAUNCH_PROPERTY_LABEL)) == NULL) {
		fprintf(stderr, "Could not locate a 'Label' for this launcher\n");
		goto out_bad;
	}

	if ((path = property_find((properties)(prop), 
				  LAUNCH_PROPERTY_PATH)) == NULL) {
		fprintf(stderr, "Could not locate a 'Path' for this launcher\n");
		goto out_bad;
	}

	if ((flags = property_find((properties)(prop), 
				   LAUNCH_PROPERTY_FLAGS)) == NULL) {
		fflag = false;
		free(flags);
	}

		
	/* begin to insert pertinent data into the job data structure */
	launch_data_dict_insert(job, launch_data_new_string(label), 
				LAUNCH_JOBKEY_LABEL);
	launch_data_dict_insert(job, launch_data_new_string(path), 
				LAUNCH_JOBKEY_PROGRAM);
	if (flags != NULL)
		launch_data_dict_insert(job, 
					launch_data_new_string(flags), 
					LAUNCH_JOBKEY_PROGRAMARGUMENTS);

	launch_data_dump(job);
	
	return job;

out_bad:
	free(label);
	free(path);
	if (flags != NULL)
		free(flags);
	
	exit(EXIT_FAILURE);
}
#endif /* _XML_CONF_ */
#else /* _BUILD_DARWIN_ */
static launch_data_t read_plist_file(const char *file, bool editondisk, 
				     bool load)
{
	CFPropertyListRef plist = CreateMyPropertyListFromFile(file);
	launch_data_t r = NULL;

	if (NULL == plist) {
		fprintf(stderr, "%s: no plist was returned for: %s\n", 
			getprogname(), file);
		return NULL;
	}
	if (editondisk) {
		if (load) {
			CFDictionaryRemoveValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED));
		} else {
			CFDictionarySetValue((CFMutableDictionaryRef)plist, CFSTR(LAUNCH_JOBKEY_DISABLED), kCFBooleanTrue);
		}
		WriteMyPropertyListToFile(plist, file);
	}
	r = CF2launch_data(plist);
	CFRelease(plist);
	return r;
}
#endif /* _BUILD_DARWIN_ */

static void delay_to_second_pass2(launch_data_t o, const char *key, 
				  void *context)
{
	bool *res = context;
	size_t i;

	if (key && 0 == strcmp(key, LAUNCH_JOBSOCKETKEY_BONJOUR)) {
		*res = true;
		return;
	}

	switch (launch_data_get_type(o)) {
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(o, delay_to_second_pass2, 
					 context);
		break;
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < launch_data_array_get_count(o); i++)
			delay_to_second_pass2(
				launch_data_array_get_index(o, i), 
				NULL, context);
		break;
	default:
		break;
	}
}

static bool delay_to_second_pass(launch_data_t o)
{
	bool res = false;
	launch_data_t socks = 
		launch_data_dict_lookup(o, LAUNCH_JOBKEY_SOCKETS);

	if (NULL == socks)
		return false;

	delay_to_second_pass2(socks, NULL, &res);

	return res;
}

static void readfile(const char *what, launch_data_t pass1, 
		     launch_data_t pass2, bool editondisk, bool load, 
		     bool forceload)
{
	char ourhostname[1024];
	launch_data_t tmpd, thejob, tmpa;
	bool job_disabled = false;
	size_t i, c;

	gethostname(ourhostname, sizeof(ourhostname));
#ifndef _BUILD_DARWIN_
	if ((thejob = read_conf_file(what)) == NULL) {
		fprintf(stderr, 
			"%s: no config file was returned for: %s\n", 
			getprogname(), what);
		log_err("no config file found");
		return;
	}
#else /* _BUILD_DARWIN_ */
	if (NULL == (thejob = read_plist_file(what, editondisk, load))) {
		fprintf(stderr, "%s: no plist was returned for: %s\n", 
			getprogname(), what);                    
                return;
        }
#endif /* _BUILD_DARWIN_ */

	if (NULL == launch_data_dict_lookup(thejob, 
					    LAUNCH_JOBKEY_LABEL)) {
		fprintf(stderr, "%s: missing the Label key: %s\n", 
			getprogname(), what);
		goto out_bad;
	}

	if (NULL != (tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADFROMHOSTS))) {
		c = launch_data_array_get_count(tmpa);

		for (i = 0; i < c; i++) {
			launch_data_t oai = launch_data_array_get_index(tmpa, i);
			if (!strcasecmp(ourhostname, 
					launch_data_get_string(oai)))
				goto out_bad;
		}
	}

	if (NULL != (tmpa = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LIMITLOADTOHOSTS))) {
		c = launch_data_array_get_count(tmpa);

		for (i = 0; i < c; i++) {
			launch_data_t oai = launch_data_array_get_index(tmpa, i);
			if (!strcasecmp(ourhostname, 
					launch_data_get_string(oai)))
				break;
		}

		if (i == c)
			goto out_bad;
	}

	if ((tmpd = launch_data_dict_lookup(thejob, 
					    LAUNCH_JOBKEY_DISABLED)))
		job_disabled = launch_data_get_bool(tmpd);

	if (forceload)
		job_disabled = false;

	if (job_disabled && load)
		goto out_bad;

	if (delay_to_second_pass(thejob))
		launch_data_array_append(pass2, thejob);
	else
		launch_data_array_append(pass1, thejob);

	return;
out_bad:
	launch_data_free(thejob);
}

static void readpath(const char *what, launch_data_t pass1, 
		     launch_data_t pass2, bool editondisk, bool load, 
		     bool forceload)
{
#ifndef _SQL_CONF_
	char buf[MAXPATHLEN];
	struct stat sb;
	struct dirent *de;
	DIR *d;

	if (stat(what, &sb) == -1)
		return;

	if (S_ISREG(sb.st_mode) && !(sb.st_mode & S_IWOTH)) {
		readfile(what, pass1, pass2, editondisk, load, 
			 forceload);
	} else {
		if ((d = opendir(what)) == NULL) {
			fprintf(stderr, "%s: opendir() failed to open the directory\n", getprogname());
			return;
		}

		while ((de = readdir(d))) {
			if ((de->d_name[0] == '.'))
				continue;
			snprintf(buf, sizeof(buf), "%s/%s", what, 
				 de->d_name);

			readfile(buf, pass1, pass2, editondisk, load, 
				 forceload);
		}
		closedir(d);
	}
#else /* _SQL_CONF_ */
	/* not really reading from file but from sqlitedb */
	readfile(what, pass1, pass2, editondisk, load, forceload);
#endif /* !_SQL_CONF_ */
}

struct distill_context {
	launch_data_t base;
	launch_data_t newsockdict;
};

static void distill_config_file(launch_data_t id_plist)
{
	struct distill_context dc = { id_plist, NULL };
	launch_data_t tmp, sipco = launch_data_dict_lookup(dc.base, LAUNCH_JOBKEY_SERVICEIPC);
	bool sipc = sipco ? launch_data_get_bool(sipco) : false;

	if ((tmp = launch_data_dict_lookup(dc.base, 
					   LAUNCH_JOBKEY_SOCKETS))) {
		if (!sipc && !launch_data_dict_lookup(dc.base, LAUNCH_JOBKEY_INETDCOMPATIBILITY)) {
			fprintf(stderr, "%s specified without %s == true or %s will not work as expected.\n",
					LAUNCH_JOBKEY_SOCKETS,
					LAUNCH_JOBKEY_SERVICEIPC,
					LAUNCH_JOBKEY_INETDCOMPATIBILITY);
		}
		dc.newsockdict = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_iterate(tmp, sock_dict_cb, &dc);
		launch_data_dict_insert(dc.base, dc.newsockdict, 
					LAUNCH_JOBKEY_SOCKETS);
	}
}

static void sock_dict_cb(launch_data_t what, const char *key, 
			 void *context)
{
	struct distill_context *dc = context;
	launch_data_t fdarray = launch_data_alloc(LAUNCH_DATA_ARRAY);

	launch_data_dict_insert(dc->newsockdict, fdarray, key);

	if (launch_data_get_type(what) == LAUNCH_DATA_DICTIONARY) {
		sock_dict_edit_entry(what, key, fdarray, dc->base);
	} else if (launch_data_get_type(what) == LAUNCH_DATA_ARRAY) {
		launch_data_t tmp;
		size_t i;

		for (i = 0; i < launch_data_array_get_count(what); i++) {
			tmp = launch_data_array_get_index(what, i);
			sock_dict_edit_entry(tmp, key, fdarray, 
					     dc->base);
		}
	}
}

static void sock_dict_edit_entry(launch_data_t tmp, const char *key, 
				 launch_data_t fdarray, 
				 launch_data_t thejob)
{
	launch_data_t a, val;
	int sfd, st = SOCK_STREAM;
	bool passive = true;

	if ((val = launch_data_dict_lookup(tmp, 
					   LAUNCH_JOBSOCKETKEY_TYPE))) {
		if (!strcasecmp(launch_data_get_string(val), "stream")) {
			st = SOCK_STREAM;
		} else if (!strcasecmp(launch_data_get_string(val), 
				       "dgram")) {
			st = SOCK_DGRAM;
		} else if (!strcasecmp(launch_data_get_string(val), 
				       "seqpacket")) {
			st = SOCK_SEQPACKET;
		}
	}

	if ((val = launch_data_dict_lookup(tmp, 
					   LAUNCH_JOBSOCKETKEY_PASSIVE)))
		passive = launch_data_get_bool(val);

	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SECUREWITHKEY))) {
		char secdir[] = LAUNCH_SECDIR, buf[1024];
		launch_data_t uenv = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES);

		if (NULL == uenv) {
			uenv = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
			launch_data_dict_insert(thejob, uenv, LAUNCH_JOBKEY_USERENVIRONMENTVARIABLES);
		}

		mkdtemp(secdir);

		sprintf(buf, "%s/%s", secdir, key);

		a = launch_data_new_string(buf);
		launch_data_dict_insert(tmp, a, LAUNCH_JOBSOCKETKEY_PATHNAME);
		a = launch_data_new_string(buf);
		launch_data_dict_insert(uenv, a, launch_data_get_string(val));
	}
		
	if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PATHNAME))) {
		struct sockaddr_un sun;
		mode_t sun_mode = 0;
		mode_t oldmask;
		bool setm = false;

		memset(&sun, 0, sizeof(sun));

		sun.sun_family = AF_UNIX;

		strncpy(sun.sun_path, launch_data_get_string(val), 
			sizeof(sun.sun_path));
	
		if ((sfd = _fd(socket(AF_UNIX, st, 0))) == -1)
			return;

		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PATHMODE))) {
			sun_mode = (mode_t)launch_data_get_integer(val);
			setm = true;
		}

		if (passive) {                  
			if (unlink(sun.sun_path) == -1 
			    && errno != ENOENT) {
				close(sfd);     
				return;
			}
			oldmask = umask(S_IRWXG|S_IRWXO);
			if (bind(sfd, (struct sockaddr *)&sun, 
				 sizeof(sun)) == -1) {
				close(sfd);
				umask(oldmask);
				return;
			}
			umask(oldmask);
			if (setm) {
				chmod(sun.sun_path, sun_mode);
			}
			if ((st == SOCK_STREAM || st == SOCK_SEQPACKET)
			    && listen(sfd, SOMAXCONN) == -1) {
				close(sfd);
				return;
			}
		} else if (connect(sfd, (struct sockaddr *)&sun, 
				   sizeof(sun)) == -1) {
			close(sfd);
			return;
		}

		val = launch_data_new_fd(sfd);
		launch_data_array_append(fdarray, val);
	} else {
		launch_data_t rnames = NULL;
		const char *node = NULL, *serv = NULL, *mgroup = NULL;
		char servnbuf[50];
		struct addrinfo hints, *res0, *res;
		int gerr, sock_opt = 1;
		bool rendezvous = false;

		memset(&hints, 0, sizeof(hints));

		hints.ai_socktype = st;
		if (passive)
			hints.ai_flags |= AI_PASSIVE;

		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_NODENAME)))
			node = launch_data_get_string(val);
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_MULTICASTGROUP)))
			mgroup = launch_data_get_string(val);
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_SERVICENAME))) {
			if (LAUNCH_DATA_INTEGER == launch_data_get_type(val)) {
				sprintf(servnbuf, "%lld", launch_data_get_integer(val));
				serv = servnbuf;
			} else {
				serv = launch_data_get_string(val);
			}
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_FAMILY))) {
			if (!strcasecmp("IPv4", launch_data_get_string(val)))
				hints.ai_family = AF_INET;
			else if (!strcasecmp("IPv6", launch_data_get_string(val)))
				hints.ai_family = AF_INET6;
		}
		if ((val = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_PROTOCOL))) {
			if (!strcasecmp("TCP", launch_data_get_string(val)))
				hints.ai_protocol = IPPROTO_TCP;
		}
		if ((rnames = launch_data_dict_lookup(tmp, LAUNCH_JOBSOCKETKEY_BONJOUR))) {
			rendezvous = true;
			if (LAUNCH_DATA_BOOL == launch_data_get_type(rnames)) {
				rendezvous = launch_data_get_bool(rnames);
				rnames = NULL;
			}
		}

		if ((gerr = getaddrinfo(node, serv, &hints, &res0)) != 0) {
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(gerr));
			return;
		}

		for (res = res0; res; res = res->ai_next) {
			launch_data_t rvs_fd = NULL;
			if ((sfd = _fd(socket(res->ai_family, res->ai_socktype, res->ai_protocol))) == -1) {
				fprintf(stderr, "socket(): %s\n", strerror(errno));
				return;
			}
			if (hints.ai_flags & AI_PASSIVE) {
				if (AF_INET6 == res->ai_family && -1 == setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY,
							(void *)&sock_opt, sizeof(sock_opt))) {
					fprintf(stderr, "setsockopt(IPV6_V6ONLY): %m");
					return;
				}
				if (mgroup) {
					if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, (void *)&sock_opt, sizeof(sock_opt)) == -1) {
						fprintf(stderr, "setsockopt(SO_REUSEPORT): %s\n", strerror(errno));
						return;
					}
				} else {
					if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt, sizeof(sock_opt)) == -1) {
						fprintf(stderr, "setsockopt(SO_REUSEADDR): %s\n", strerror(errno));
						return;
					}
				}
				if (bind(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					fprintf(stderr, "bind(): %s\n", strerror(errno));
					return;
				}

				if (mgroup) {
					do_mgroup_join(sfd, res->ai_family, res->ai_socktype, res->ai_protocol, mgroup);
				}
				if ((res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_SEQPACKET)
						&& listen(sfd, SOMAXCONN) == -1) {
					fprintf(stderr, "listen(): %s\n", strerror(errno));
					return;
				}
				if (rendezvous && (res->ai_family == AF_INET || res->ai_family == AF_INET6) &&
						(res->ai_socktype == SOCK_STREAM || res->ai_socktype == SOCK_DGRAM)) {
					launch_data_t rvs_fds = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_BONJOURFDS);
					if (NULL == rvs_fds) {
						rvs_fds = launch_data_alloc(LAUNCH_DATA_ARRAY);
						launch_data_dict_insert(thejob, rvs_fds, LAUNCH_JOBKEY_BONJOURFDS);
					}
					if (NULL == rnames) {
#ifdef _BUILD_DARWIN_
						rvs_fd = do_rendezvous_magic(res, serv);
#endif
						if (rvs_fd)
							launch_data_array_append(rvs_fds, rvs_fd);
					} else if (LAUNCH_DATA_STRING == launch_data_get_type(rnames)) {
#ifdef _BUILD_DARWIN_
						rvs_fd = do_rendezvous_magic(res, launch_data_get_string(rnames));
#endif
						if (rvs_fd)
							launch_data_array_append(rvs_fds, rvs_fd);
					} else if (LAUNCH_DATA_ARRAY == launch_data_get_type(rnames)) {
						size_t rn_i, rn_ac = launch_data_array_get_count(rnames);

						for (rn_i = 0; rn_i < rn_ac; rn_i++) {
#ifdef _BUILD_DARWIN_
							launch_data_t rn_tmp = launch_data_array_get_index(rnames, rn_i);
							rvs_fd = do_rendezvous_magic(res, launch_data_get_string(rn_tmp));
#endif
							if (rvs_fd)
								launch_data_array_append(rvs_fds, rvs_fd);
						}
					}
				}
			} else {
				if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
					fprintf(stderr, "connect(): %s\n", strerror(errno));
					return;
				}
			}
			val = launch_data_new_fd(sfd);
			if (rvs_fd) {
				/* <rdar://problem/3964648> Launchd should not register the same service more than once */
				/* <rdar://problem/3965154> Switch to DNSServiceRegisterAddrInfo() */
				rendezvous = false;
			}
			launch_data_array_append(fdarray, val);
		}
	}
}

static void do_mgroup_join(int fd, int family, int socktype, 
			   int protocol, const char *mgroup)
{
	struct addrinfo hints, *res0, *res;
	struct ip_mreq mreq;
	struct ipv6_mreq m6req;
	int gerr;

	memset(&hints, 0, sizeof(hints));

	hints.ai_flags |= AI_PASSIVE;
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;

	if ((gerr = getaddrinfo(mgroup, NULL, &hints, &res0)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", 
			gai_strerror(gerr));
		return;
	}

	for (res = res0; res; res = res->ai_next) {
		if (AF_INET == family) {
			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
			if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				       &mreq, sizeof(mreq)) == -1) {
				fprintf(stderr, "setsockopt(IP_ADD_MEMBERSHIP): %s\n", strerror(errno));
				continue;
			}
			break;
		} else if (AF_INET6 == family) {
			memset(&m6req, 0, sizeof(m6req));
			m6req.ipv6mr_multiaddr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
				       &m6req, sizeof(m6req)) == -1) {
				fprintf(stderr, "setsockopt(IPV6_JOIN_GROUP): %s\n", strerror(errno));
				continue;
			}
			break;
		} else {
			fprintf(stderr, "unknown family during multicast group bind!\n");
			break;
		}
	}

	freeaddrinfo(res0);
}

#ifdef _BUILD_DARWIN_
static launch_data_t do_rendezvous_magic(const struct addrinfo *res, 
					 const char *serv)
{
	struct stat sb;
	DNSServiceRef service;
	DNSServiceErrorType error;
	char rvs_buf[200];
	short port;
	static int statres = 1;

	if (1 == statres)
		statres = stat("/usr/sbin/mDNSResponder", &sb);

	if (-1 == statres)
		return NULL;

	sprintf(rvs_buf, "_%s._%s.", serv, 
		res->ai_socktype == SOCK_STREAM ? "tcp" : "udp");

	if (res->ai_family == AF_INET)
		port = ((struct sockaddr_in *)res->ai_addr)->sin_port;
	else
		port = ((struct sockaddr_in6 *)res->ai_addr)->sin6_port;

	error = DNSServiceRegister(&service, 0, 0, NULL, rvs_buf, NULL, 
				   NULL, port, 0, NULL, NULL, NULL);

	if (error == kDNSServiceErr_NoError)
		return launch_data_new_fd(DNSServiceRefSockFD(service));

	fprintf(stderr, "DNSServiceRegister(\"%s\"): %d\n", serv, error);
	return NULL;
}

static CFPropertyListRef CreateMyPropertyListFromFile(const char *posixfile)
{
	CFPropertyListRef propertyList;
	CFStringRef       errorString;
	CFDataRef         resourceData;
	SInt32            errorCode;
	CFURLRef          fileURL;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)posixfile, strlen(posixfile), false);
	if (!fileURL)
		fprintf(stderr, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed\n", getprogname(), posixfile);
	if (!CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode))
		fprintf(stderr, "%s: CFURLCreateDataAndPropertiesFromResource(%s) failed: %d\n", getprogname(), posixfile, (int)errorCode);
	propertyList = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, resourceData, kCFPropertyListMutableContainers, &errorString);
	if (!propertyList)
		fprintf(stderr, "%s: propertyList is NULL\n", getprogname());

	return propertyList;
}

static void WriteMyPropertyListToFile(CFPropertyListRef plist, const char *posixfile)
{
	CFDataRef	resourceData;
	CFURLRef	fileURL;
	SInt32		errorCode;

	fileURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)posixfile, strlen(posixfile), false);
	if (!fileURL)
		fprintf(stderr, "%s: CFURLCreateFromFileSystemRepresentation(%s) failed\n", getprogname(), posixfile);
	resourceData = CFPropertyListCreateXMLData(kCFAllocatorDefault, plist);
	if (resourceData == NULL)
		fprintf(stderr, "%s: CFPropertyListCreateXMLData(%s) failed", getprogname(), posixfile);
	if (!CFURLWriteDataAndPropertiesToResource(fileURL, resourceData, NULL, &errorCode))
		fprintf(stderr, "%s: CFURLWriteDataAndPropertiesToResource(%s) failed: %d\n", getprogname(), posixfile, (int)errorCode);
}

void myCFDictionaryApplyFunction(const void *key, const void *value, 
				 void *context)
{
	launch_data_t ik, iw, where = context;

	ik = CF2launch_data(key);
	iw = CF2launch_data(value);

	launch_data_dict_insert(where, iw, launch_data_get_string(ik));
	launch_data_free(ik);
}

static launch_data_t CF2launch_data(CFTypeRef cfr)
{
	launch_data_t r;
	CFTypeID cft = CFGetTypeID(cfr);

	if (cft == CFStringGetTypeID()) {
		char buf[4096];
		CFStringGetCString(cfr, buf, sizeof(buf), 
				   kCFStringEncodingUTF8);
		r = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(r, buf);
	} else if (cft == CFBooleanGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_BOOL);
		launch_data_set_bool(r, CFBooleanGetValue(cfr));
	} else if (cft == CFArrayGetTypeID()) {
		CFIndex i, ac = CFArrayGetCount(cfr);
		r = launch_data_alloc(LAUNCH_DATA_ARRAY);
		for (i = 0; i < ac; i++) {
			CFTypeRef v = CFArrayGetValueAtIndex(cfr, i);
			if (v) {
				launch_data_t iv = CF2launch_data(v);
				launch_data_array_set_index(r, iv, i);
			}
		}
	} else if (cft == CFDictionaryGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		CFDictionaryApplyFunction(cfr, 
					  myCFDictionaryApplyFunction, 
					  r);
	} else if (cft == CFDataGetTypeID()) {
		r = launch_data_alloc(LAUNCH_DATA_ARRAY);
		launch_data_set_opaque(r, CFDataGetBytePtr(cfr), 
				       CFDataGetLength(cfr));
	} else if (cft == CFNumberGetTypeID()) {
		long long n;
		double d;
		CFNumberType cfnt = CFNumberGetType(cfr);
		switch (cfnt) {
		case kCFNumberSInt8Type:
		case kCFNumberSInt16Type:
		case kCFNumberSInt32Type:
		case kCFNumberSInt64Type:
		case kCFNumberCharType:
		case kCFNumberShortType:
		case kCFNumberIntType:
		case kCFNumberLongType:
		case kCFNumberLongLongType:
			CFNumberGetValue(cfr, kCFNumberLongLongType, &n);
			r = launch_data_alloc(LAUNCH_DATA_INTEGER);
			launch_data_set_integer(r, n);
			break;
		case kCFNumberFloat32Type:
		case kCFNumberFloat64Type:
		case kCFNumberFloatType:
		case kCFNumberDoubleType:
			CFNumberGetValue(cfr, kCFNumberDoubleType, &d);
			r = launch_data_alloc(LAUNCH_DATA_REAL);
			launch_data_set_real(r, d);
			break;
		default:
			r = NULL;
			break;
		}
	} else {
		r = NULL;
	}
	return r;
}
#endif /* _BUILD_DARWIN_ */

/*
 * Display help page.
 */
static int help_cmd(int argc, char *const argv[])
{
	FILE *where = stdout;
	int l, cmdwidth = 0;
	size_t i;
	
	if (argc == 0 || argv == NULL)
		where = stderr;

	fprintf(where, "usage: %s <subcommand>\n", getprogname());

	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++) {
		l = strlen(cmds[i].name);
		if (l > cmdwidth)
			cmdwidth = l;
	}

	for (i = 0; i < (sizeof cmds / sizeof cmds[0]); i++) {
		if (cmds[i].func == exit_cmd && istty == false)
			continue;
		fprintf(where, "\t%-*s\t%s\n", cmdwidth, cmds[i].name, 
			cmds[i].desc);
	}

	return 0;
}

/*
 * Exit function.
 */
static int exit_cmd(int argc __attribute__((unused)), 
		    char *const argv[] __attribute__((unused)))
{
	exit(EXIT_SUCCESS);
	
	return 0; // god help us if we get here ;)
}

#ifdef _SQL_CONF_
/*
 * Handles the set command for solidbase account.
 */
static int setsbacct_cmd(int argc, char *const argv[])
{
	log_info("in setsbacct_cmd");

	if (argc < 2) {
		fprintf(stderr, "usage: setsbacct user [pass] [host [port]]\n");
		return 1;
	}

	setsbacct_defaults();

	if (argc >= 2)
		sbuser = strdup(argv[1]);
	if (argc >= 3)
		sbpass = strdup(argv[2]);
	if (argc >= 4)
		sbhost = strdup(argv[3]);
	if (argc >= 5)
		sbport = atoi(argv[4]);
	if (argc >= 6)
		sbdb = strdup(argv[5]);

	log_info("account set: %s-%s-%s-%d-%s", sbuser, sbpass, sbhost, sbport,
		 sbdb);

	return 0;
}

/*
 * Sets the solidbase account to default values.
 */
static void setsbacct_defaults(void)
{
	sbuser = getlogin();
	sbpass = "";

	sbhost = DEF_SBHOST;
	sbport = DEF_SBPORT;
	sbdb = DEF_SBDB;
	
	return;
}

#endif /* _SQL_CONF_ */

/*
 * Handles load and unload commands.
 */
static int load_and_unload_cmd(int argc, char *const argv[])
{
	launch_data_t pass1, pass2;
	int i, ch;
	bool wflag = false;
	bool lflag = false;
	bool Fflag = false;

	if (!strcmp(argv[0], "load"))
		lflag = true;

        while ((ch = getopt(argc, argv, "wF")) != -1) {
                switch (ch) {
                case 'w': wflag = true; break;
                case 'F': Fflag = true; break;
                default:
                        fprintf(stderr, 
				"usage: %s load [-wF] paths...\n", 
				getprogname());
                        return 1;
                }
        }
        argc -= optind;
        argv += optind;

	if (argc == 0) {
		fprintf(stderr, "usage: %s load [-w] paths...\n", 
			getprogname());
		return 1;
	}

	/* I wish I didn't need to do two passes, but I need to load 
	 * mDNSResponder and use it too.
	 * In later versions of launchd, I hope to load everything in the
	 * first pass, then do the Bonjour magic on the jobs that need 
	 * it, and reload them, but for now, I haven't thought through 
	 * the various complexities of reloading jobs, and therefore
	 * launchd doesn't have reload support right now.
	 */

	pass1 = launch_data_alloc(LAUNCH_DATA_ARRAY);
	pass2 = launch_data_alloc(LAUNCH_DATA_ARRAY);

	for (i = 0; i < argc; i++) {
		//log_info("load_and_unload: %s", argv[i]);
		readpath(argv[i], pass1, pass2, wflag, lflag, Fflag);
	}

	if (((launch_data_array_get_count(pass1)) == 0) 
	    && ((launch_data_array_get_count(pass2)) == 0)) {
		fprintf(stderr, "nothing found to %s\n", 
			lflag ? "load" : "unload");
		//log_info("nothing found to %s", lflag? "load" : "unload");
		launch_data_free(pass1);
		launch_data_free(pass2);
		return 1;
	}
	
	if (lflag) {
		if (0 < launch_data_array_get_count(pass1)) {
			syslog(LOG_INFO, "load: pass 1");
			submit_job_pass(pass1);
		}
		if (0 < launch_data_array_get_count(pass2)) {
			syslog(LOG_INFO, "load: pass 2");
			submit_job_pass(pass2);
		}
	} else {
		for (i = 0; i < (int)launch_data_array_get_count(pass1); 
		     i++)
			unloadjob(launch_data_array_get_index(pass1, i));
		for (i = 0; i < (int)launch_data_array_get_count(pass2);
		     i++)
			unloadjob(launch_data_array_get_index(pass2, i));
	}

	return 0;
}

/*
 * Process jobs for submission to launchd.
 */
static void submit_job_pass(launch_data_t jobs)
{
	launch_data_t msg, resp;
	size_t i;
	int e;

	for (i = 0; i < launch_data_array_get_count(jobs); i++)
		distill_config_file(launch_data_array_get_index(jobs, i));

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	launch_data_dict_insert(msg, jobs, LAUNCH_KEY_SUBMITJOB);

	resp = launch_msg(msg);

	if (resp) {
		switch (launch_data_get_type(resp)) {
		case LAUNCH_DATA_ERRNO:
			if ((e = launch_data_get_errno(resp)))
				fprintf(stderr, "%s\n", strerror(e));
			break;
		case LAUNCH_DATA_ARRAY:
			for (i = 0; i < launch_data_array_get_count(jobs); i++) {
				launch_data_t obatind = launch_data_array_get_index(resp, i);
				launch_data_t jatind = launch_data_array_get_index(jobs, i);
				const char *lab4job = launch_data_get_string(launch_data_dict_lookup(jatind, LAUNCH_JOBKEY_LABEL));
				if (LAUNCH_DATA_ERRNO == launch_data_get_type(obatind)) {
					e = launch_data_get_errno(obatind);
					switch (e) {
					case EEXIST:
						fprintf(stderr, "%s: %s\n", lab4job, "Already loaded");
						break;
					case ESRCH:
						fprintf(stderr, "%s: %s\n", lab4job, "Not loaded");
						break;
					default:
						fprintf(stderr, "%s: %s\n", lab4job, strerror(e));
					case 0:
						break;
					}
				}
			}
			break;
		default:
			fprintf(stderr, "unknown respose from launchd!\n");
			break;
		}
		launch_data_free(resp);
	} else {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
	}

	launch_data_free(msg);
}

static int start_stop_remove_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgcmd = LAUNCH_KEY_STOPJOB;
	int e, r = 0;

	if (0 == strcmp(argv[0], "start"))
		lmsgcmd = LAUNCH_KEY_STARTJOB;

	if (0 == strcmp(argv[0], "remove"))
		lmsgcmd = LAUNCH_KEY_REMOVEJOB;

	if (argc != 2) {
		fprintf(stderr, "usage: %s %s <job label>\n", 
			getprogname(), argv[0]);
		return 1;
	}

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_dict_insert(msg, launch_data_new_string(argv[1]), 
				lmsgcmd);

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", 
				getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	return r;
}

static void print_jobs(launch_data_t j __attribute__((unused)), 
		       const char *label, 
		       void *context __attribute__((unused)))
{
	launch_data_t pido = launch_data_dict_lookup(j, LAUNCH_JOBKEY_PID);
	launch_data_t stato = launch_data_dict_lookup(j, LAUNCH_JOBKEY_LASTEXITSTATUS);

	if (pido) {
		fprintf(stdout, "%lld\t-\t%s\n", 
			launch_data_get_integer(pido), label);
	} else if (stato) {
		int wstatus = (int)launch_data_get_integer(stato);
		if (WIFEXITED(wstatus)) {
			fprintf(stdout, "-\t%d\t%s\n", 
				WEXITSTATUS(wstatus), label);
		} else if (WIFSIGNALED(wstatus)) {
			fprintf(stdout, "-\t-%d\t%s\n", 
				WTERMSIG(wstatus), label);
		} else {
			fprintf(stdout, "-\t???\t%s\n", label);
		}
	} else {
		fprintf(stdout, "-\t-\t%s\n", label);
	}
}

#if !defined(_BUILD_DARWIN_) && !defined(_XML_CONF_) && !defined(_SQL_CONF_)
static int quickstart_cmd(int argc, char *const argv[]) {
	launch_data_t pass1;
	launch_data_t resp, msg, label;
	launch_data_t thejob;
	
	/* XXX: I need to add some error checking after the deadline */

	pass1 = launch_data_alloc(LAUNCH_DATA_ARRAY);

	thejob = read_conf_file(argv[1]);
	label = launch_data_dict_lookup(thejob, LAUNCH_JOBKEY_LABEL);

	/* XXX: assuming data has been read correctly */
	launch_data_array_append(pass1, thejob);
	submit_job_pass(pass1);

	fprintf(stderr, "finished loading in quickstart()\n");
	/* end load portion */

	fprintf(stderr, "label of type: %d\n", 
		launch_data_get_type(label));
	fprintf(stderr, "constructing msg data struct\n");
	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	//launch_data_dict_insert(msg, label, LAUNCH_KEY_STARTJOB);

	fprintf(stderr, "calling launch_msg()\n");
	resp = launch_msg(msg);
	fprintf(stderr, "executed launch_msg()\n");
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	}

	launch_data_free(resp);

	return 0;
}
#endif /* !_XML_CONF_ && !_BUILD_DARWIN_ */

static int list_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
        int ch, r = 0;
        bool vflag = false;

        while ((ch = getopt(argc, argv, "v")) != -1) {
                switch (ch) {
                case 'v':
                        vflag = true;
                        break;
                default:
                        fprintf(stderr, "usage: %s list [-v]\n", 
				getprogname());
                        return 1;
                }
        }

        if (vflag) {
                fprintf(stderr, "usage: %s list: \"-v\" flag not implemented yet\n", getprogname());
                return 1;
        }

        msg = launch_data_new_string(LAUNCH_KEY_GETJOBS);
        resp = launch_msg(msg);
        launch_data_free(msg);

        if (resp == NULL) {
                fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
                return 1;
        } else if (launch_data_get_type(resp) == LAUNCH_DATA_DICTIONARY) {
                fprintf(stdout, "PID\tStatus\tLabel\n");
                launch_data_dict_iterate(resp, print_jobs, NULL);
        } else {
                fprintf(stderr, "%s %s returned unknown response\n", getprogname(), argv[0]);
                r = 1;
        }

        launch_data_free(resp);

        return r;
}

static int stdio_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg, tmp;
	int e, fd = -1, r = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s %s <path>\n", getprogname(), 
			argv[0]);
		return 1;
	}

	fd = open(argv[1], O_CREAT|O_APPEND|O_WRONLY, DEFFILEMODE);

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);

	if (fd == -1) {
		tmp = launch_data_new_string(argv[1]);
	} else {
		tmp = launch_data_new_fd(fd);
	}

	if (!strcmp(argv[0], "stdout")) {
		launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETSTDOUT);
	} else {
		launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETSTDERR);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", 
				getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	if (fd != -1)
		close(fd);

	launch_data_free(resp);

	return r;
}

static int fyi_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	const char *lmsgk = LAUNCH_KEY_RELOADTTYS;
	int e, r = 0;

	if (argc != 1) {
		fprintf(stderr, "usage: %s %s\n", getprogname(), 
			argv[0]);
		return 1;
	}

	if (!strcmp(argv[0], "shutdown")) {
		lmsgk = LAUNCH_KEY_SHUTDOWN;
	} else if (!strcmp(argv[0], "singleuser")) {
		lmsgk = LAUNCH_KEY_SINGLEUSER;
	}

	msg = launch_data_new_string(lmsgk);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", 
				getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

static int logupdate_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	int e, i, j, r = 0, m = 0;
	bool badargs = false, maskmode = false, onlymode = false, 
		levelmode = false;
	const char *whichcmd = LAUNCH_KEY_SETLOGMASK;
	static const struct {
		const char *name;
		int level;
	} logtbl[] = {
		{ "debug",	LOG_DEBUG },
		{ "info",	LOG_INFO },
		{ "notice",	LOG_NOTICE },
		{ "warning",	LOG_WARNING },
		{ "error",	LOG_ERR },
		{ "critical",	LOG_CRIT },
		{ "alert",	LOG_ALERT },
		{ "emergency",	LOG_EMERG },
	};
	int logtblsz = sizeof logtbl / sizeof logtbl[0];

	if (argc >= 2) {
		if (!strcmp(argv[1], "mask"))
			maskmode = true;
		else if (!strcmp(argv[1], "only"))
			onlymode = true;
		else if (!strcmp(argv[1], "level"))
			levelmode = true;
		else
			badargs = true;
	}

	if (maskmode)
		m = LOG_UPTO(LOG_DEBUG);

	if (argc > 2 && (maskmode || onlymode)) {
		for (i = 2; i < argc; i++) {
			for (j = 0; j < logtblsz; j++) {
				if (!strcmp(argv[i], logtbl[j].name)) {
					if (maskmode)
						m &= ~(LOG_MASK(logtbl[j].level));
					else
						m |= LOG_MASK(logtbl[j].level);
					break;
				}
			}
			if (j == logtblsz) {
				badargs = true;
				break;
			}
		}
	} else if (argc > 2 && levelmode) {
		for (j = 0; j < logtblsz; j++) {
			if (!strcmp(argv[2], logtbl[j].name)) {
				m = LOG_UPTO(logtbl[j].level);
				break;
			}
		}
		if (j == logtblsz)
			badargs = true;
	} else if (argc == 1) {
		whichcmd = LAUNCH_KEY_GETLOGMASK;
	} else {
		badargs = true;
	}

	if (badargs) {
		fprintf(stderr, "usage: %s [[mask loglevels...] | [only loglevels...] [level loglevel]]\n", getprogname());
		return 1;
	}

	if (whichcmd == LAUNCH_KEY_SETLOGMASK) {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(msg, launch_data_new_integer(m), 
					whichcmd);
	} else {
		msg = launch_data_new_string(whichcmd);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		if ((e = launch_data_get_errno(resp))) {
			fprintf(stderr, "%s %s error: %s\n", 
				getprogname(), argv[0], strerror(e));
			r = 1;
		}
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_INTEGER) {
		if (whichcmd == LAUNCH_KEY_GETLOGMASK) {
			m = launch_data_get_integer(resp);
			for (j = 0; j < logtblsz; j++) {
				if (m & LOG_MASK(logtbl[j].level))
					fprintf(stdout, "%s ", 
						logtbl[j].name);
			}
			fprintf(stdout, "\n");
		}
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);

	return r;
}

static const struct {
	const char *name;
	int lim;
} limlookup[] = {
	{ "cpu",	RLIMIT_CPU },
	{ "filesize",	RLIMIT_FSIZE },
	{ "data",	RLIMIT_DATA },
	{ "stack",	RLIMIT_STACK },
	{ "core",	RLIMIT_CORE },
	{ "rss", 	RLIMIT_RSS },
	{ "memlock",	RLIMIT_MEMLOCK },
	{ "maxproc",	RLIMIT_NPROC },
	{ "maxfiles",	RLIMIT_NOFILE }
};

static const size_t limlookupcnt = sizeof limlookup / sizeof limlookup[0];

static ssize_t name2num(const char *n)
{
	size_t i;

	for (i = 0; i < limlookupcnt; i++) {
		if (!strcmp(limlookup[i].name, n)) {
			return limlookup[i].lim;
		}
	}
	return -1;
}

static const char *num2name(int n)
{
	size_t i;

	for (i = 0; i < limlookupcnt; i++) {
		if (limlookup[i].lim == n)
			return limlookup[i].name;
	}
	return NULL;
}

static const char *lim2str(rlim_t val, char *buf)
{
	if (val == RLIM_INFINITY)
		strcpy(buf, "unlimited");
	else
		sprintf(buf, "%lld", (long long)val);
	return buf;
}

static bool str2lim(const char *buf, rlim_t *res)
{
	char *endptr;
	*res = strtoll(buf, &endptr, 10);
	if (!strcmp(buf, "unlimited")) {
		*res = RLIM_INFINITY;
		return false;
	} else if (*endptr == '\0') {
		 return false;
	}
	return true;
}



static int limit_cmd(int argc __attribute__((unused)), 
		     char *const argv[])
{
	char slimstr[100];
	char hlimstr[100];
	struct rlimit *lmts = NULL;
	launch_data_t resp, resp1 = NULL, msg, tmp;
	int r = 0;
	size_t i, lsz = -1, which = 0;
	rlim_t slim = -1, hlim = -1;
	bool badargs = false;

	if (argc > 4)
		badargs = true;

	if (argc >= 3 && str2lim(argv[2], &slim))
		badargs = true;
	else
		hlim = slim;

	if (argc == 4 && str2lim(argv[3], &hlim))
		badargs = true;

	if (argc >= 2 && -1 == (which = name2num(argv[1])))
		badargs = true;

	if (badargs) {
		fprintf(stderr, "usage: %s %s [", getprogname(), 
			argv[0]);
		for (i = 0; i < limlookupcnt; i++)
			fprintf(stderr, "%s %s", limlookup[i].name, 
				(i + 1) == limlookupcnt ? "" : "| ");
		fprintf(stderr, "[both | soft hard]]\n");
		return 1;
	}

	msg = launch_data_new_string(LAUNCH_KEY_GETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_OPAQUE) {
		lmts = launch_data_get_opaque(resp);
		lsz = launch_data_get_opaque_size(resp);
		if (argc <= 2) {
			for (i = 0; i < (lsz / sizeof(struct rlimit)); 
			     i++) {
				if (argc == 2 && (size_t)which != i)
					continue;
				fprintf(stdout, "\t%-12s%-15s%-15s\n", 
					num2name(i), 
					lim2str(lmts[i].rlim_cur, 
						slimstr),
					lim2str(lmts[i].rlim_max, 
						hlimstr));
			}
		}
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), 
			argv[0], launch_data_get_string(resp));
		r = 1;
	} else {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	if (argc <= 2 || r != 0) {
		launch_data_free(resp);
		return r;
	} else {
		resp1 = resp;
	}

	lmts[which].rlim_cur = slim;
	lmts[which].rlim_max = hlim;

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	tmp = launch_data_new_opaque(lmts, lsz);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_SETRESOURCELIMITS);
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), 
			argv[0], launch_data_get_string(resp));
		r = 1;
	} else if (launch_data_get_type(resp) != LAUNCH_DATA_OPAQUE) {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	}

	launch_data_free(resp);
	launch_data_free(resp1);

	return r;
}

static int umask_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	bool badargs = false;
	char *endptr;
	long m = 0;
	int r = 0;

	if (argc == 2) {
		m = strtol(argv[1], &endptr, 8);
		if (*endptr != '\0' || m > 0777)
			badargs = true;
	}

	if (argc > 2 || badargs) {
		fprintf(stderr, "usage: %s %s <mask>\n", getprogname(), 
			argv[0]);
		return 1;
	}


	if (argc == 1) {
		msg = launch_data_new_string(LAUNCH_KEY_GETUMASK);
	} else {
		msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		launch_data_dict_insert(msg, launch_data_new_integer(m), 
					LAUNCH_KEY_SETUMASK);
	}
	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_STRING) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), 
			argv[0], launch_data_get_string(resp));
		r = 1;
	} else if (launch_data_get_type(resp) != LAUNCH_DATA_INTEGER) {
		fprintf(stderr, "%s %s returned unknown response\n", 
			getprogname(), argv[0]);
		r = 1;
	} else if (argc == 1) {
		fprintf(stdout, "%o\n", 
			(unsigned int)launch_data_get_integer(resp));
	}

	launch_data_free(resp);

	return r;
}

static int submit_cmd(int argc, char *const argv[])
{
        launch_data_t msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
        launch_data_t job = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
        launch_data_t resp, largv = launch_data_alloc(LAUNCH_DATA_ARRAY);
        int ch, i, r = 0;

        launch_data_dict_insert(job, launch_data_new_bool(false), 
				LAUNCH_JOBKEY_ONDEMAND);

        while ((ch = getopt(argc, argv, "l:p:o:e:")) != -1) {
                switch (ch) {
                case 'l':
                        launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_LABEL);
                        break;
                case 'p':
                        launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_PROGRAM);
                        break;
                case 'o':
                        launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_STANDARDOUTPATH);
                        break;
                case 'e':
                        launch_data_dict_insert(job, launch_data_new_string(optarg), LAUNCH_JOBKEY_STANDARDERRORPATH);
                        break;
                default:
                        fprintf(stderr, "usage: %s submit ...\n", 
				getprogname());
                        return 1;
                }
        }
        argc -= optind;
        argv += optind;

        for (i = 0; argv[i]; i++) {
                launch_data_array_append(largv, launch_data_new_string(argv[i]));
        }

        launch_data_dict_insert(job, largv, 
				LAUNCH_JOBKEY_PROGRAMARGUMENTS);

        launch_data_dict_insert(msg, job, LAUNCH_KEY_SUBMITJOB);

        resp = launch_msg(msg);
        launch_data_free(msg);

        if (resp == NULL) {
                fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
                return 1;
        } else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
                errno = launch_data_get_errno(resp);
                if (errno) {
                        fprintf(stderr, "%s %s error: %s\n", 
				getprogname(), argv[0], strerror(errno));
                        r = 1;
                }
        } else {
                fprintf(stderr, "%s %s error: %s\n", getprogname(), 
			argv[0], "unknown response");
        }

        launch_data_free(resp);

        return r;
}

static int getrusage_cmd(int argc, char *const argv[])
{
	launch_data_t resp, msg;
	bool badargs = false;
	int r = 0;

	if (argc != 2)
		badargs = true;
	else if (strcmp(argv[1], "self") && strcmp(argv[1], "children"))
		badargs = true;

	if (badargs) {
		fprintf(stderr, "usage: %s %s self | children\n", 
			getprogname(), argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "self")) {
		msg = launch_data_new_string(LAUNCH_KEY_GETRUSAGESELF);
	} else {
		msg = launch_data_new_string(LAUNCH_KEY_GETRUSAGECHILDREN);
	}

	resp = launch_msg(msg);
	launch_data_free(msg);

	if (resp == NULL) {
		fprintf(stderr, "launch_msg(): %s\n", strerror(errno));
		return 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		fprintf(stderr, "%s %s error: %s\n", getprogname(), 
			argv[0], strerror(launch_data_get_errno(resp)));
		r = 1;
	} else if (launch_data_get_type(resp) == LAUNCH_DATA_OPAQUE) {
		struct rusage *rusage = launch_data_get_opaque(resp);
		fprintf(stdout, "\t%-10f\tuser time used\n",
			(double)rusage->ru_utime.tv_sec 
			+ (double)rusage->ru_utime.tv_usec 
			/ (double)1000000);
		fprintf(stdout, "\t%-10f\tsystem time used\n",
			(double)rusage->ru_stime.tv_sec 
			+ (double)rusage->ru_stime.tv_usec 
			/ (double)1000000);
		fprintf(stdout, "\t%-10ld\tmax resident set size\n", 
			rusage->ru_maxrss);
		fprintf(stdout, "\t%-10ld\tshared text memory size\n", 
			rusage->ru_ixrss);
		fprintf(stdout, "\t%-10ld\tunshared data size\n", 
			rusage->ru_idrss);
		fprintf(stdout, "\t%-10ld\tunshared stack size\n",
			rusage->ru_isrss);
		fprintf(stdout, "\t%-10ld\tpage reclaims\n", 
			rusage->ru_minflt);
		fprintf(stdout, "\t%-10ld\tpage faults\n", 
			rusage->ru_majflt);
		fprintf(stdout, "\t%-10ld\tswaps\n", rusage->ru_nswap);
		fprintf(stdout, "\t%-10ld\tblock input operations\n", 
			rusage->ru_inblock);
		fprintf(stdout, "\t%-10ld\tblock output operations\n", 
			rusage->ru_oublock);
		fprintf(stdout, "\t%-10ld\tmessages sent\n", 
			rusage->ru_msgsnd);
		fprintf(stdout, "\t%-10ld\tmessages received\n",
			rusage->ru_msgrcv);
		fprintf(stdout, "\t%-10ld\tsignals received\n",
			rusage->ru_nsignals);
		fprintf(stdout, "\t%-10ld\tvoluntary context switches\n",
			rusage->ru_nvcsw);
		fprintf(stdout, 
			"\t%-10ld\tinvoluntary context switches\n", 
			rusage->ru_nivcsw);
	} else {
		fprintf(stderr, "%s %s returned unknown response\n",
			getprogname(), argv[0]);
		r = 1;
	} 

	launch_data_free(resp);

	return r;
}

static bool launch_data_array_append(launch_data_t a, launch_data_t o)
{
	size_t offt = launch_data_array_get_count(a);

	return launch_data_array_set_index(a, o, offt);
}
