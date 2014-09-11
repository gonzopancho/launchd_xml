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

#ifndef __LAUNCHD_H__
#define __LAUNCHD_H__

#include <unistd.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "launch.h"

/*
 * Use launchd_assumes() when we can recover, even if it means we leak or limp along.
 *
 * Use launchd_assert() for core initialization routines.
 */
#define launchd_assumes(e)	\
	(__builtin_expect(!(e), 0) ? syslog(LOG_NOTICE, "Please file a bug report: %s:%u in %s(): (%s) == %u", __FILE__, __LINE__, __func__, #e, errno), false : true)

#define launchd_assert(e)	launchd_assumes(e) ? true : abort();

#define PID1_REAP_ADOPTED_CHILDREN

struct kevent;
struct conncb;

typedef void (*kq_callback)(void *, struct kevent *);

extern kq_callback kqsimple_zombie_reaper;
extern sigset_t blocked_signals;
extern bool shutdown_in_progress;
extern int batch_disabler_count;

#ifdef PID1_REAP_ADOPTED_CHILDREN
extern int pid1_child_exit_status;
bool init_check_pid(pid_t);
#endif

int kevent_mod(uintptr_t ident, short filter, u_short flags, u_int fflags, intptr_t data, void *udata);

/* note: the following functions are defined in ./init.c */
void init_boot(bool sflag, bool vflag, bool xflag);
void init_pre_kevent(void);
bool init_check_pid(pid_t);
void fsck_all(void);
void mount_localfs(void);

#ifdef _SQL_CONF_
void run_sqlitedbms(void);
void enable_solidbase_inet(void);
#endif

void update_ttys(void);
void catatonia(void);
void death(bool reboot, int howto);

void batch_job_enable(bool e, struct conncb *c);

launch_data_t launchd_setstdio(int d, launch_data_t o);
void launchd_SessionCreate(void);
void launchd_shutdown(void);
void launchd_single_user(void);
pid_t launchd_fork(void);
pid_t launchd_ws_fork(void);
int _fd(int fd);
/* this is exposed to init.c */
void reload_launchd_config_sql(void);
void reload_launchd_config_plist(void);

#ifdef _BUILD_DARWIN_
boolean_t launchd_mach_ipc_demux(mach_msg_header_t *Request, mach_msg_header_t *Reply);
extern mach_port_t launchd_bootstrap_port;
void launchd_SessionCreate(const char *who);
#endif


#ifndef _BUILD_DARWIN_

// on Darwin-based systems, LOG_LAUNCHD is defined for syslog()
#define LOG_LAUNCHD LOG_DAEMON

/* on Darwin-based systems, O_EVTONLY helps us track changes to a certain file descriptor
 * as outlined here:
 * http://developer.apple.com/documentation/Performance/Conceptual/FileSystem/Articles/TrackingChanges.html#//apple_ref/doc/uid/20001993-118158 
 * 
 * in FreeBSDland, EVFILT_VNODE is the closest thing to what we want to do
 * see: job_watch():launchd.c and load_job():launchd.c for it's usage.
 */
#define O_EVTONLY EVFILT_VNODE

/* 
 * these are defined in sys/event.h in the Darwin source tree, for now we'll 
 * define them here (disgusting, but we'll see how it works out.
 * 
 * XXX: this _will_ (most likely) break something ;)
 */
#define NOTE_SECONDS    0x00000001              /* data is seconds         */
#define NOTE_USECONDS   0x00000002              /* data is microseconds    */
#define NOTE_NSECONDS   0x00000004              /* data is nanoseconds     */
#define NOTE_ABSOLUTE   0x00000008              /* absolute timeout        */
#endif

#endif
