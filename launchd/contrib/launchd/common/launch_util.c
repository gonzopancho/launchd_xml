/*
 * Copyright 2006 Infoweapons Corporation
 */

#include <stdio.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libutil.h>
#include <string.h>
#include "launch_log.h"

#ifdef _SQL_CONF_
/* 
 * Get user input solidbase password 
 *  for specified user.
 */
char *
input_sbpass(char *username)
{
	char *sbpass, *prompt;

	asprintf(&prompt, "SolidBase Account\nUsername: %s\nPassword: ", 
		 username);

	if (prompt == NULL) {
		log_err("Memory allocation error: password input");
		exit(1);
	}
	sbpass = getpass(prompt);

	return (sbpass);
} /* input_sbpass */

/* 
 * Determine solidbase table name for particular user.
 */
char *
get_confname(char *user)
{
	char *conf;

	asprintf(&conf, "%s_conf", user);
	
	return (conf);
} /* get_confname */

#endif /* _SQL_CONF_ */

/*
 * Set config value.
 */ 
int
set_cfvalue(properties head, const char *key, char **store)
{
	int ret = 0;
	char *value;

	value = property_find(head, key);
	if (value) {
		*store = strdup(value);
		ret = 1;
	}

	return (ret);
} /* set_cfvalue */
