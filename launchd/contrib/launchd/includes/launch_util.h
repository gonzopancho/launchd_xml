#ifndef __UTIL_H
#define __UTIL_H

/* key strings for launchd-solidbasefor configuration file */
#define  SBUSER  "user"
#define  SBPASS  "password"
#define  SBHOST  "host"
#define  SBPORT  "port"
#define  SBDB    "database"
#define  SBCONF  "init_config"

char *input_sbpass(char *);
char *get_confname(char *);
int set_cfvalue(properties, const char *, char **);

#endif /* __UTIL_H */
