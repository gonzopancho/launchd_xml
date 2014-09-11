#ifndef _SQLDBMS_IF_H
#define _SQLDBMS_IF_H

/* default solidbase settings */
#define DEF_PID1_SBHOST    "localdomain"
#define DEF_SBHOST         "localhost"
#define DEF_PID1_SBPORT    -1
#define DEF_SBPORT         6543
#define DEF_SBDB    	   "launchdb"

#define PID1_CONF	"launch_confs"
#define RETRY_TIMEOUT	30

/* SQLITEDBMS IF return codes */
#define SQLDBMS_IF_OK 0 
#define SQLDBMS_IF_MEMERR 1

/* SQLITEDBMS IF functions */
sqlited *connect_sb(char *, char *, char *, int, char *);
int load_initrc_jobs(sqlited *, char *, int);
int get_table_data(sqlited *, char *, sqlited_result **,
                   char ****, sqlited_int64 *, unsigned int *);
launch_data_t cnv_sdbms_to_launch(char ***table, sqlited_int64 rows);
#endif /* _SQLDBMS_IF_H_ */
