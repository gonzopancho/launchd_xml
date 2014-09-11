/*
 * Interface functions to SolidBase(SQLiteDBMS).
 *
 * Copyright 2006 Infoweapons Corporation
 */

#include <stdio.h>
#include <solidb.h> /* equivalent to sqlited.h */
#include <stdlib.h>
#include <syslog.h>
#include <time.h>  /* sqldbms re-connect */
#include <fcntl.h>

#include "launch.h"
#include "launch_priv.h"
#include "launch_sb_if.h"
#include "launch_pliststack.h"
#include "launch_log.h"

static void write_launchctl_cmd(int fd, char ***table, sqlited_int64 rows);
static void cnv_dict(char **table, STACK *pliststack);
static void cnv_arr(char **table, STACK *pliststack);
static void cnv_str(char **table, STACK *pliststack);
static void cnv_bool(char **table, STACK *pliststack);
static void cnv_int(char **table, STACK *pliststack);

extern char *sqlited_error;

/*
 * Connect to the solidbase process.
 */
sqlited *connect_sb(char *sbuser, char *sbpass, char *sbhost, int sbport, 
		    char *sbdb)
{
	sqlited *retdb = NULL;
	char *conninfo, *proto;
	time_t start_time = 0, curr_time=0;

	if (geteuid() == 0) {
		proto = "http";
	} else {
		proto = "https";
	}

	asprintf(&conninfo, "%s://%s:%s@%s:%d/%s", proto, sbuser, sbpass,
		 sbhost, sbport, sbdb);
	log_info("%s", conninfo);
	if (conninfo == NULL) {
		log_err("memory allocation failure");
		retdb = NULL;
	} else {
		time(&start_time);
		while (retdb == NULL) {
			if ((sqlited_open(&retdb, conninfo)) != SQLITED_OK) {
				retdb = NULL;
				sleep(1);
			} else {
				/* successful connect to sqlitedbms */
				log_info("connected to solidbase");
			}
			time(&curr_time);
			if ((curr_time - start_time) >= RETRY_TIMEOUT) {
				log_err("connect timeout reached");
				break;
			} 
		}
	}

	free(conninfo); /* sqlited keeps own copy */

	return (retdb);

} /* connect_sb */

/*
 * Get launchd.conf equivalent table. 
 */
int load_initrc_jobs(sqlited *db, char *conf, int fd)
{
	int tbl_retval;
	sqlited_result *result;
	char ***table;
	sqlited_int64 rows;
	unsigned int fields;
	char *querystr;

	if ((asprintf(&querystr, "SELECT * FROM %s", conf)) == -1) {
		log_err("memory allocation failed");
		sqlited_close(db);
		return (SQLDBMS_IF_MEMERR);
	}
	
	tbl_retval = get_table_data(db, querystr, &result, &table, &rows,
				    &fields);
	if (tbl_retval == SQLITED_OK) {
		if (table != NULL)
			write_launchctl_cmd(fd, table, rows);
	} else {
		log_err("get_table_data() error");
	}

	free(querystr);
	return (tbl_retval);
} /* load_initrc_jobs */

/*
 * Write launchctl commands to launchctl socket.
 */
static void write_launchctl_cmd(int fd, char ***table,
				sqlited_int64 rows)
{
	char *cmd_str;
	int i;

	for (i=0; i<rows; i++) {
		asprintf(&cmd_str, "load %s\n", *table[i]);
		if (write(fd, cmd_str, strlen(cmd_str)) < 0) {
			log_err("error writing socket");
		}
		free(cmd_str);
	}

	return;
} /* write_launchctl_cmd */

/*
 * Get table data for individual jobs.
 *
 */
int get_table_data(sqlited *db, char *querystr, 
	  	   sqlited_result **result, 
		   char ****table, sqlited_int64 *rows, 
		   unsigned int *fields)
{
	int retval;

	*result = sqlited_query(db, querystr);
	if (*result != NULL) {
		if (sqlited_result_type(*result) == SQLITED_RESULT) {
			retval = sqlited_fetch_all(*result, table, rows, 
						   fields);
		} else {
			retval = SQLITED_ERROR;
		}
	} else {
		log_err("sqlitedbms query: null result");
		/* misspelled 'EMTPY' in sqlited.h */
		retval = SQLITED_RESULT_EMTPY;
	}
	return (retval);
} /* get_table_data */

/*
 * Converts configuration table data to launchd.
 */
launch_data_t cnv_sdbms_to_launch(char ***table, sqlited_int64 rows)
{
	launch_data_t launch_dt;
	STACK pliststack;
	int i;

	pliststack = create_stack();
	launch_dt = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	if ((pliststack == NULL) || (launch_dt == NULL)) {
		log_err("memory allocation error");
		return NULL;
	}
	/* launch_dt will the overall dict entry */
	push(launch_dt, pliststack);
	
	for (i=0; i<rows; i++) {
#ifdef DEBUG_MODE
		printf("[%d] %s: %s\n", i, table[i][0], table[i][2]);
#endif
		if (!strcmp(table[i][1], "dict")) {
			cnv_dict(table[i], &pliststack);
		} else if (!strcmp(table[i][1], "array")) {
			cnv_arr(table[i], &pliststack);
		} else if (!strcmp(table[i][1], "string")) {
			cnv_str(table[i], &pliststack);
		} else if (!strcmp(table[i][1], "boolean")) {
			cnv_bool(table[i], &pliststack);
		} else if (!strcmp(table[i][1], "integer")) {
			cnv_int(table[i], &pliststack);
		} else {
			fprintf(stderr, "Error: Unknown value type!");
		}
	}
	launch_dt = top(pliststack);
#ifdef DEBUG_MODE
	launch_data_dict_dump(launch_dt);
#endif
	pop(pliststack);
	if (!is_empty(pliststack))
		log_err("Warning: Stack not empty!");
	dispose_stack(pliststack);

	return (launch_dt);
} /* cnv_sdbms_to_launch */

/*
 * Convert a dictionary entry.
 */
static void cnv_dict(char **table, STACK *pliststack)
{
	launch_data_t launch_dt, key_dt, val_dt, tmp_dt;
	int count;

	tmp_dt = top(*pliststack);
	if (tmp_dt == NULL) {
		/* design decision to return a NULL pointer */
		/* error in sqlitedbms entry */
		dispose_stack(*pliststack);
		return;
	}
	if (!strcmp(table[2], "start")) {
		key_dt = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(key_dt, table[0]);
		count = launch_data_array_get_count(tmp_dt);
		launch_data_array_set_index(tmp_dt, key_dt, 
					    count);
		val_dt = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
		if (val_dt)
			push(val_dt, *pliststack);
		else
			return;
	} else if (!strcmp(table[2], "end")) {
		pop(*pliststack);
		launch_dt = (launch_data_t)top(*pliststack);
		if (launch_dt == NULL) {
			/* design decision to return a NULL pointer */
			/* error in sqlitedbms entry */
			dispose_stack(*pliststack);
			return;
		}		
		count = launch_data_array_get_count(launch_dt);
		launch_data_array_set_index(launch_dt, tmp_dt, count);
	} else {
		/* this is an error */
	}

	return;
} /* cnv_dict */

/*
 * Convert an array entry.
 */
static void cnv_arr(char **table, STACK *pliststack)
{
	launch_data_t launch_dt, key_dt, val_dt, tmp_dt;
	int count;

	tmp_dt = top(*pliststack);
	if (tmp_dt == NULL) {
		/* design decision to return a NULL pointer */
		/* error in sqlitedbms entry */
		dispose_stack(*pliststack);
		return;
	}
	if (!strcmp(table[2], "start")) {
		key_dt = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(key_dt, table[0]);
		count = launch_data_array_get_count(tmp_dt);
		launch_data_array_set_index(tmp_dt, key_dt, 
					    count);
		val_dt = launch_data_alloc(LAUNCH_DATA_ARRAY);
		if (val_dt)
			push(val_dt, *pliststack);
		else
			return;
	} else if (!strcmp(table[2], "end")) {
		pop(*pliststack);
		launch_dt = (launch_data_t)top(*pliststack);
		if (launch_dt == NULL) {
			/* design decision to return a NULL pointer */
			/* error in sqlitedbms entry */
			dispose_stack(*pliststack);
			return;
		}		
		count = launch_data_array_get_count(launch_dt);
		launch_data_array_set_index(launch_dt, tmp_dt, count);
	} else {
		/* this is an error */
	}

	return;
} /* cnv_arr */

/*
 * Convert a string entry.
 */
static void cnv_str(char **table, STACK *pliststack)
{
	launch_data_t key_dt, val_dt, tmp_dt;
	int count;

	tmp_dt = top(*pliststack);
	if (tmp_dt == NULL) {
		/* design decision to return a NULL pointer */
		/* error in sqlitedbms entry */
		dispose_stack(*pliststack);
		return;
	}
	count = launch_data_array_get_count(tmp_dt);
	if (launch_data_get_type(tmp_dt) != LAUNCH_DATA_ARRAY) {
		key_dt = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(key_dt, table[0]);
		launch_data_array_set_index(tmp_dt, key_dt, 
					    count++);
	}
	val_dt = launch_data_alloc(LAUNCH_DATA_STRING);
	launch_data_set_string(val_dt, table[2]);
	launch_data_array_set_index(tmp_dt, val_dt, count);

	return;
} /* cnv_str */

/*
 * Convert a boolean entry.
 */
static void cnv_bool(char **table, STACK *pliststack)
{
	launch_data_t key_dt, val_dt, tmp_dt;
	int count;

	tmp_dt = top(*pliststack);
	if (tmp_dt == NULL) {
		/* design decision to return a NULL pointer */
		/* error in sqlitedbms entry */
		dispose_stack(*pliststack);
		return;
	}
	count = launch_data_array_get_count(tmp_dt);
	if (launch_data_get_type(tmp_dt) != LAUNCH_DATA_ARRAY) {
		key_dt = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(key_dt, table[0]);
		launch_data_array_set_index(tmp_dt, key_dt,
					    count++);
	}
	val_dt = launch_data_alloc(LAUNCH_DATA_BOOL);
	launch_data_set_bool(val_dt, !strcmp(table[2], "true"));
	launch_data_array_set_index(tmp_dt, val_dt, count);

	return;
} /* cnv_bool */

/*
 * Convert a integer entry.
 */
static void cnv_int(char **table, STACK *pliststack)
{
	launch_data_t key_dt, val_dt, tmp_dt;
	int count;

	tmp_dt = top(*pliststack);
	if (tmp_dt == NULL) {
		/* design decision to return a NULL pointer */
		/* error in sqlitedbms entry */
		dispose_stack(*pliststack);
		return;
	}
	count = launch_data_array_get_count(tmp_dt);
	if (launch_data_get_type(tmp_dt) != LAUNCH_DATA_ARRAY) {
		key_dt = launch_data_alloc(LAUNCH_DATA_STRING);
		launch_data_set_string(key_dt, table[0]);
		launch_data_array_set_index(tmp_dt, key_dt, 
					    count++);
	}
	val_dt = launch_data_alloc(LAUNCH_DATA_INTEGER);
	launch_data_set_integer(val_dt, strtol(table[2], 
					       (char **)NULL, 10));
	launch_data_array_set_index(tmp_dt, val_dt, count);		

	return;
} /* cnv_int */
