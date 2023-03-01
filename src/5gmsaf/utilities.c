/*
License: 5G-MAG Public License (v1.0)
Author: Dev Audsin
Copyright: (C) 2022 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ctype.h>
#include "utilities.h"

time_t str_to_time(char *str_time)
{
    static time_t time;
    struct tm tm = {0};
    strptime(str_time, "%a, %d %b %Y %H:%M:%S %Z", &tm);
    time = mktime(&tm);      
    return time;
}	

char *get_time(time_t time_epoch)
{
    struct tm *ts;
    static char buf[80];

    /* Format and print the time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
    ts = localtime(&time_epoch);   
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", ts);

    return buf;
}

char *read_file(const char *filename)
{
    FILE *f = NULL;
    long len = 0;
    char *data_json = NULL;

    /* open in read binary mode */
    f = fopen(filename, "rb");
    if (f == NULL) {
	ogs_error("Unable to open file with name [%s]: %s", filename, strerror(errno));
	return NULL;
    }
    /* get the length */
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    data_json = (char*)malloc(len + 1);

    fread(data_json, 1, len, f);
    data_json[len] = '\0';
    fclose(f);
    return data_json;

}

int str_match(const char *line, const char *word_to_find) {
 
  char* p = strstr(line,word_to_find);
  if ((p==line) || (p!=NULL && !isalnum((unsigned char)p[-1])))
  {
     p += strlen(word_to_find);
     if (!isalnum((unsigned char)*p))
     {      
       return 1;
     } else {
	return 0;
    }
  }
  return 0;
}

char *get_path(const char *file)
{
    char *path = NULL;
    char *file_dir = NULL;

    path = realpath(file, NULL);
    if(path == NULL){
        ogs_error("cannot find file with name[%s]: %s", file, strerror(errno));
        return NULL;
    }
    file_dir = ogs_strdup(dirname(path));
    return file_dir;
}

char *rebase_path(const char *base, const char *file)
{
    ogs_debug("rebase_path(\"%s\", \"%s\")", base, file);
    if (file[0] != '/') {
        /* relative path - prefix with the directory of the base filename */
        char *base_path, *path;
        base_path = get_path(base);
        path = ogs_msprintf("%s/%s", base_path, file);
        ogs_free(base_path);
        return path;
    }
    /* absolute path - return a copy */
    return ogs_strdup(file);
}

long int ascii_to_long(const char *str)
{
    char *endp = NULL;
    long int ret;

    ret = strtol(str, &endp, 10);
    if (endp == NULL || *endp != 0) {
        ogs_error("Failed to convert '%s' to an integer", str);
        ret = 0;
    }
    return ret;
}

uint16_t ascii_to_uint16(const char *str) 
{
    long int ret;
    ret = ascii_to_long(str);
    if (ret > UINT16_MAX)
    {
        ogs_error("[%s] cannot be greater than [%d]", str, UINT16_MAX);
        ret = 0;
    }
    return ret;
}

cJSON *create_cjson_number_object(char *name, int value)
{
    cJSON *item = NULL;
    item = cJSON_CreateObject();
    if (cJSON_AddNumberToObject(item, name, value) == NULL) 
    {
        ogs_error("Failed to create JSON object [%s] for integer value [%d]", name, value);
    }
    return item;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
