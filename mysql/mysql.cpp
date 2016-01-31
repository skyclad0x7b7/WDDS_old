#include <string.h>
#include <stdio.h>
#include <iostream>
#include <mysql/mysql.h>

#define BUFSIZE 0xff

using namespace std;

int main(int argc, char *argv[])
{
    MYSQL pMysql;
    MYSQL_RES *res;
    MYSQL_FIELD *field;
    MYSQL_ROW row;
    unsigned int field_num;
    char buf[BUFSIZE] = {0};
    mysql_init(&pMysql);
    mysql_options(&pMysql, MYSQL_READ_DEFAULT_GROUP, "my_prog_name");
    if(!mysql_real_connect(&pMysql, "[SERVER]", "[USER]", "[PASSWD]", "[DB]", 3306, NULL, 0)){
        fprintf(stderr, "[*] Failed to Connect to the database : %s\n", mysql_error(&pMysql));
    }
    while(true)
    {
	printf("[*] Input Query! : ");
	gets(buf);
	if(mysql_real_query(&pMysql, buf, strlen(buf))){   // Error occured!!
		printf("[*] An Error occured in mysql_real_query : %s\n",mysql_error(&pMysql));
		continue;
	}
	res = mysql_store_result(&pMysql);
	if (res == 0) {
		printf("[*] Query Accepted\n");
		continue;
	}
	field_num = mysql_num_fields(res);
	for(int i=0; i<21*field_num+2; i++) printf("_");
	putchar('\n');
	while((field = mysql_fetch_field(res))){		// print fields
	    printf("|%20s", field->name);
	} printf("|\n");

	for(int i=0; i<21*field_num+2; i++) printf("_");
        putchar('\n');

	while((row = mysql_fetch_row(res))){			// print rows
	    for(int i=0; i<field_num; i++) {
		printf("|%20s", row[i] ? row[i] : "NULL");
	    } printf("|\n");
	}

	for(int i=0; i<21*field_num+2; i++) printf("_");
        putchar('\n');
    	putchar('\n');
    }
    return 0;
}
