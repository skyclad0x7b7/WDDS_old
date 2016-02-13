/* Build : g++ -o scanner main.cpp -lpcap `mysql_config --cflags --libs`
*  
*  Author : 5kyc1ad
*/

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <cstring>
#include <iostream>
#include <mysql/mysql.h>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <time.h>

using namespace std;

#define BUFSIZE 65536
#define SQL_BUFSIZE 0xFF

#pragma pack(push, 1)
typedef struct beacon_frame {
    u_int16_t frame_control;
    u_int16_t duration;
    u_char dest[6];
    u_char src[6];
    u_char bss[6];
    u_int16_t seq_control;
} BF_header ;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ieee80211_wlan_management {
    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capabilities_information;
} IEEE80211 ;
#pragma pack(pop)

bool isContain(std::vector<string>*, string);
bool insertQuery(MYSQL *, char *query);
void *timer(void *);
void dataLogging(MYSQL *pMysql);


int main(int argc, char *argv[])
{
	if(argc != 2) {
		fprintf(stderr, "[*] Usage : scanner [dev]\n");
		return 1;
	}

	MYSQL pMysql;
    	MYSQL_RES *res;
    	MYSQL_FIELD *field;
	MYSQL_ROW row;
	char query[SQL_BUFSIZE];
    	unsigned int field_num, row_num, tmp;
    	char sql_buf[SQL_BUFSIZE] = "SELECT mac_addr FROM `user`";
    	mysql_init(&pMysql);
    	mysql_options(&pMysql, MYSQL_READ_DEFAULT_GROUP, "my_prog_name");
    	int flag = false;
	std::vector<string> mac_list;

	pthread_t timerThread;

	if(!mysql_real_connect(&pMysql, "localhost", "ID", "PASSWD", "wdds_db", 3306, NULL, 0)){
    	    fprintf(stderr, "[*] Failed to Connect to the database : %s\n", mysql_error(&pMysql));
		return 1;
    	}

	insertQuery(&pMysql, sql_buf);

	res = mysql_store_result(&pMysql);
	field_num = mysql_num_fields(res);
	row_num = mysql_num_rows(res);

	cout << "[*] Saved MAC Address" << endl;
	cout << "Field_num : " << field_num << endl;
	tmp = 0;
	while((row = mysql_fetch_row(res))){                    // print rows
        	printf("|%17s|\n", row[0] ? row[0] : "NULL");
		mac_list.push_back(row[0] ? row[0] : "NULL");
        }
	char errBuf[256];
	const u_char *data;
	pcap_pkthdr *pkthdr;
	BF_header bf_header;
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZE, 1, 10, errBuf);
	char src[18], dest[18];    	

	if(handle == NULL){
        	fprintf(stderr, "Couldn't open device %s : %s\n",  argv[1], errBuf);
        	return 1;
   	}
	cout << "[*] Please input any key to start scanning" << endl;
	getchar();

	if(pthread_create(&timerThread, NULL, timer, (void *)&pMysql)) {
		cout << "Threading Error!!" << endl;
		return 1;
	};
	while(true) {	
		int res = pcap_next_ex(handle, &pkthdr, &data);

		if(res == 0) continue;
		if(res < 0) break;
	
		data += *(u_int16_t *)(data+2); // Skip Radiotap Header
		memcpy(&bf_header, data, 0x18);
		if(bf_header.frame_control != 0x0050 && bf_header.frame_control != 0x0040) continue; // Probe response and request only
		sprintf(src, "%02X:%02X:%02X:%02X:%02X:%02X", bf_header.src[0], bf_header.src[1], bf_header.src[2], bf_header.src[3], bf_header.src[4], bf_header.src[5]);
		sprintf(dest, "%02X:%02X:%02X:%02X:%02X:%02X", bf_header.dest[0], bf_header.dest[1], bf_header.dest[2], bf_header.dest[3], bf_header.dest[4], bf_header.dest[5]);
		cout << "SRC : " << src << "    DEST : " << dest << endl;
                sprintf(query, "INSERT INTO `temp_log` (mac_addr) VALUES ('%s')", src);
                insertQuery(&pMysql, query);
		sprintf(query, "INSERT INTO `temp_log` (mac_addr) VALUES ('%s')", dest);
                insertQuery(&pMysql, query);

		/*flag = false;
		for(int i=0; i<row_num ; i++) if( !strcmp(mac_list[i], src) || !strcmp(mac_list[i], dest) ) {
			sprintf(query, "INSERT INTO `log` (mac_addr) VALUES ('%s')", mac_list[i]);
			if(mysql_real_query(&pMysql, query, strlen(query))){
         		       printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
         		       return 1;
        		}
			cout << "[*] Query injected : " << query << endl;
			flag = true;
		}
		if(!flag) {
			sprintf(query,"INSERT INTO `user` (name, mac_addr) VALUES ('Unknown', '%s')", 
		}*/
	}
	
	return 0;
}


bool isContain(std::vector<string> *mac_list, std::string comp) 
{
	if( std::find(mac_list->begin(), mac_list->end(), comp) != mac_list->end() ) return true;
	return false;
}

bool insertQuery(MYSQL *pMysql, char *query)
{	
	cout << "[*] Query injected : " << query << endl;
	if(mysql_real_query(pMysql, query, strlen(query))){
		printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(pMysql));  // Error Occured
              	return false;
        }
	return true;
}

void *timer(void *tmp)
{
	MYSQL pMysql = (MYSQL &)tmp;
	unsigned int cur, next;
	cur = (unsigned int)time(NULL);
	while(true)
	{
		next = (unsigned int)time(NULL);
		if((next - 10) == cur) {
			dataLogging(&pMysql);
		}
	}	
}

void dataLogging(MYSQL *pMysql)
{
	MYSQL_RES *res;
	MYSQL_FIELD *field;
        MYSQL_ROW row;
	char query[SQL_BUFSIZE];
	insertQuery(pMysql, "SELECT DISTINCT(mac_addr) from temp_log");
	res = mysql_store_result(pMysql);
	int field_num = mysql_num_fields(res);
        int row_num = mysql_num_rows(res);
	while((row = mysql_fetch_row(res))){
		sprintf(query, "INSERT INTO `log` (mac_addr) values ('%s')", row[0]);
		insertQuery(pMysql, query);
        }
}
