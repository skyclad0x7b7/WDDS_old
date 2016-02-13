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
#include <string>
#include <vector>
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


bool isContain(char **, char *, int);


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
	char **mac_list;

	if(!mysql_real_connect(&pMysql, "localhost", "ID", "PASSWD", "wdds_db", 3306, NULL, 0)){
    	    fprintf(stderr, "[*] Failed to Connect to the database : %s\n", mysql_error(&pMysql));
		return 1;
    	}

	if(mysql_real_query(&pMysql, sql_buf, strlen(sql_buf))){ 
                printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
               	return 1;
        }

	res = mysql_store_result(&pMysql);
	field_num = mysql_num_fields(res);
	row_num = mysql_num_rows(res);

	mac_list = (char **)malloc(row_num * sizeof(char *));
	
	cout << "[*] Saved MAC Address" << endl;
	cout << "Field_num : " << field_num << endl;
	tmp = 0;
	while((row = mysql_fetch_row(res))){                    // print rows
        	printf("|%17s|\n", row[0] ? row[0] : "NULL");
		mac_list[tmp] = (char *)malloc(18);
		strcpy(mac_list[tmp++], row[0] ? row[0] : "NULL");
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
		if(!isContain(mac_list, src, row_num)) {
			sprintf(query, "INSERT INTO `user` (name, mac_addr) VALUES ('Unknown', '%s')", src);
			if(mysql_real_query(&pMysql, query, strlen(query))){
                               printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
                               return 1;
                        }
                        cout << "[*] Query injected : " << query << endl;
		} else {
                        sprintf(query, "INSERT INTO `log` (mac_addr) VALUES ('%s')", src);
                        if(mysql_real_query(&pMysql, query, strlen(query))){
                               printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
                               return 1;
                        }
                        cout << "[*] Query injected : " << query << endl;
                }

		if(!isContain(mac_list, dest, row_num)) {
                        sprintf(query, "INSERT INTO `user` (name, mac_addr) VALUES ('Unknown', '%s')", dest);
                        if(mysql_real_query(&pMysql, query, strlen(query))){
                               printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
                               return 1;
                        }
                        cout << "[*] Query injected : " << query << endl;
                } else {
                        sprintf(query, "INSERT INTO `log` (mac_addr) VALUES ('%s')", dest);
                        if(mysql_real_query(&pMysql, query, strlen(query))){
                               printf("[*] An Error occured in mysql_real_query : %s\n", mysql_error(&pMysql));  // Error Occured
                               return 1;
                        }
                        cout << "[*] Query injected : " << query << endl;
                }

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
	
	for(int i=0; i<field_num; i++) free(row[i]);
	free(mac_list);
	return 0;
}


bool isContain(char **mac_list, char *comp, int row_num) {
	for(int i=0; i<row_num; i++) if(!strcmp(mac_list[i], comp)) return true;
	return false;
}
