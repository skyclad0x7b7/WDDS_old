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
    	unsigned int field_num;
    	char buf[SQL_BUFSIZE] = {0};
    	mysql_init(&pMysql);
    	mysql_options(&pMysql, MYSQL_READ_DEFAULT_GROUP, "my_prog_name");
    	if(!mysql_real_connect(&pMysql, "localhost", "ID", "PASSWD", "wdds_db", 3306, NULL, 0)){
    	    fprintf(stderr, "[*] Failed to Connect to the database : %s\n", mysql_error(&pMysql));
    	}


	char errBuf[256];
	const u_char *data;
	pcap_pkthdr *pkthdr;
	BF_header bf_header;
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZE, 1, 10, errBuf);
    	
	if(handle == NULL){
        	fprintf(stderr, "Couldn't open device %s : %s\n",  argv[1], errBuf);
        	return 1;
   	}

	while(true) {	

		int res = pcap_next_ex(handle, &pkthdr, &data);

		if(res == 0) continue;
		if(res < 0) break;
	
		data += *(u_int16_t *)(data+2); // Skip Radiotap Header
		memcpy(&bf_header, data, 0x18);
		if(bf_header.frame_control != 0x0050) continue;
		fprintf(stdout, "BSS : %02X:%02X:%02X:%02X:%02X:%02X    ", bf_header.bss[0], bf_header.bss[1], bf_header.bss[2], bf_header.bss[3], bf_header.bss[4], bf_header.bss[5]);
		fprintf(stdout, "SRC : %02X:%02X:%02X:%02X:%02X:%02X    ", bf_header.src[0], bf_header.src[1], bf_header.src[2], bf_header.src[3], bf_header.src[4], bf_header.src[5]);
		fprintf(stdout, "DEST : %02X:%02X:%02X:%02X:%02X:%02X\n", bf_header.dest[0], bf_header.dest[1], bf_header.dest[2], bf_header.dest[3], bf_header.dest[4], bf_header.dest[5]);
	}
	
	return 0;
}
