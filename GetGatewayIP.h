#include<string>
#include<vector>
#include<pcap.h>
#include"ethhdr.h"
#include"arphdr.h"

void GetGatewayIP(std::string & _gatewayIP)
{
	FILE * fp;
        fp = popen("route", "r");

#define BUFF_SIZE 1024
        char buff[4][BUFF_SIZE];
        
	int j = 0;
        while(fgets(buff[j], BUFF_SIZE, fp)!=NULL)
        	//printf("%s", buff[j++]);
		j++;
	
	//printf("\n%s\n", buff[2]);
        char*ptr = strtok(buff[2], " ");
        char * route_infos[50] = {NULL};
        int i = 0;
        
	while (ptr != NULL)               
        {
               // printf("%s\n", ptr);
                route_infos[i] = ptr;
                ptr = strtok(NULL, " ");
                i++;
        }

	//printf("\nroute infos : %s\n", route_infos[1]);
	_gatewayIP = std::string(route_infos[1]);
}
