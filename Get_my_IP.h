#include<stdio.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<string.h>
#include<arpa/inet.h>
#include<string>
#include<iostream>

void Get_my_IP(std::string & _my_IP, std::string & _my_mac)
{
	struct ifreq ifr;
	char ipstr[40];
	char macstr[40];

	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

	if(ioctl(s,SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error");
	}
	else
	{
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				ipstr, sizeof(struct sockaddr));
		//printf("my IP address : %s\n"ipstr);
	}

	uint8_t my_mac_func[6];
	if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Error");
	}
	else
	{
		//macstr = ether_ntoa(AF_INET, ifr.ifr_addr.sa_data);
		memcpy(my_mac_func, ifr.ifr_addr.sa_data, 6);
		sprintf(macstr, "%02X:%02X:%02X:%02X:%02X:%02X",
				my_mac_func[0], my_mac_func[1],
				my_mac_func[2], my_mac_func[3],
				my_mac_func[4], my_mac_func[5]);
	}
	
	_my_mac = std::string(macstr);
	//printf("%s\n", macstr);
	std::cout <<"my mac : " << _my_mac << std::endl;

	_my_IP = std::string(ipstr);
	std::cout <<"my IP : " << _my_IP << std::endl;
	
}
