#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <pcap.h>
#include <iostream>
//#include"EthArpPacket.h"

void MakeRequestPacket(struct EthArpPacket &_packet, std::string& _my_IP, std::string _my_mac, std::string _gatewayIP)
{
	EthArpPacket packet;

	// broad casting, my Mac
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(_my_mac.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);

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

	std::cout << "req done" << std::endl;
	_packet = packet;
}

