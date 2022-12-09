#pragma once
#include <memory>
#include <cstdint>
#include <string>
// We need winsock for the timeval struct
#include <winsock.h>
#include <openssl/md5.h>
#include "EngineResources.h"

namespace Analyzer {

	/* Precondition: data is apointer to the data field of an ethernet frame, size_t is the 
	length of the packet in bytes, timestamp is the return of the ts value associated with the
	pcap_pktheader returned with the packet, and the packet's ethertype indicates it is an ARP
	message*/
	void examine_arp(const uint8_t* data, size_t length, timeval timestamp);

	/* Precondition: data is a pointer to the data field of an ethernet frame, size_t is the
	length of the packet in bytes including header, timestamp is the return of the ts value
	associated with the pcap_pktheader returned with the packet, and the packet's ethertype
	indicates it is an IPv4 message.
	   Postcondition: The packet is scanned for anomalies, and a security alert is raised for
	   very serious ones while less serious anomalies are logged as suspicious*/
	void examine_ipv4(const uint8_t* data, size_t length, timeval timestamp);

	/* Precondition: data is a pointer to the data field of an ethernet frame, size_t is the
	length of the packet in bytes including header, timestamp is the return of the ts value
	associated with the pcap_pktheader returned with the packet, and the packet's ethertype
	indicates it is an IPv6 message.
	   Postcondition: The packet is scanned for anomalies, and a security alert is raised for
	   very serious ones while less serious anomalies are logged as suspicious*/
	// void examine_ipv6(const uint8_t* data, size_t length, timeval timestamp);
}