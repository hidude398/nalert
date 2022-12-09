#include<cstdint>
#include<string>
#include<memory>
// Use the timeval primitive from winsock
#include <winsock.h>
#include <openssl/md5.h>

#include "DBConnect.h"
#include "AnalysisFunctions.h"

namespace Analyzer {
	void examine_ipv4(const uint8_t* data, size_t length, timeval timestamp) {
		// Immediately return when a packet is too short to contain even a complete IP_header
		if (length < 20) return;

		// Use a shared_ptr for smart passing to the logger
		size_t header_length;
		uint8_t protocol;
		uint32_t src = 0;
		std::shared_ptr<uint8_t> data_ptr;

		// Copy data out of the kernel buffer so that it is viable after the next call to pcap_next_ex():
		std::unique_ptr<uint8_t> packet (new uint8_t[length]);
		memcpy(packet.get(), data, length);

		// Find the length of the IP_Packet by masking the first byte with 0b00001111 to get only the
		// ihl and drop the version number
		header_length =  4 * size_t (packet.get()[0] & 0x0F);

		// Only set the data pointer if there is actually data in the packet. Otherwise, we can return here because
		// the packet contains no malicious information
		if (length > header_length) { 
			data_ptr = std::shared_ptr<uint8_t>(&packet.get()[header_length]);
		}
		else return;

		// Get source address
		for (int i = 12; i < 16; i++) {
			src += packet.get()[i];
			src = src << 8;
		}

		// Find the encapsulated protocol

		protocol = packet.get()[9];

		switch (protocol) {
			// Handle ICMP
		case 1:
			// Fire for ICMP Stuffing
			if (((length - header_length) > 42) && packet.get()[header_length] == 0) {
				// Storage for hash
				uint128_t hp = 0;
				// hash any data past the header
				MD5(&packet.get()[header_length + 42], (length - header_length - 42), (unsigned char*) &hp);
				DBConnect::getInstance()->fire_alert(timestamp, hp, 0x080001, (ip46mask | src));
			}
			return;
			break;
			// Handle TCP
		case 6:
			// TODO
			break;
			// Handle UDP
		case 17:
			// TODO
			break;
		} 
	}

	/*
	void examine_ipv6(const uint8_t* data, size_t length, timeval timestamp) {
		// TODO
		return;
	}
	*/

	void examine_arp(const uint8_t* data, size_t length, timeval timestamp) {
		// TODO
		// Check for arps from broadcast
		uint8_t hlen = data[4];
		uint8_t alen = data[5];

		// Test to see if the sender protocol address is ipv4 or ipv6

		// Test to see if the sender hardware address is the broadcast address
		if (data[7] == 0x02) {
			bool broadcast_huh = true;
			// broadcast_huh is only ever true if every octet of the hardware address corresponds with the broadcast address
			for (int i = 8; i < (8 + hlen); ++i) {
				if (data[i] == 0xFF) break;
				broadcast_huh = false;
			}
			if (broadcast_huh) {
				uint32_t ip = 0;
				// Arp only carried out over IPv4, gets an ip address
				for (int i = 0; i < alen; ++i) {
					ip += data[8 + hlen + i];
					ip = ip << 8;
				}
				DBConnect::getInstance()->fire_alert(timestamp, NULL, 0x080600, ip);
			}
		}
		return;
	}
}