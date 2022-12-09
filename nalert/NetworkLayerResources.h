#pragma once

namespace layer_three {

	// List the network layer protocols this software is capable of handling
	enum protocol{
		ipv4 = 0x0800,
		arp = 0x0806,
		ipv6 = 0x86DD};

	// Generic return type which can hold the frame payload of an ethernet frame.
	class L3_Packet {
		// Constructor which takes a packet of some network variety and the protocol type.
		// Precondition: idata is a pointer to a network-layer packet after decapsulation and pname
		//     is of type 'protocol' and contains the protocol carried by the frame.
		L3_Packet(uint8_t* idata, protocol pname);

		// Destructor which frees memory to prevent leaks.
		~L3_Packet() {
			delete data;
		}

	private:
		uint8_t* data;
		protocol ptype;
	};




}