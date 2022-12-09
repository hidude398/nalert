#pragma once
#include <pcap.h>
#include <array>
#include <stdint.h>
#include <cstddef>
#include <boost/dynamic_bitset.hpp>
#include "NetworkLayerResources.h"

namespace layer_two {

	

	class EthernetFrame {
	public:
		// Precondition: Takes a pcap_pkthdr struct and an array of data from a npcap capture
		// Postcondition: Produces an EthernetFrame which has different methods for accessing
		//     different parts of the ethernet frame for decapsulation
		EthernetFrame(pcap_pkthdr* cap_head, uint8_t* data);

		// Precondition: Is called from an instance of an EthernetFrame
		// Postcondition: The associated memory of that class is freed
		~EthernetFrame();

		// Precondition: an EthernetFrame exists
		// Postcondition: Returns the destination address
		std::array<uint8_t, 6> get_dest_addr();

		// Precondition: an EthernetFrame exists
		// Postcondition: Returns the source address as a 6 value std::Array
		std::array<uint8_t, 6> get_srce_addr();

		layer_three::L3_Packet* get_payload();

	private:
		uint8_t* data;
		std::size_t len;
	};

	

} // Close namespace layer_two