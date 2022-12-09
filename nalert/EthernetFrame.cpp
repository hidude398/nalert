#include <pcap/pcap.h>
#include <array>

#include "EthernetResources.h"

namespace layer_two {

	// Here we assign the data pointer of the EthernetFrame class to be the
	//     length of the captured data, and then copy the values of the data
	//     data received from the capture into the EthernetFrame
	EthernetFrame::EthernetFrame(pcap_pkthdr* cap_head, uint8_t* data_in) {
		// If the capture has no fragments of FCS, copy normally. Otherwise, if the last 4 chars are the FCS, drop them
		if (cap_head->len - cap_head->caplen >= 4) {
			len = cap_head->caplen;
			data = new uint8_t[len];
			std::memcpy(data, data_in, len);
		} else {
			// When the actual length - captured length <4, make sure to drop any remaining bytes of the FCS.
			len = cap_head->caplen - (4 - (cap_head->len - cap_head->caplen));
			data = new uint8_t[len];
			std::memcpy(data, data_in, len);
			
		}
	}

	// Here we free the held memory when the class is destroyed
	EthernetFrame::~EthernetFrame() {
		delete data;
	}

	// Here, we return the first 6 characters of the data, which is a destination
	//    Mac address
	std::array<uint8_t, 6> EthernetFrame::get_dest_addr() {
		std::array<uint8_t, 6> returnValue;
		// Returns the first set of 6 chars
		std::memcpy(returnValue.data(), data, 6);
		return returnValue;
	}

	// Here, we return the next 6 characters of the data, which is a source
	//     Mac address
	std::array<uint8_t, 6> EthernetFrame::get_srce_addr() {
		std::array<uint8_t, 6> returnValue;
		// Returns the 2nd set of 6 chars
		std::memcpy(returnValue.data(), data + 6, 6);
		return returnValue;
	}

	layer_three::L3_Packet* EthernetFrame::get_payload() {
		
	}


}