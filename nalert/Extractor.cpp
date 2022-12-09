// Library imports
#include <iostream>
#include <memory>
#include <thread>
#include <stop_token>
#include <stdexcept>
#include <string>

extern "C" {
#include <pcap.h>
}

// Include header of class being defined
#include "Extractor.h"

#include "AnalysisFunctions.h"
#include "EngineResources.h"

namespace Analyzer {

	/* Constructor for an instance of Extractor. Takes a pcap_if_t pointer, which points
	to an interface capable of capturing packets off of an ethernet line. Using this
	pointer, it activates that adapter as a pcap_t object and stores it in the class.*/
	Extractor::Extractor(pcap_if_t* i_adapter) {
		std::string error;
		// Set private adapter to at address corresponding to network interface
		char* errbuf = new char[PCAP_ERRBUF_SIZE];
		// RAII for the network interface. Acquires the interface, aborting construction on fail
		adapter = pcap_create(i_adapter->name, errbuf);
		if (adapter == nullptr) {
			error = errbuf;
			throw std::runtime_error("An error was encountered while attempting to access the network interface: " + error);
		}
		delete[PCAP_ERRBUF_SIZE] errbuf;
	}

	

	void Extractor::t_stop() {
		// Stop the thread if is running
		if (analysis_thread.joinable()) analysis_thread.join();
		// Close the adapter
		pcap_close(adapter);
	}

	// Free the adapter from memory
	Extractor::~Extractor() {
		if (analysis_thread.joinable()) analysis_thread.join();
		pcap_close(adapter);
		delete adapter;
	}

	void Extractor::analyze(std::stop_token token) {
		int rv;
		// errcount holds the consecutive read errors
		int errcount = 0;
		/* lenmod is used when calculating the lenght of the data portion of an 
		   ethernet frame to avoid passing the FCS */
		int lenmod = 0;
		// The index is used to locate the FCS, or the 802.1Q tag
		unsigned int index = 12;
		// The pcap_pkthdr pointer points to a structure containing the timestamp, length, and line length of the data
		pcap_pkthdr* head;
		// Self explanatory - points to data
		const u_char** data = NULL;
		// Used to form a switch statement to help figure out what is contained in an ethernet data frame.
		uint16_t etherType;
		do {
			// Analysis engine code goes here.

			// Get next packet from system queue
			rv = pcap_next_ex(adapter, &head, data);
			// Log errors, return after 5 consecutive errors.
			if (rv == PCAP_ERROR) {
				++errcount;
				break;
			}
			else if (rv == 0) {
				break;
			}
			if (errcount == 5) return;
			// If 5 recurring errors don't happen, set the error counter back to 0.
			errcount = 0;
			/* Detection of IEEE 802.1Q Frame Tag or IEEE 802.1ad Double Frame Tag
			 * If present, advance index to location of EtherType in frame. Otherwise,
			 * index already is located at EtherType */

			// Data will not be null here because it is being manipulated by pcap_next_ex or the loop breaks
			if ((*data[index] == 0x81) && (*data[index + 1] == 0x00)) {
				index = 14;
			}
			else if ((*data[index] == 0x88) && (*data[index + 1] == 0xA8)) {
				index = 16;
			}

			// Set lenmod based on the value of the line and capture length to drop FCS
			if (head->len - head->caplen < 4) {
				lenmod = head->len - 4 - (head->len - head->caplen);
			}

			/* Reading the EtherType of data from the index, not the fixed frame position to
			 * ensure that frame tags are skipped */
			etherType = *data[index];
			etherType = etherType << 8;
			etherType += *data[index + 1];

			switch (etherType) {
			// IPv4 Over Ethernet
			case 0x0800:
				// TODO: IPV4 Handler
				examine_ipv4(&(*data[index+2]), lenmod, head->ts);
				break;
			// ARP over Ethernet
			case 0x0806:
				// TODO: ARP Handler
				examine_arp(&(*data[index + 2]), lenmod, head->ts);
				break;
			// IPv6 Over Ethernet
			/*case 0x86DD:
				// TODO: IPV6 Handler
				examine_ipv6(&(*data[index+2]), lenmod, head->ts);
				break; */
			}

		} while (!token.stop_requested());
		return;
	}

	void Extractor::t_start() {
		// Activates the adapter to begin capture
		int n = pcap_activate(adapter);
		// Throw an error if pcap_activate fails
		if (n < 0) {
			std::string error = pcap_geterr(adapter);
			throw std::runtime_error("An error was encountered while attempting to activate the network interface: " + error);
		}
		// Here, we pass stop_token() out of the regular order in which Jthread passes it because we need to
		// make sure that the jthread instance utilizes the Extractor class instance when invoking Extractor::analyze by pointer
		analysis_thread = std::jthread(&Extractor::analyze, this, std::stop_token());
	}
}