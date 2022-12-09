#pragma once
// Library imports
extern "C" {
#include <pcap.h>
}

#include <iostream>
#include <memory>
#include <thread>
#include <stop_token>
#include <stdexcept>
#include <string>

#include "AnalysisFunctions.h"
#include "EngineResources.h"


namespace Analyzer {
	class Extractor {
	public:
		/* Precondition: i_adapter is a pcap_if_t pointer obtained from the findalldevs
		   method, and the pcap_init() method has been called.
		   Postcondition: The adapter private variable is set to hold the value of the 
		   i_adapter, and it is created with pcap_create(). Once the adapter has been
		   created, it is activated and the analysis thread is started. The thread will
		   run until the object is destroyed. */
		Extractor(pcap_if_t* i_adapter);

		/* Precondition: N/A
		   Postcondition: The analysis_thread is stopped and joined, then the pcap_t pointer is deleted.*/
		~Extractor(); 

		/* Precondition: The extractor instance exists
		   Postcondition: The analysis thread is started and runs until either the class
		   destructor is called or until t_stop() is called. */
		void t_start();

		/* Precondition: The extractor instance exits and analysis_thread exists and is running
		   Postcondition: The analysis thread is requested to stop and joined with the calling thread */
		void t_stop();

	private:
		void analyze(std::stop_token token);
		pcap_t* adapter;
		std::jthread analysis_thread;
	};
}