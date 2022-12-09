// ConsoleVersionOfNalert.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../nalert/Extractor.h"
#include <pcap.h>

int main()
{
    int userselect = NULL;
    int ctoken = 0;
    std::cout << "Starting analysis engine" << std::endl;
    pcap_if_t* devlist;
    char* errbuf = new char[PCAP_ERRBUF_SIZE];

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) == PCAP_ERROR) {
        std::cout << "Something went terribly wrong during initialization";
        return -1;
    };
    

    if (pcap_findalldevs(&devlist,errbuf) == PCAP_ERROR) {
        std::cout << "Something went terribly wrong during device lookup";
        return -1;
    }

    while (userselect == NULL) {
        std::cout << "Select an ethernet enabled device:" << std::endl;
    }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
