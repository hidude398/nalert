#pragma once
#include <mysqlx/xdevapi.h>
#include <winsock.h>
#include "EngineResources.h"
#include <string>
#include <time.h>

namespace Analyzer {
	class DBConnect {
	private:
		// converts a time struct into a timestamp
		static std::string maketime (const tm* timevalue) {
			std::string rt;
			rt += timevalue->tm_year + 1900;
			rt += '-';
			rt += timevalue->tm_mon + 1;
			rt += '-';
			rt += timevalue->tm_mday;
			rt += ' ';
			rt += timevalue->tm_hour;
			rt += ':';
			rt += timevalue->tm_min;
			rt += ':';
			rt += timevalue->tm_sec;
			return rt;
		}

		// Stores singleton
		static std::shared_ptr<DBConnect> obj;
		// private constructor to force use of getInstance() to create Singleton object
		DBConnect() {}
	public:
		// Singleton accessor
		static std::shared_ptr<DBConnect> getInstance()
		{
			// If the singleton doesn't exist, make it
			if (obj == NULL) obj = std::make_shared<DBConnect>(new DBConnect());
			// Return a shared pointer to the DBConnect class.
			return obj;
		}

		// Fires an alert if the database is alive.
		void fire_alert(timeval tstamp_raw, uint128_t hash, uint64_t protocol_num, uint128_t src) 
		{
			tm* meantime;
			gmtime_s(meantime, (time_t*) tstamp_raw.tv_sec);

			std::string time;
			std::cout << "Logged suspicious activity - " << maketime(meantime) << " \nData Hash: "
				<< hash << "\nProtocol: " << protocol_num << "\nSource Address: " << src;
		}

	};
}