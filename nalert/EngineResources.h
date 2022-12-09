#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <ctime>
using namespace boost::multiprecision;

namespace Analyzer {
#define ip46mask 0x00000000000000000000FFFF00000000
	typedef uint128_t ipv6;
	typedef uint128_t md5;
	typedef time_t ts;

	struct Report {
		ts timestamp;
		ipv6 source_address;
		uint8_t L4_protocol;
		md5 data_hash;
	};
}