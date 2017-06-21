/* dns.h
* CSCE 613 - 600 Spring 2017
* HW2 dns_server
* by Mian Qin
*/

/***  Acknowledgment   ***/
/*
* From homework pdf
*
*/

#ifndef   _dns_h_   
#define   _dns_h_

#include "stdafx.h"

#define TIMEOUT 10
#define MAX_DNS_RESPONSE_SIZE  512	// largest valid UDP packet 
#define MAX_ATTEMPTS    3			// largest attempt
#define USHORT unsigned short
#define UBYTE unsigned char

/* DNS query types */
#define DNS_A    1    /* name -> IP */ 
#define DNS_NS   2    /* name server */ 
#define DNS_CNAME  5    /* canonical name */ 
#define DNS_PTR  12    /* IP -> name */
#define DNS_HINFO  13    /* host info/SOA */ 
#define DNS_MX   15    /* mail exchange */ 
#define DNS_AXFR  252    /* request for zone transfer */ 
#define DNS_ANY  255    /* all records */ 

/* query classes */
#define DNS_INET  1 

/* flags */
#define DNS_QUERY		(0 << 15)		/* 0 = query; 1 = response */ 
#define DNS_RESPONSE	(1 << 15)
#define DNS_STDQUERY	(0 << 11)		/* opcode - 4 bits */ 
#define DNS_AA			(1 << 10)		/* authoritative answer */
#define	DNS_TC			(1 << 9)		/* truncated */
#define DNS_RD			(1 << 8)		/* recursion desired */
#define DNS_RA			(1 << 7)		/* recursion available */

#define DNS_OK			0		/* success */ 
#define DNS_FORMAT		1		/* format error (unable to interpret) */ 
#define DNS_SERVERFAIL	2		/* can¡¯t find authority nameserver */ 
#define	DNS_ERROR		3		/* no DNS entry */
#define DNS_NOTIMPL		4		/* not implemented */
#define DNS_REFUSED		5		/* server refused the query */ 

#pragma pack(push,1)     // sets struct padding/alignment to 1 byte 
class QueryHeader {
	public:
		USHORT qType;
		USHORT qClass;
};

class FixedDNSheader {
	public:
		USHORT ID;
		USHORT flags;
		USHORT questions;
		USHORT answers;
		USHORT Authority;
		USHORT Additional;
};
#pragma pack(pop)		// restores old packing

#pragma pack(push, 1)		// sets struct padding/alignment to 1 byte
class FixedRR {
	public:
		USHORT qT;
		USHORT qC;
		int TTL;
		USHORT dataLen;
};
#pragma pack(pop)			// restores old packing

typedef enum {A, PTR} QueryType;

class JumpAddrSet
{
public:
	unordered_set<int> JumpAddr;
	int prevSize;

	JumpAddrSet(void)
	{
		prevSize = 0;
	}
};

void DNSQueryConstructor(char *sendBuf, int pktSize, char *StrQuery, int TxID, QueryType queryType);

bool ReverseIPField(char *src, char *dst);

bool ParseName(char *recvBuf, int recvBytes, char **strBuf, UBYTE *ans, int *curPos);

bool PrintRecord(char *recvBuf, int recvBytes, int *curPos);

#endif