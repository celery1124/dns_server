/* main.cpp
* CSCE 613-600 Spring 2017 
* HW2 dns_server
* by Mian Qin
*/

#include "stdafx.h"
#include "dns.h"
//#include "vld.h"
void print_usage() {
	printf("Usage : dns_server.exe hostname/IP DNS server IP\n");
	printf("Example : dns_server.exe celery1124.com 8.8.8.8\n");
	printf("     or : dns_server.exe 45.78.23.8 8.8.8.8\n");
}

bool InitialWinsock()
{
	WSADATA wsaData;
	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return false;
	}
	return true;
}

void CleanWinsock()
{
	WSACleanup();
}


int main(int argc, char* argv[])
{
	int ret;
	char *StrQuery;
	char *StrDNSSeverIP;
	USHORT TxID = 0;
	int count = 0;

	QueryType queryType;
	/* check input argument */
	if (argc != 3) 
	{
		printf("wrong number of argument \n");
		print_usage();
		return 0;
	}
	// legal argument format
	else 
	{
		if (inet_addr(argv[2]) == INADDR_NONE)
		{
			printf("please input the correct DNS server IP \n");
			print_usage();
			return 0;
		}
	}

	/* initial winsock */
	if ((ret = InitialWinsock()) == false)
		return 0;

	/* Query Constructor */
	StrQuery = (char *)malloc(strlen(argv[1]) + 1);
	memcpy(StrQuery, argv[1], strlen(argv[1]));
	StrQuery[strlen(argv[1])] = '\0';
	StrDNSSeverIP = argv[2];
	// decide query type
	if (inet_addr(StrQuery) == INADDR_NONE)
	{
		queryType = A;
	}
		
	else
	{
		char *strSrc = StrQuery; // for ip field filp need to be writeable
		StrQuery = (char *)malloc(strlen(argv[1]) + 13 + 1); // add ".in-addr.arpa"
		StrQuery[strlen(argv[1]) + 13] = '\0';
		if (ReverseIPField(strSrc, StrQuery) == false)
			return 0;

		free(strSrc);
		queryType = PTR;
	}	

	// report infomation
	printf("Lookup: %s\n", argv[1]);
	printf("Query : %s, type %d, TXID %.4x\n",StrQuery, (queryType == A?DNS_A : DNS_PTR),TxID);
	printf("Server : %s\n", StrDNSSeverIP);
	printf("********************************\n");

	int pktSize = strlen(StrQuery) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
	char *sendBuf = NULL;
	sendBuf = (char *)malloc(pktSize);
	memset(sendBuf, 0, pktSize);

	DNSQueryConstructor(sendBuf, pktSize, StrQuery, TxID, queryType);
	free(StrQuery);

	/* Send DNS query packet to server */
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("  socket error: %ld\n", WSAGetLastError());
		CleanWinsock();
		return 0;
	}
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
	{
		printf("  socket error: %ld\n", WSAGetLastError());
		CleanWinsock();
		return 0;
	}

	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(StrDNSSeverIP);
	remote.sin_port = htons(53);

		while (count++ < MAX_ATTEMPTS)
		{
			printf("Attempt %d with %d bytes... ", count - 1, pktSize);
			if (sendto(sock, sendBuf, pktSize, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
			{
				printf("  socket error: %ld\n", WSAGetLastError());
				CleanWinsock();
				return 0;
			}

			/* Receive DNS server responds */
			char recvBuf[MAX_DNS_RESPONSE_SIZE];
			struct sockaddr_in response;
			int responseSize = sizeof(response);
			clock_t time_elapse;
			// set timeout to 10 seconds
			const timeval timeout = { TIMEOUT,0 };
			fd_set fd;
			FD_ZERO(&fd);       // clear the set 
			FD_SET(sock, &fd);   // add your socket to the set 

			time_elapse = clock();
			int recvBytes;
			if ((ret = select(0, &fd, NULL, NULL, &timeout)) > 0)
			{
				recvBytes = recvfrom(sock, recvBuf, MAX_DNS_RESPONSE_SIZE, 0, (SOCKADDR *)&response, &responseSize);

				// check packet size
				if (recvBytes == SOCKET_ERROR)
				{
					printf("  socket error %ld\n", WSAGetLastError());
					return 0;
				}
				else if (recvBytes < sizeof(FixedDNSheader))
				{
					printf("\n  ++\tinvalid reply: smaller than fixed header\n");
					break;
				}
				else if (recvBytes > MAX_DNS_RESPONSE_SIZE)
				{
					printf("\n  ++\tinvalid reply: exceed maximum response packet size\n");
					break;
				}

				FixedDNSheader *fdh = (FixedDNSheader *)recvBuf;
				if ((ntohs(fdh->flags)  & 0x8000) == 0)
				{
					printf("\n  ++\tinvalid reply: Fixed header error not a response message\n");
					break;
				}
				printf("response in %d ms with %d bytes\n", clock() - time_elapse, recvBytes);
				printf("  TXID %.4x flags %.4x questions %d answers %d authority %d additional %d\n",
					ntohs(fdh->ID), ntohs(fdh->flags), ntohs(fdh->questions), ntohs(fdh->answers), ntohs(fdh->Authority), ntohs(fdh->Additional));

				if (ntohs(fdh->ID) != TxID)
				{
					printf("  ++\tinvalid reply: TXID mismatch, sent %.4x, received %.4x", TxID, ntohs(fdh->ID));
					return 0;
				}

				/* parse the response  */
				// check if this packet came from the server to which we sent the query earlier 
				if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port)
				{
					printf("  ++\tinvalid reply: packet didn't come from DNS server\n");
					break;
				}


				// check Rcode
				if ((ntohs(fdh->flags) & 0x000F) != DNS_OK)
				{
					printf("  failed with Rcode = %d\n", (ntohs(fdh->flags) & 0x000F));
					break;
				}
				else
					printf("  succeeded with Rcode = %d\n", DNS_OK);

				int curPos = sizeof(FixedDNSheader);
				// print questions
				for (int i = 0; i < ntohs(fdh->questions); i++)
				{
					if (i == 0)
						printf("  ------------ [questions] ----------\n");
					UBYTE *ans = (UBYTE *)(recvBuf + curPos);
					char *strBuf = NULL;
					if (ParseName(recvBuf, recvBytes, &strBuf, ans, &curPos) == true)
					{
						printf("  \t%s", strBuf);
						free(strBuf);
					}
					else
					{
						if (strBuf != NULL)
							free(strBuf);
						return 0;
					}

					QueryHeader *qh = (QueryHeader *)(recvBuf + curPos);
					printf(" type %d class %d\n", ntohs(qh->qType), ntohs(qh->qClass));
					curPos += sizeof(QueryHeader);
				}


				// print answers
				for (int i = 0; i < ntohs(fdh->answers); i++)
				{
					if (i == 0)
						printf("  ------------ [answers] ------------\n");
					// check not enough records error
					if (curPos == recvBytes)
					{
						printf("  ++\tinvalid section: not enough records\n");
						return 0;
					}
					if (PrintRecord(recvBuf, recvBytes, &curPos) == false)
						return 0;
				}

				// print authority
				for (int i = 0; i < ntohs(fdh->Authority); i++)
				{
					if (i == 0)
						printf("  ------------ [authority] ------------\n");
					// check not enough records error
					if (curPos == recvBytes)
					{
						printf("  ++\tinvalid section: not enough records");
						return 0;
					}
					if (PrintRecord(recvBuf, recvBytes, &curPos) == false)
						return 0;
				}

				// print additional
				for (int i = 0; i < ntohs(fdh->Additional); i++)
				{
					if (i == 0)
						printf("  ------------ [additional] ------------\n");
					// check not enough records error
					if (curPos == recvBytes)
					{
						printf("  ++\tinvalid section: not enough records\n");
						return 0;
					}
					if (PrintRecord(recvBuf, recvBytes, &curPos) == false)
						return 0;
				}

				// break from the loop 
				break;
			}
			else if (ret == 0) {
				// report timeout 
				printf("timeout in %d ms\n", clock() - time_elapse);
			}
			else {
				printf("  socket error: %ld\n", WSAGetLastError());
			}
		}
	
	free(sendBuf);
	/* Cleanning Winsock */
	CleanWinsock();

	//printf("\ntime elapsed:%d ms\n", (int)(end_t - start_t));

	return 0;
}
