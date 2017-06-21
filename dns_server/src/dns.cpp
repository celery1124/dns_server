/* dns.c
* CSCE 613 - 600 Spring 2017
* HW2 dns_server
* by Mian Qin
*/
#include "dns.h"

bool ReverseIPField(char *src, char *dst)
{
	int dst_offset = 0;
	char *dot_mark;
	for (int i = 0; i < 3; i++)
	{
		if ((dot_mark = strrchr(src, '.')) == NULL)
		{
			printf("bad IP address format\n");
			return false;
		}
		
		else
		{
			memcpy(dst + dst_offset, dot_mark + 1, src + strlen(src) - dot_mark - 1);
			dst_offset += src + strlen(src) - dot_mark ;
			dst[dst_offset-1] = '.';
			*dot_mark = '\0';
		}
	}
	memcpy(dst + dst_offset, src, strlen(src));
	dst_offset += strlen(src);
	memcpy(dst + dst_offset, ".in-addr.arpa", 13);
	return true;
}

void DNSQueryConstructor(char *sendBuf, int pktSize, char *StrQuery, int TxID, QueryType queryType)
{
	FixedDNSheader *fdh = (FixedDNSheader *)sendBuf;
	QueryHeader *qh = (QueryHeader*)(sendBuf + pktSize - sizeof(QueryHeader));

	// fixed field initialization 
	fdh->ID = htons(TxID);
	fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	fdh->questions = htons(1);

	// query string
	UBYTE wordSize;
	char *queryBuf = sendBuf + sizeof(FixedDNSheader);
	char *dotMark;
	while (*StrQuery != NULL)
	{
		if ((dotMark = strchr(StrQuery, '.')) != NULL)
			wordSize = dotMark - StrQuery;
		else
			wordSize = strlen(StrQuery);
		*queryBuf = wordSize;
		memcpy(queryBuf + 1, StrQuery, wordSize);
		queryBuf += wordSize + (dotMark != NULL);
		StrQuery += wordSize + (dotMark != NULL);
	}
	// query field initialization 
	qh->qType = htons(queryType == A ? DNS_A : DNS_PTR);
	qh->qClass = htons(DNS_INET);
}

bool ParseName(char *recvBuf, int recvBytes, char **strBuf, UBYTE *ans, int *curPos)
{
	bool firstJump = true;
	int jumpOffset;
	JumpAddrSet SeenJumpAddr;
	while (1)
	{
		if (*ans == 0)
		{ // stop
			if (firstJump)
				*curPos += 1;
			break;
		}
		if (*ans >= 0xC0)
		{ // compressed
			if (firstJump)
			{
				*curPos += 2;
				firstJump = false;
			}
			// check Jump offset truncated error
			if (ans + 1 > (UBYTE *)(recvBuf + recvBytes - 1))
			{
				printf("  ++\tinvalid record: truncated jump offset\n");
				return false;
			}
			// check jump beyond packet boundary error 
			jumpOffset = ((*ans & 0x3F) << 8) + *(ans + 1);
			if (jumpOffset > recvBytes - 1)
			{
				printf("  ++\tinvalid record: jump beyond packet boundary\n");
				return false;
			}
			// check jump into fixed header error
			else if (jumpOffset <= sizeof(FixedDNSheader) - 1)
			{
				printf("  ++\tinvalid record: jump into fixed header\n");
				return false;
			}
			else
			{
				ans = (UBYTE *)(recvBuf + jumpOffset);
			}

			// check jump address uniqueness (avoid infinite loop)
			SeenJumpAddr.JumpAddr.insert(jumpOffset);
			if (SeenJumpAddr.JumpAddr.size() > SeenJumpAddr.prevSize)
			{ // unique jump address
				SeenJumpAddr.prevSize++;
			}
			else
			{
				printf("  ++\tinvalid record: jump loop\n");
				return false;
			}
		}
		else
		{ // uncompressed
			if (firstJump)
			{
				*curPos += *ans + 1;
			}
			// check Truncated name error
			if (ans + *ans + 1 > (UBYTE *)(recvBuf + recvBytes - 1))
			{
				printf("  ++\tinvalid record: truncated name\n");
				return false;
			}
			if (*strBuf == NULL)
			{
				*strBuf = (char *)malloc((*ans) + 1);
				(*strBuf)[*ans] = '\0';
				memcpy(*strBuf, ans + 1, *ans);
			}
			else
			{
				int orig_len = strlen(*strBuf);
				*strBuf = (char *)realloc(*strBuf, orig_len + (*ans) + 2);
				(*strBuf)[orig_len + (*ans) + 1] = '\0';
				(*strBuf)[orig_len] = '.';
				memcpy(*strBuf + orig_len + 1, ans + 1, *ans);
			}
			ans += (*ans) + 1;
		}
	}
	return true;
}

bool PrintRecord(char *recvBuf, int recvBytes, int *curPos)
{
	UBYTE *ans = (UBYTE *)(recvBuf + *curPos);
	char *strBuf = NULL;

	if (ParseName(recvBuf, recvBytes, &strBuf, ans, curPos) == false)
		return false;

	// check Truncated fixedRR error
	if ((*curPos + sizeof(FixedRR)) > recvBytes - 1)
	{
		printf("  ++\tinvalid record: truncated fixed RR header\n");
		return false;
	}
	FixedRR *frr = (FixedRR *)(recvBuf + *curPos);
	*curPos += sizeof(FixedRR);
	// check RR value length beyond packet error
	if (*curPos + ntohs(frr->dataLen) > recvBytes)
	{
		printf("  ++\tinvalid record: RR value length beyond packet\n");
		return false;
	}

	if (ntohs(frr->qT) == DNS_A)
	{
		if (ntohs(frr->dataLen) != 4)
		{
			printf("  +++\tinvalid record:wrong length field\n");
			return false;
		}
		in_addr *recordA;
		recordA = (in_addr *)(recvBuf + *curPos);
		*curPos += ntohs(frr->dataLen);
		printf("  \t%s ", strBuf);
		printf("type A %s TTL = %d\n", inet_ntoa(*recordA), ntohl(frr->TTL));
	}
	else if (ntohs(frr->qT) == DNS_NS || ntohs(frr->qT) == DNS_CNAME || ntohs(frr->qT) == DNS_PTR)
	{
		UBYTE *ans = (UBYTE *)(recvBuf + *curPos);
		char *strBuf2 = NULL;
		if (ParseName(recvBuf, recvBytes, &strBuf2, ans, curPos) == false)
			return false;
		else
		{
			switch (ntohs(frr->qT))
			{
			case DNS_NS: printf("  \t%s ", strBuf);
				printf("type NS %s TTL = %d\n", strBuf2, ntohl(frr->TTL));
				break;
			case DNS_CNAME: printf("  \t%s ", strBuf);
				printf("type CNAME %s TTL = %d\n", strBuf2, ntohl(frr->TTL));
				break;
			case DNS_PTR: printf("  \t%s ", strBuf);
				printf("type PTR %s TTL = %d\n", strBuf2, ntohl(frr->TTL));
				break;
			default:
				break;
			}
			if (strBuf != NULL)
				free(strBuf2);
		}

	}
	else
	{
		*curPos += ntohs(frr->dataLen);
	}
	if (strBuf != NULL)
		free(strBuf);
	return true;
}