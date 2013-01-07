#define NET_SERVER_2000
//#define ALPHA

#include <conio.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>

#include <stdio.h>
#include <time.h>

#include <string>
//#include <iostream>

using namespace std;

#include "RawSock.h"
#include "Console.h"
#include "Socket.h"
#include "resource.h"

CRITICAL_SECTION critsect;

#define CONSOLE_WIDTH 140

static string sCurrPacket = "";
static bool	  bNewPacket = true;

unsigned __stdcall Connection(void* a) 
{
	Socket* s = (Socket*) a;
	if (a == NULL)
		return SOCKET_ERROR;
	while (1)
	{
		if (bNewPacket)
		{
			EnterCriticalSection(&critsect);

			s->SendLine(sCurrPacket+(char)13+(char)10);
			bNewPacket = false;

			LeaveCriticalSection(&critsect);
		}
	}

	delete s;
	return 0;
}

unsigned __stdcall AcceptConnections(void* a) 
{
	SocketServer in(2000, 20);
  
	while (1) 
	{
		Socket* s = in.Accept();

		unsigned ret;
		_beginthreadex(0, 0, Connection, (void*)s, 0, &ret);
	}
}


/*
*  Выделение пакета цветом
*/
void ColorPacket(const IPHeader *h, const u_long haddr, const u_long whost = 0)
{
	if (h->xsum)
		SetConsoleTextColor(0x17); // если пакет не пустой
	else
		SetConsoleTextColor(0x07); // пустой пакет

	if (haddr == h->src)		 
	{
		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/ 
			FOREGROUND_RED | FOREGROUND_INTENSITY); // "родной" пакет на отдачу
	}
	else if (haddr == h->dest)		 
	{
		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/ 
			FOREGROUND_GREEN | FOREGROUND_INTENSITY); // "родной" пакет на прием
	}

	if (h->protocol == PROT_ICMP || h->protocol == PROT_IGMP)		 
	{
		SetConsoleTextColor(0x70); // ICMP-пакет 
	}
	else if(h->protocol == PROT_IP || h->protocol == 115)
	{
		SetConsoleTextColor(0x4F); // IP-in-IP-пакет, L2TP
	}
	else if(h->protocol == 53 || h->protocol == 56)
	{
		SetConsoleTextColor(0x4C); // TLS, IP with Encryption
	}

	if(whost == h->dest || whost == h->src)
	{
		SetConsoleTextColor(0x0A);
	}
}

/*
*  Печать легенды цветов пакетов
*/
void ShowLegend()
{
		SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY | 
			BACKGROUND_GREEN | BACKGROUND_BLUE);
		printf("Legend\t\t\t\n");
		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/ 
			FOREGROUND_GREEN | FOREGROUND_INTENSITY); // "родной" пакет на прием
		printf("\nPacket FOR this host\t\n");
		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/ 
			FOREGROUND_RED | FOREGROUND_INTENSITY); // "родной" пакет на отдачу
		printf("Packet FROM this host\t\n");
		SetConsoleTextColor(0x17); // если пакет не пустой
		printf("Any non-empty packet\t\n");
		SetConsoleTextColor(0x07); // пустой пакет
		printf("Any empty packet\t\n");
		SetConsoleTextColor(0x70); // ICMP-пакет 
		printf("ICMP packet\t\t\n");
		SetConsoleTextColor(0x4F); // IP-in-IP-пакет
		printf("IP-in-IP packet, L2TP\t\n");
		SetConsoleTextColor(0x4C); // TLS, IP with Encryption
		printf("TLS, IP with Encryption\t\n");
		SetConsoleTextColor(0x0A); // TLS, IP with Encryption
		printf("Watched host packets\t\n");
}



void ShowHelp()
{
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("IP-datagram structure:\n");
	printf("ver");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Internet Protocol version. Common Defaults: usually 4 (IPv4) or 6 (IPv6), 4 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("hlen");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": IP header length(in bytes), 4 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("tos");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Type of Service flags controls the priority of the packet. The first 3 bits stand for routing priority, the next 4 bits for the type of service (delay, throughput, reliability and cost), 8 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("len");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Total length must contain the total length of the IP datagram. This includes IP, ICMP, TCP or UDP header and payload size in bytes, 16 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("id");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": The ID sequence number is mainly used for reassembly of fragmented IP datagrams, 16 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("flags");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Flags, 3 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("offset");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Offset, 16 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("ttl");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Time to live, 8 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("prot");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": The transport layer protocol. Can be tcp (6), udp(17), icmp(1), or whatever protocol follows the IP header, 8 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("crc");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": The header checksum. Every time anything in the header changes, it needs to be recalculated, or the packet will be discarded by the next router, 16 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("src");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Source address, 32 bits;\n");
	//----
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf("dest");
	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
	printf(": Destination address, 32 bits;\n");
}

int main(int argc, char* argv[])
{
	char		 console_out = 'y';
	char		 buf[64];

	FILE*		 f = NULL;
	DWORD		 packet_res = 0;
	u_long		 watch_host = 0;
	DWORD		 packets_count = 0;
	unsigned int ret;

#ifdef NET_SERVER_2000
	InitializeCriticalSection(&critsect);
#endif

	ResizeConsole(CONSOLE_WIDTH, 10000);
	printf(STR_ABOUT);
	SetConsoleTitle("Sniffer");

	// инициализация
	RS_Init();

	// проверка на успешность создания сокета
	if (RS_SSocket != SOCKET_ERROR)
	{
		//SetConsoleTextColor(0x0A);
		printf("%s> %d\n", STR_SOCKET, RS_SSocket);
		//SetConsoleTextColor(0x07);
	}
	else
	{
		printf(STR_CANT_CREATE_SOCKET);
		Sleep(5000);
		return -1;
	}
	
	printf("%s> ", STR_HOSTNAME);
	SetConsoleTextColor(0x2F);
	printf("%s\n", RS_Hostname);
	SetConsoleTextColor(0x07);

	f = fopen(RS_Hostname, "wt");
	
	printf("%s> ", STR_HOST_IP);
	SetConsoleTextColor(0x2F);
	printf("%s\n", nethost2str(RS_SocketAddress.sin_addr.s_addr));
	SetConsoleTextColor(0x07);

	// Включение promiscuous mode
	RS_SetPromMode(1);
	printf("%s> OK\n", STR_PROM_MODE);

	

#ifndef ALPHA
	SetConsoleTextColor(0x07);
	printf(STR_CONSOLE_OUTPUT); 
	SetConsoleTextColor(0x0A); scanf("%c", &console_out);

	SetConsoleTextColor(0x07);
	printf(STR_RESOLUTION);
	SetConsoleTextColor(0x0A);
	scanf("%d", &packet_res);

	SetConsoleTextColor(0x07);
	printf(STR_WATCH_HOST);
	SetConsoleTextColor(0x0A);
	scanf("%s", buf);
	watch_host = inet_addr(buf);
	SetConsoleTextColor(0x07);
#endif

#ifdef NET_SERVER_2000
	// запуск сервера - посылка трафика  любому клиенту
	if (_beginthreadex(0, 0, AcceptConnections, (void*)RS_SSocket, 0, &ret))
		printf(STR_NET_SERVER_STARTED);
#endif

	printf("\n");
	ShowLegend();
	SetConsoleTextColor(0x07);
	printf("\n");
	ShowHelp();
	SetConsoleTextColor(0x07);

	printf("\nPress any key to start...\n\n");
	WaitForKey();
	
	RS_InitStat();

	while(true)
	{
		IPHeader* hdr = RS_Sniff();
		// обработка IP-пакета
		if (hdr)
		{
			char *packet_str = 0;
			packets_count++;
			// штамп времени
			time(&rawtime);
			timeinfo = localtime (&rawtime);
			// пакет в строку
			packet_str = RS_IPHeaderToStr(hdr);
			// запись в лог
			if (f)
				fprintf(f, "%.2d:%.2d:%.2d>%s\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, packet_str);
			
			/* подсветка */
			SetConsoleTextColor(0x07);
			/*ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);*/
			// печать заголовка IP-пакета
			if (console_out == 'y')
			{
				SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE /*| FOREGROUND_INTENSITY*/);
				printf("%.2d:%.2d:%.2d>", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
				ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);
				printf("%s", packet_str);
				//for(int i = 0; i < CONSOLE_WIDTH - strlen(packet_str)-9; i++) printf(" ");
				//printf("\n");
			}

			// для посылки строки заголовка в сеть
			sCurrPacket = packet_str;
			bNewPacket = true;

			free((void*)packet_str);
			free((void*)hdr);

			if (packet_res > 0)
				Sleep(packet_res);
		}

		SetConsoleTitle(RS_GetNetStat());

		if(!PauseAndContinue())
			break;
	}

	printf("\r");

	// Конец работы
	RS_Free();
	fclose(f);
	
	SetConsoleTextColor(0x0E);
	printf("\n\n%s %d\n", STR_END_OF_PROGRAM, packets_count);
	
	WaitForKey();
	return 0;
}