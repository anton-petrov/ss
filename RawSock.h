#ifndef  RAW_SOCK_H
#define RAW_SOCK_H

#include <cstring>
#include <cmath>
#include "Console.h"
 
// ulong = b4 b3 b2 b1
#define ULONG_BYTE4(u) ((u & 0xFF000000) >> 24) // самый старший байт 
#define ULONG_BYTE3(u) ((u & 0xFF0000) >> 16)
#define ULONG_BYTE2(u) ((u & 0xFF00) >> 8)
#define ULONG_BYTE1(u) (u & 0xFF)		// самый младший байт 

#define BYTE_L(u) (u & 0xF)
#define BYTE_H(u) (u >> 4)

#define IP_FLAGS(f) (f >> 13)
#define IP_OFFSET(o) (o & 0x1FFF)

#define SIO_RCVALL 0x98000001

//Some IP constants
//Version
#define IP_VERSION 4

//Service types
#define IpService_NETWORK_CONTROL 111
#define IpService_INTERNETWORK_CONTROL 110
#define IpService_CRITIC_ECP 101
#define IpService_FLASH_OVERIDE 100
#define IpService_FLASH 011
#define IpService_IMMEDIATE 010
#define IpService_PRIORITY 001
#define IP_SERVICE_ROUTINE 0

//Fragmetation flag
#define IpFragFlag_MAY_FRAG 0x0000
#define IpFragFlag_MORE_FRAG 0x2000
#define IpFragFlag_LAST_FRAG 0x5000
#define IpFragFlag_DONT_FRAG 0x4000

#define ICMPHeaderLength sizeof(ICMPHeader)
#define IPHeaderLength sizeof(IPHeader)

#define PROT_HOPOPT		 0      //	        IPv6 Hop-by-Hop Option                   [RFC1883]
#define PROT_ICMP		 1		//          Internet Control Message                 [RFC792] 
#define PROT_IGMP		 2		//          Internet Group Management                [RFC1112]
#define PROT_GGP		 3		//          Gateway-to-Gateway                       [RFC823]
#define PROT_IP		  	 4		//          IP in IP (encapsulation)                 [RFC2003]
#define PROT_ST			 5		//          Stream                                   [RFC1190][RFC1819]
#define PROT_TCP		 6		//          Transmission Control                     [RFC793]
#define PROT_CBT		 7		//          CBT                                      [Ballardie]
#define PROT_EGP		 8		//          Exterior Gateway Protocol                [RFC888][DLM1]
#define PROT_IGP		 9		//          any private interior gateway             [IANA]       
#define PROT_BBN_RCC_MON 10     //			BBN RCC Monitoring                       [SGC]
#define PROT_NVP_II      11     //			Network Voice Protocol                   [RFC741][SC3]
#define PROT_PUP         12     //			PUP                                      [PUP][XEROX]
#define PROT_ARGUS       13     //			ARGUS                                    [RWS4]
#define PROT_EMCON       14     //			EMCON                                    [BN7]
#define PROT_XNET        15     //			Cross Net Debugger                       [IEN158][JFH2]
#define PROT_CHAOS       16     //			Chaos                                    [NC3]
#define PROT_UDP         17     //			User Datagram                            [RFC768][JBP]
#define PROT_MUX         18     //			Multiplexing                             [IEN90][JBP]
#define PROT_DCN_MEAS    19     //			DCN Measurement Subsystems               [DLM1]
//#define HMP         20     Host Monitoring                          [RFC869][RH6]
//#define PRM         21     Packet Radio Measurement                 [ZSU]
//#define XNS-IDP     22     XEROX NS IDP                             [ETHERNET][XEROX]
//#define TRUNK-1     23     Trunk-1                                  [BWB6]
//#define TRUNK-2     24     Trunk-2                                  [BWB6]
//#define LEAF-1      25     Leaf-1                                   [BWB6]
//#define LEAF-2      26     Leaf-2                                   [BWB6]
//#define RDP         27     Reliable Data Protocol                   [RFC908][RH6]
//#define IRTP        28     Internet Reliable Transaction            [RFC938][TXM]
//#define ISO-TP4     29     ISO Transport Protocol Class 4           [RFC905][RC77]
//#define NETBLT      30     Bulk Data Transfer Protocol              [RFC969][DDC1]
//#define MFE-NSP     31     MFE Network Services Protocol            [MFENET][BCH2]
//#define MERIT-INP   32     MERIT Internodal Protocol                [HWB]
//#define DCCP        33     Datagram Congestion Control Protocol     [RFC4340]
//#define 3PC         34     Third Party Connect Protocol             [SAF3]
//#define IDPR        35     Inter-Domain Policy Routing Protocol     [MXS1] 
//#define XTP         36     XTP                                      [GXC]
//#define DDP         37     Datagram Delivery Protocol               [WXC]
//#define IDPR-CMTP   38     IDPR Control Message Transport Proto     [MXS1]
//#define TP++        39    TP++ Transport Protocol                  [DXF]
//#define IL          40     IL Transport Protocol                    [Presotto]
//#define IPv6        41     Ipv6                                     [Deering]    
//#define SDRP        42    Source Demand Routing Protocol           [DXE1]
//#define IPv6-Route  43     Routing Header for IPv6                  [Deering]
//#define IPv6-Frag   44     Fragment Header for IPv6                 [Deering]
//#define IDRP        45     Inter-Domain Routing Protocol            [Hares]
//#define RSVP        46     Reservation Protocol                     [Braden]
//#define GRE         47     General Routing Encapsulation            [Li]
//#define DSR         48     Dynamic Source Routing Protocol          [RFC4728]
//#define BNA         49     BNA                                      [Salamon]
//#define ESP         50     Encap Security Payload                   [RFC4303]
//#define AH          51     Authentication Header                    [RFC4302]
//#define I-NLSP      52     Integrated Net Layer Security  TUBA      [GLENN]
//#define SWIPE       53     IP with Encryption                       [JI6]
//#define NARP        54     NBMA Address Resolution Protocol         [RFC1735]
//#define MOBILE      55     IP Mobility                              [Perkins]
//#define TLSP        56     Transport Layer Security Protocol        [Oberg]
//									using Kryptonet key management
//57      #define SKIP             SKIP                                     [Markson]
//58      #define IPv6-ICMP        ICMP for IPv6                            [RFC1883]
//59      #define IPv6-NoNxt       No Next Header for IPv6                  [RFC1883]
//60      #define IPv6-Opts        Destination Options for IPv6             [RFC1883]
//61      #define ANY_HOST_INTERNAL_PROTOCOL								[IANA]
//62      #define CFTP             CFTP                                     [CFTP][HCF2]
//63                        any local network                        [IANA]
//64      #define SAT-EXPAK        SATNET and Backroom EXPAK                [SHB]
//65      #define KRYPTOLAN        Kryptolan                                [PXL1]
//66      #define RVD              MIT Remote Virtual Disk Protocol         [MBG]
//67      #define IPPC             Internet Pluribus Packet Core            [SHB]
//68                        any distributed file system              [IANA]
//69      #define SAT-MON          SATNET Monitoring                        [SHB]
//70      #define VISA             VISA Protocol                            [GXT1]
//71      #define IPCV             Internet Packet Core Utility             [SHB]
//72      #define CPNX             Computer Protocol Network Executive      [DXM2]
//73      #define CPHB             Computer Protocol Heart Beat             [DXM2]
//74      #define WSN              Wang Span Network                        [VXD]
//75      #define PVP              Packet Video Protocol                    [SC3]
//76      #define BR-SAT-MON       Backroom SATNET Monitoring               [SHB]
//77      #define SUN-ND           SUN ND PROTOCOL-Temporary                [WM3]
//78      #define WB-MON           WIDEBAND Monitoring                      [SHB]
//79      #define WB-EXPAK         WIDEBAND EXPAK                           [SHB]
//80      #define ISO-IP           ISO Internet Protocol                    [MTR]
//81      #define VMTP             VMTP                                     [DRC3]
//82      #define SECURE-VMTP      SECURE-VMTP                              [DRC3]
//83      #define VINES            VINES                                    [BXH]
//84      #define TTP              TTP                                      [JXS]
//85      #define NSFNET-IGP       NSFNET-IGP                               [HWB]
//86      #define DGP              Dissimilar Gateway Protocol              [DGP][ML109]
//87      #define TCF              TCF                                      [GAL5]
//88      #define EIGRP            EIGRP                                    [CISCO][GXS]
//89      #define OSPFIGP          OSPFIGP                                  [RFC1583][JTM4]
//90      #define Sprite-RPC       Sprite RPC Protocol                      [SPRITE][BXW] 
//91      #define LARP             Locus Address Resolution Protocol        [BXH]
//92      #define MTP              Multicast Transport Protocol             [SXA]
//93      #define AX.25            AX.25 Frames                             [BK29]         
//94      #define IPIP             IP-within-IP Encapsulation Protocol      [JI6]
//95      #define MICP             Mobile Internetworking Control Pro.      [JI6]
//96      #define SCC-SP           Semaphore Communications Sec. Pro.       [HXH]     
//97      #define ETHERIP          Ethernet-within-IP Encapsulation         [RFC3378]
//98      #define ENCAP            Encapsulation Header                     [RFC1241,RXB3]
//99                        any private encryption scheme            [IANA]
//100     #define GMTP             GMTP                                     [RXB5]
//101     #define IFMP             Ipsilon Flow Management Protocol         [Hinden]
//102     #define PNNI             PNNI over IP                             [Callon]
//103     #define PIM              Protocol Independent Multicast           [Farinacci]
//104     #define ARIS             ARIS                                     [Feldman]
//105     #define SCPS             SCPS                                     [Durst]
//106     #define QNX              QNX                                      [Hunter]
//107     #define A/N              Active Networks                          [Braden]
//108     #define IPComp           IP Payload Compression Protocol          [RFC2393]
//109     #define SNP              Sitara Networks Protocol                 [Sridhar]
//110     #define Compaq-Peer      Compaq Peer Protocol                     [Volpe]
//111     #define IPX-in-IP        IPX in IP                                [Lee]
//112     #define VRRP             Virtual Router Redundancy Protocol       [RFC3768]
//113     #define PGM              PGM Reliable Transport Protocol          [Speakman]
//114                       any 0-hop protocol                       [IANA]
//115     #define L2TP             Layer Two Tunneling Protocol             [Aboba]
//116     #define DDX              D-II Data Exchange (DDX)                 [Worley] 
//117     #define IATP             Interactive Agent Transfer Protocol      [Murphy]
//118     #define STP              Schedule Transfer Protocol               [JMP]
//119     #define SRP              SpectraLink Radio Protocol               [Hamilton]
//120     #define UTI              UTI                                      [Lothberg]
//121     #define SMP              Simple Message Protocol                  [Ekblad]
//122     #define SM               SM                                       [Crowcroft]
//123     #define PTP              Performance Transparency Protocol        [Welzl]
//124     #define ISIS over IPv4                                            [Przygienda]
//125     #define FIRE                                                      [Partridge]
//126     #define CRTP             Combat Radio Transport Protocol          [Sautter]
//127     #define CRUDP            Combat Radio User Datagram               [Sautter]
//128     #define SSCOPMCE                                                  [Waber]
//129     #define IPLT                                                      [Hollbach]
//130     #define SPS              Secure Packet Shield                     [McIntosh] 
//131     #define PIPE             Private IP Encapsulation within IP       [Petri]
//132     #define SCTP             Stream Control Transmission Protocol     [Stewart]
//133     #define FC               Fibre Channel                            [Rajagopal]
//134     #define RSVP-E2E-IGNORE                                           [RFC3175]
//135     #define Mobility Header                                           [RFC3775]
//136     #define UDPLite                                                   [RFC3828]
//137     #define MPLS-in-IP                                                [RFC4023]
//138     #define manet            MANET Protocols                          [RFC5498]
//139     #define HIP              Host Identity Protocol                   [RFC5201]     
//140     #define Shim6            Shim6 Protocol                           [RFC5533]
////141-252                   Unassigned                               [IANA]//
////253                       Use for experimentation and testing      [RFC3692] 
////254                       Use for experimentation and testing      [RFC3692] 
////255      Reserved                                                  [IANA]


struct ETHERNET_FRAME
{
	unsigned char  dest[6];	// MAC-адрес получателя
	unsigned char  src[6];	// MAC-адрес отправителя
	unsigned short type;	// версия: IPv4 0x0800, IPv6 0x86DD, ARP 0x0806
	unsigned char  data[];	// данные
};

struct ETHERNET_ARP
{
	unsigned short hrd;		// Тип аппаратуры (Ethernet), 0x0001.
	unsigned short pro;		// Протокол (IP), 0x0800.
	unsigned char  hln;		// Длина аппаратного адреса (MAC), 6 байт.
	unsigned char  pln;		// Длина адреса протокола IP, 4 байта.
	unsigned short op;		// Вид операции {Запрос, Ответ} = {1, 2}.
	unsigned char  sha[6];	// Аппаратный адрес (MAC) отправителя.
	unsigned char  spa[4];	// IP-адрес отправителя.
	unsigned char  tha[6];	// Аппаратный адрес (MAC) получателя.
	unsigned char  tpa[4];	// IP-адрес получателя.
};

typedef struct _IPHeader
{
	unsigned char  ver_len;		// версия и длина заголовка
	unsigned char  tos;			// тип сервиса РАЗБИТЬ НА ФЛАГИ(0 1 2 3 ... 7)
	unsigned short length;		// длина всего пакета 
	unsigned short id;			// Id 
	unsigned short flgs_offset;	// смещение
	unsigned char  ttl;			// время жизни 
	unsigned char  protocol;	// протокол 
	unsigned short xsum;		// контрольная сумма 
	unsigned long  src;			// IP-адрес отправителя 
	unsigned long  dest;		// IP-адрес назначения 
    //------------------------------------------------------------
	unsigned short *params;	    // параметры (до 320 бит)
	unsigned char  *data;	    // данные (до 65535 - длина заголовка)
}IPHeader;


typedef struct _ICMPHeader
{
	unsigned char type;
	unsigned char code;			
	unsigned short checksum;
	union
	{
		struct {unsigned char c1, c2, c3, c4;} C;
		struct {unsigned short s1, s2;} S;
		unsigned long L;
	} ICMP;
	unsigned long originate_timestamp;
	unsigned long receive_timestamp;
	unsigned long transmit_timestamp;
} ICMPHeader;

typedef ICMPHeader FAR * LPICMPHeader;
typedef IPHeader FAR * LPIPHeader;

typedef struct _NetStat
{
	DWORD DownSpeed;
	DWORD UpSpeed;
	DWORD TotalSpeed;
	DWORD DatagramsPerSecond;
}NetStat;

//Max buf
#define ICMP_BUF 100

#define MAX_PACKET_SIZE    0x10000

// Буфер для приёма данных
BYTE RS_Buffer[MAX_PACKET_SIZE]; // 64 Kb

WSADATA			RS_WSAData;         // Инициализация WinSock.
SOCKET			RS_SSocket;         // Cлущающий сокет.
char			RS_Hostname[128];   // Имя хоста (компьютера).
HOSTENT*		RS_Hostinfo;        // Информация о хосте.
SOCKADDR_IN		RS_SocketAddress;   // Адрес хоста
static u_long   RS_Flag = 1;        // Флаг PROMISC Вкл/выкл.
NetStat			RS_NetStat;

static DWORD RS_time;
static DWORD bps_recv, bps_send, bps_tot, dps;

static time_t	  rawtime;
static struct tm* timeinfo;

// ===============================================================

void RS_InitStat()
{
	RS_time = GetTickCount();
	bps_send = bps_recv = bps_tot = dps = 0;
}

// статистика
static void RS_UpdateNetStat(const int c, const IPHeader *h)
{
	if (RS_SocketAddress.sin_addr.s_addr == h->dest)	
		bps_recv += c;
	else if (RS_SocketAddress.sin_addr.s_addr == h->src)
		bps_send += c;
	bps_tot += c;
	dps++;
	if (GetTickCount() - RS_time >= 250)
	{
		RS_NetStat.DatagramsPerSecond = dps*4;
		RS_NetStat.DownSpeed = bps_recv*4;
		RS_NetStat.UpSpeed = bps_send*4;
		RS_NetStat.TotalSpeed = bps_tot*4;

		bps_send = bps_recv = bps_tot = dps = 0;
		RS_time = GetTickCount();
	}
}

char *RS_GetNetStat()
{
	static char r[100];

	sprintf(r, "stats: recv=%.8d KB/s; send=%.8d KB/s; total=%.8d KB/s; datagrams/s=%d", 
		RS_NetStat.DownSpeed/1024, RS_NetStat.UpSpeed/1024, RS_NetStat.TotalSpeed/1024, RS_NetStat.DatagramsPerSecond);

	return r;
}

int RS_Init()
{
	WSAStartup(MAKEWORD(2,2), &RS_WSAData);
	RS_SSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	gethostname(RS_Hostname, sizeof(RS_Hostname));
	RS_Hostinfo = gethostbyname(RS_Hostname);
	ZeroMemory(&RS_SocketAddress, sizeof(RS_SocketAddress));
	RS_SocketAddress.sin_family = AF_INET;
	RS_SocketAddress.sin_addr.s_addr = ((struct in_addr *)RS_Hostinfo->h_addr_list[0])->s_addr;
	bind(RS_SSocket, (SOCKADDR *)&RS_SocketAddress, sizeof(SOCKADDR));
	ZeroMemory(&RS_NetStat, sizeof(RS_NetStat));
	return RS_SSocket;
}

void RS_SetPromMode(int flag = 1)
{
	RS_Flag = flag;
	ioctlsocket(RS_SSocket, SIO_RCVALL, &RS_Flag);
}

IPHeader* RS_Sniff()
{
	IPHeader *hdr;
	int count = 0;
	count = recv(RS_SSocket, (char*)&RS_Buffer[0], sizeof(RS_Buffer), 0);
	if (count >= sizeof(IPHeader))
	{
		hdr = (LPIPHeader)malloc(MAX_PACKET_SIZE);
		memcpy(hdr, RS_Buffer, MAX_PACKET_SIZE);
		RS_UpdateNetStat(count, hdr);
		return hdr;
	}
	else
		return 0;
}

void RS_Free()
{
	closesocket(RS_SSocket);
	WSACleanup();
}


unsigned short checksum(unsigned short *buf, int size)
{
	unsigned long chksum=0;

	//Calculate the checksum
	while (size>1)
	{
		chksum+=*buf++;
		size-=sizeof(unsigned short);
	}

	//If we have one char left
	if (size)
		chksum+=*(unsigned char*)buf;

	//Complete the calculations
	chksum=(chksum >> 16) + (chksum & 0xffff);
	chksum+=(chksum >> 16);

	//Return the value (inversed)
	return (unsigned short)(~chksum);
}

/*
*   преобразование сетвого адреса хоста в строку
*/
inline char* nethost2str(u_long h)
{
	const int __BUF_SIZE = 16;
	char *r = (char*)malloc(__BUF_SIZE);
	memset((void*)r, 0, __BUF_SIZE);
	
	h = ntohl(h);

	sprintf(r, "%d.%d.%d.%d", ULONG_BYTE4(h), ULONG_BYTE3(h), ULONG_BYTE2(h), ULONG_BYTE1(h));
	return r;
}

inline unsigned int iexp(unsigned int x, unsigned n)
{
	int p, y;
	y = 1;
	p = x;
	while(1)
	{
		if (n & 1) y *= p;
		n = n >> 1;
		if (n == 0)
			return y;
		p *= p;
	}
}

char* int2bin(unsigned int num, unsigned char bits)
{
	char *str_bin = (char*)malloc(bits+1);
	for(unsigned char i = 0, m = iexp(2, bits-1); m > 0; m /= 2, i++)
	{
		str_bin[i] = (num & m) ? '1' : '0';
	}
	str_bin[bits] = 0;
	return str_bin;
}

/*
*   преобразование ip-заголовка в строку
*/
char* RS_IPHeaderToStr(IPHeader *iph)
{
	const int __BUF_SIZE = 1024;

	char *r = (char*)malloc(__BUF_SIZE);
	char *t1, *t2;

	memset((void*)r, 0, __BUF_SIZE);

	t1 = int2bin(iph->tos, 8);
	t2 = int2bin(IP_FLAGS(ntohs(iph->flgs_offset)), 3);

	sprintf(r,
		"ver=%d hlen=%d tos=%s len=%-4d id=%-5d flags=%s offset=%d ttl=%3dms prot=%-2d crc=%-4X src=%-15s dest=%-15s",
		BYTE_H(iph->ver_len), BYTE_L(iph->ver_len)*4, t1, ntohs(iph->length), ntohs(iph->id), 
		t2, IP_OFFSET(ntohs(iph->flgs_offset)), iph->ttl, iph->protocol, 
		ntohs(iph->xsum), nethost2str(iph->src), nethost2str(iph->dest));
	
	free((void*)t1);
	free((void*)t2);


	return r;
}


#endif