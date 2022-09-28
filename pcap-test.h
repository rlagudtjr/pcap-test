#include <stdint.h>
#include <pcap.h>
#include <stdbool.h>
#include <iostream>

#define ETHER_ADDR_LEN 0x6
#define IP_ADDR_LEN 0x4
#define IP 0x0800
#define TCP 0x06

#define ADD16(a, b) (a << 8) + b
#define ADD32(a, b, c, d) (a << 24) + (b << 16) + (c << 8) + d

using std::cout;
using std::cin;
using std::hex;
using std::dec;
using std::uppercase;

typedef struct {
	char* dev_;
} Param;

typedef struct
{
	u_int8_t  dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t type;                 /* protocol */
}ethernet_hdr;

typedef struct {
	u_int8_t ip[IP_ADDR_LEN];
}ip_addr;

typedef struct {
	u_int8_t v;         /* version */
	u_int8_t hl;      /* header length */
	u_int8_t tos;       /* type of service */
	u_int16_t len;         /* total length */
	u_int16_t id;          /* identification */
	u_int16_t off;
	u_int8_t ttl;          /* time to live */
	u_int8_t p;            /* protocol */
	u_int16_t sum;         /* checksum */
	ip_addr src, dst; /* source and dest address */
}ipv4_hdr;

typedef struct {
	u_int16_t sport;       /* source port */
	u_int16_t dport;       /* destination port */
	u_int32_t seq;          /* sequence number */
	u_int32_t ack;          /* acknowledgement number */
	u_int8_t off;        /* data offset */
	u_int8_t x2;         /* (unused) */
	u_int8_t flags;       /* control flags */
	u_int16_t win;         /* window */
	u_int16_t sum;         /* checksum */
	u_int16_t urp;         /* urgent pointer */
}tcp_hdr;

typedef struct {
	ethernet_hdr ethernet;
	ipv4_hdr ipv4;
	tcp_hdr tcp;
	uint8_t payload[8];
}Header;

void usage() {
	cout << "syntax: pcap-test <interface>\n";
	cout << "sample: pcap-test wlan0\n";
}

bool parse_param(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void parse_ethernet(const u_char* packet, Header& header) {
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		header.ethernet.dhost[i] = packet[i];
		header.ethernet.shost[i] = packet[i + ETHER_ADDR_LEN];
	}
	header.ethernet.type = ADD16(packet[12], packet[13]);
}

void parse_ip(const u_char* packet, Header& header) {
	header.ipv4.v = packet[0] >> 4;
	header.ipv4.hl = packet[0] & 0xf;
	header.ipv4.tos = packet[1];
	header.ipv4.len = ADD16(packet[2], packet[3]);
	header.ipv4.id = ADD16(packet[4], packet[5]);
	header.ipv4.off = ADD16(packet[6], packet[7]);
	header.ipv4.ttl = packet[8];
	header.ipv4.p = packet[9];
	header.ipv4.sum = ADD16(packet[10], packet[11]);
	for (int i = 0; i < IP_ADDR_LEN; i++) {
		header.ipv4.src.ip[i] = packet[12 + i];
		header.ipv4.dst.ip[i] = packet[16 + i];
	}
}

void parse_tcp(const u_char* packet, Header& header) {
	header.tcp.sport = ADD16(packet[0], packet[1]);
	header.tcp.dport = ADD16(packet[2], packet[3]);
	header.tcp.seq = ADD32(packet[4], packet[5], packet[6], packet[7]);
	header.tcp.ack = ADD32(packet[8], packet[9], packet[10], packet[11]);
	header.tcp.off = packet[12] >> 4;
	header.tcp.x2 = packet[12] & 0xf;
	header.tcp.flags = packet[13];
	header.tcp.win = ADD16(packet[14], packet[15]);
	header.tcp.sum = ADD16(packet[16], packet[17]);
	header.tcp.urp = ADD16(packet[18], packet[19]);
}

void parse_packet(const u_char* packet) {
	Header header;

	parse_ethernet(packet, header);
	if (header.ethernet.type != IP) {
		cout << "this is not IP";
		return;
	}

	parse_ip(&packet[14], header);
	if (header.ipv4.p != TCP) {
		cout << "this is not TCP";
		return;
	}

	parse_tcp(&packet[14 + header.ipv4.hl * 4], header);

	cout << uppercase << hex;
	cout << "\nehternet src mac     ";
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		cout << static_cast<int>(header.ethernet.shost[i]);
		if (i != 5) cout << ':';
	}
	cout << "\nehternet dst mac     ";
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		cout << static_cast<int>(header.ethernet.dhost[i]);
		if (i != 5) cout << ':';
	}

	cout << dec;
	cout << "\nip header src ip     ";
	for (int i = 0; i < IP_ADDR_LEN; i++) {
		cout << static_cast<int>(header.ipv4.src.ip[i]);
		if (i != 3) cout << '.';
	}
	cout << "\nip header dst ip     ";
	for (int i = 0; i < IP_ADDR_LEN; i++) {
		cout << static_cast<int>(header.ipv4.dst.ip[i]);
		if (i != 3) cout << '.';
	}

	cout << "\ntcp header src port  " << header.tcp.sport;
	cout << "\ntcp header dst port  " << header.tcp.dport;

	int payload_len = header.ipv4.len - (header.ipv4.hl + header.tcp.off) * 4;
	if (payload_len > 0) {
		cout << uppercase << hex;
		cout << "\npayload              ";
		for (int i = 0; i < 8; i++) {
			cout << static_cast<int>(packet[i + 14 + (header.ipv4.hl + header.tcp.off) * 4]);
		}
	}
	else {
		cout << "\nthere is no payload";
	}
}

