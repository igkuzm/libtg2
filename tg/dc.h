#ifndef TG_DC_H
#define TG_DC_H

/* Telegram is currently composed by a decentralized,
 * multi-DC infrastructure (currently 5 DCs, each of which
 * can work independently) spread across different
 * locations worldwide. However, some of the less busy DCs
 * have been lately dismissed and their IP addresses are now
 * kept as aliases to the nearest one.
 */

#define DCS \
	DC(1, "pluto", "149.154.175.53", "2001:b28:f23d:f001::a", "MIA, Miami FL, USA") \
	DC(2, "venus", "149.154.167.51", "2001:67c:4e8:f002::a", "AMS, Amsterdam, NL") \
	DC(3, "aurora", "149.154.175.100", "2001:b28:f23d:f003::a","MIA, Miami FL, USA") \
	DC(4, "vesta", "149.154.167.91", "2001:67c:4e8:f004::a","AMS, Amsterdam, NL") \
	DC(5, "flora", "91.108.56.130", "2001:b28:f23f:f005::a","SIN, Singapore") \

enum dc {
#define DC(n, ...) DC_##n = n,
	DCS
#undef DC
	DC_COUNT
};

typedef struct dc_t {
	enum dc dc;
	int id;
	char name[16];
	char ipv4[16];
	char ipv6[32];
	char description[64];
} dc_t;

static const dc_t DCs[] = 
{
#define DC(n, dcname, ip4, ip6, desc) DC_##n, n, dcname, ip4, ip6, desc,
	DCS
#undef DC
};

#endif /* ifndef TG_DC_H */
