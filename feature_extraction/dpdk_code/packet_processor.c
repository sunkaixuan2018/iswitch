#include "l3fwd.h"
#include "packet_processor.h"
#include "../data_types.h"
#include "../Hash_Utils.h"

#include <stdlib.h>

#include <rte_spinlock.h>
#include <rte_ring.h>

#define TOTAL_LCORES 24

extern bool force_quit;

//extern struct rte_ring *pkts_container;

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static uint64_t lcore_rx_packets[RTE_MAX_LCORE] = {0};
static uint64_t lcore_rx_bytes[RTE_MAX_LCORE] = {0};

static uint64_t timer_period = OUTPUT_INTERVAL; /* default period is 5 seconds */

static uint64_t clean_period = CLEAN_INTERVAL;

void pass_cpu_pkts(struct pkt_tuple_info *);
void output_flow_features();
void clean_flow_stats(uint64_t);
void quit_gpu_processing();
void gpu_process();

void
extract_tuple_info(struct rte_mbuf *m, struct pkt_tuple_info *pti);

static void
print_rx_packets(void){
	uint64_t rx_packets = 0, rx_bytes = 0;
	int i;

	for(i = 0; i < RTE_MAX_LCORE; ++i){
		rx_packets += lcore_rx_packets[i];
		rx_bytes += lcore_rx_bytes[i];
//    if(i<23)      printf("\ncoreid: %ld\t\t\treceived pkt: %ld\n", i , lcore_rx_packets[i] );
	}
   
	printf("\nreceived pacakets: %ld\t\t\treceived bytes: %ld\n", rx_packets, rx_bytes);
}

static void
track_stats(void){
	uint64_t pre_cyc, cur_cyc, timer_cyc = 0, clean_timer_cyc = 0;

	timer_period *= rte_get_timer_hz();
	clean_period *= rte_get_timer_hz();
	pre_cyc = rte_get_timer_cycles();

	while(!force_quit){
		cur_cyc = rte_get_timer_cycles();
		timer_cyc += (cur_cyc-pre_cyc);
		clean_timer_cyc += (cur_cyc-pre_cyc);

		if(timer_cyc >= timer_period){
			print_rx_packets();
			output_flow_features();
			timer_cyc = 0;
		}

		if(clean_timer_cyc >= clean_period){
			clean_flow_stats(rte_get_timer_cycles() * 1.0 / rte_get_timer_hz() * 1000);
			clean_timer_cyc = 0;
		}

		pre_cyc = cur_cyc;
	}

	quit_gpu_processing();

}

int
pp_main_loop(__attribute__((unused)) void *dummy)
{
	unsigned lcore_id;
	int i, j, nb_rx;
	uint8_t queueid;
	uint16_t portid;
	struct lcore_conf *qconf;
	struct rte_mbuf *m;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u print statistics\n", lcore_id);

		switch(lcore_id){
			case 22: track_stats(); break;
			case 23: gpu_process(); break;
			//case 8: process_packets(); break;
		}

		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct pkt_tuple_info *cur_pkts = (struct pkt_tuple_info *)malloc(ArraySize * sizeof(struct pkt_tuple_info));
	int index = 0;
	while (!force_quit) {

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

			for(j = 0; j < nb_rx; ++j){
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				++lcore_rx_packets[lcore_id];
				lcore_rx_bytes[lcore_id] += m->data_len;
                
//                printf(" - RSS hash=0x%x", (unsigned) m->hash.rss);

				if(index == ArraySize){
					pass_cpu_pkts(cur_pkts);
					cur_pkts = (struct pkt_tuple_info *)malloc(ArraySize * sizeof(struct pkt_tuple_info));
					index = 0;
				}

				extract_tuple_info(m, &(cur_pkts[index]));
				++index;

				rte_pktmbuf_free(pkts_burst[j]);
			}
	  }

  }

	return 0;
}

void
extract_tuple_info(struct rte_mbuf *m, struct pkt_tuple_info *pti){
	struct pkt_tuple *m_tuple = &(pti->tuple);
	struct pkt_info *m_info = &(pti->info);

	struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(m,
							    struct ipv4_hdr *,
							    sizeof(struct ether_hdr));

	struct tcp_hdr *tcp;
	struct udp_hdr *udp;

	m_tuple->src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	m_tuple->dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	m_tuple->proto = ipv4_hdr->next_proto_id;

	switch(m_tuple->proto){
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			m_tuple->src_port = rte_be_to_cpu_16(tcp->src_port);
			m_tuple->dst_port = rte_be_to_cpu_16(tcp->dst_port);
			m_info->psh = tcp->tcp_flags & 0x8;
			m_info->urg = tcp->tcp_flags & 0x20;
			break;
		case IPPROTO_UDP:
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			m_tuple->src_port = rte_be_to_cpu_16(udp->src_port);
			m_tuple->dst_port = rte_be_to_cpu_16(udp->dst_port);
			m_info->psh = false;
			m_info->urg = false;
			break;
		default:
			return;
			break;
	}

	m_info->data_len = m->data_len;
	m_info->timestamp = rte_get_timer_cycles() * 1.0 / rte_get_timer_hz() * 1000;

	uint8_t key[5];
  key[0] = m_tuple->proto;
  uint16_t first, second;
  if(m_tuple->src_port < m_tuple->dst_port){
    first = m_tuple->src_port;
    second = m_tuple->dst_port;
  }
  else{
    first = m_tuple->dst_port;
    second = m_tuple->src_port;
  }
  key[1] = (first >> 8) & 0xff;
  key[2] = first & 0xff;
  key[3] = (second >> 8) & 0xff;
  key[4] = second & 0xff;

  pti->hash = murmur3_32(key, 5, 16);
  pti->next_index = -1;

  
}

/*void
process_packet(struct rte_mbuf *m, unsigned lcore_id){
	int cur_index;
	struct pkt_tuple_info *cur_pkts;
	bool transfer = false;

	rte_spinlock_lock(&pkt_index_spin);

	cur_index = pkt_index;
	cur_pkts = cpu_pkts;

	if(pkt_index < ArraySize - 1) ++pkt_index;
	else{
		pkt_index = 0;
		transfer = true;
		cpu_pkts = (struct pkt_tuple_info *)malloc(ArraySize * sizeof(struct pkt_tuple_info));
	}

	rte_spinlock_unlock(&pkt_index_spin);

	++lcore_rx_packets[lcore_id];
	lcore_rx_bytes[lcore_id] += m->data_len;

	struct pkt_tuple *m_tuple = &(cur_pkts[cur_index].tuple);
	struct pkt_info *m_info = &(cur_pkts[cur_index].info);

	struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(m,
							    struct ipv4_hdr *,
							    sizeof(struct ether_hdr));

	struct tcp_hdr *tcp;
	struct udp_hdr *udp;

	m_tuple->src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	m_tuple->dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	m_tuple->proto = ipv4_hdr->next_proto_id;

	switch(m_tuple->proto){
		case IPPROTO_TCP:
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			m_tuple->src_port = rte_be_to_cpu_16(tcp->src_port);
			m_tuple->dst_port = rte_be_to_cpu_16(tcp->dst_port);
			m_info->psh = tcp->tcp_flags & 0x8;
			m_info->urg = tcp->tcp_flags & 0x20;
			break;
		case IPPROTO_UDP:
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			m_tuple->src_port = rte_be_to_cpu_16(udp->src_port);
			m_tuple->dst_port = rte_be_to_cpu_16(udp->dst_port);
			m_info->psh = false;
			m_info->urg = false;
			break;
		default:
			return;
			break;
	}

	m_info->data_len = m->data_len;
	m_info->timestamp = rte_get_timer_cycles() * 1.0 / rte_get_timer_hz() * 1000;

	uint8_t key[5];
  key[0] = m_tuple->proto;
  uint16_t first, second;
  if(m_tuple->src_port < m_tuple->dst_port){
    first = m_tuple->src_port;
    second = m_tuple->dst_port;
  }
  else{
    first = m_tuple->dst_port;
    second = m_tuple->src_port;
  }
  key[1] = (first >> 8) & 0xff;
  key[2] = first & 0xff;
  key[3] = (second >> 8) & 0xff;
  key[4] = second & 0xff;

  cur_pkts[cur_index].hash = murmur3_32(key, 5, 16);
  cur_pkts[cur_index].next_index = -1;

	if(transfer){
		pass_cpu_pkts(cur_pkts);
	}
}*/
