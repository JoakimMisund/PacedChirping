/* DataCenter TCP (DCTCP) congestion control.
 *
 * http://simula.stanford.edu/~alizade/Site/DCTCP.html
 *
 * This is an implementation of DCTCP over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. DCTCP
 * leverages Explicit Congestion Notification (ECN) in the network to
 * provide multi-bit feedback to the end hosts. DCTCP's goal is to meet
 * the following three data center transport requirements:
 *
 *  - High burst tolerance (incast due to partition/aggregate)
 *  - Low latency (short flows, queries)
 *  - High throughput (continuous data updates, large file transfers)
 *    with commodity shallow buffered switches
 *
 * The algorithm is described in detail in the following two papers:
 *
 * 1) Mohammad Alizadeh, Albert Greenberg, David A. Maltz, Jitendra Padhye,
 *    Parveen Patel, Balaji Prabhakar, Sudipta Sengupta, and Murari Sridharan:
 *      "Data Center TCP (DCTCP)", Data Center Networks session
 *      Proc. ACM SIGCOMM, New Delhi, 2010.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp-final.pdf
 *
 * 2) Mohammad Alizadeh, Adel Javanmard, and Balaji Prabhakar:
 *      "Analysis of DCTCP: Stability, Convergence, and Fairness"
 *      Proc. ACM SIGMETRICS, San Jose, 2011.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp_analysis-full.pdf
 *
 * Initial prototype from Abdul Kabbani, Masato Yasuda and Mohammad Alizadeh.
 *
 * Authors:
 *
 *	Daniel Borkmann <dborkman@redhat.com>
 *	Florian Westphal <fw@strlen.de>
 *	Glenn Judd <glenn.judd@morganstanley.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

/* Paced Chirping start-up extension can be enabled by setting sysctl dctcp_pc_enabled to 1.
 * Paced chirping is described in https://riteproject.files.wordpress.com/2018/07/misundjoakimmastersthesissubmitted180515.pdf
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_dctcp.h"

#define DCTCP_MAX_ALPHA	1024U

/* Paced Chirping */
#define INVALID_CHIRP UINT_MAX
#define STATE_TRANSITION 0x20
#define STATE_ACTIVE 0x10
#define GAP_AVG_SHIFT 1           /* Average gap shift */
#define M_SHIFT 4                 /* M is the number of chirps in the current round */
#define G_G_SHIFT 10              /* Gain and geometry shift */
#define CHIRP_SIZE 16U

#define DEBUG 1
#define DEBUG_PRINT(x) do { if (DEBUG) trace_printk x;} while (0)
/*Debug print functions located at bottom of file*/
static void print_u32_array(u32 *array, u32 size, char *name, struct tcp_sock *tp);
static void print_u64_array(u64 *array, u32 size, char *name, struct tcp_sock *tp);

struct cc_chirp {
	struct list_head list;
	u8 mem_flag;

	u16 chirp_number;
	u16 N;
	u16 qdelay_index;
	
	u32 begin_seq; //seq of first segment in chirp
	u32 end_seq; //seq of first segment after last packet in chirp
	u32 fully_sent;
	
	u32 qdelay[CHIRP_SIZE];
	u64 scheduled_gaps[CHIRP_SIZE];
};

#define MEMORY_CACHE_SIZE_CHIRPS 10U
#define MEMORY_CACHE_SIZE_BYTES (sizeof(struct cc_chirp) * MEMORY_CACHE_SIZE_CHIRPS)

#define MEM_UNALLOC 0x01
#define MEM_CACHE 0x02
#define MEM_ALLOC 0x04
#define MEM_LAST 0x10

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 loss_cwnd;

	/* Paced Chirping vars */
	u8 pc_state;
	struct cc_chirp *chirp_list;

	u32 gap_avg_ns;      /*Average gap (estimate)*/
	u32 round_length_us; /*Used for termination condition*/
	u32 chirp_number;
	u32 M;               /*Maximum number of chirps in a round*/
	u32 round_start;     /*Chirp number of the first chirp in the round*/
	u32 round_sent;      /*Number of chirps sent in the round*/
	u16 gain;            /*Increase of number of chirps*/
	u16 geometry;        /*Range to probe for*/
	struct cc_chirp *memory_cache;
	struct cc_chirp *itr;
};

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = 0;//DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

/*TODO This value has to be changed*/
/*Paced Chirping parameters*/
static unsigned int dctcp_pc_enabled __read_mostly = 1;
module_param(dctcp_pc_enabled, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_enabled, "Enable paced chirping (Default: 0)");

static unsigned int dctcp_pc_initial_gain __read_mostly = 2<<G_G_SHIFT; /* gain shifted */
module_param(dctcp_pc_initial_gain, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_gain, "Initial gain for paced chirping");

static unsigned int dctcp_pc_initial_geometry __read_mostly = 2<<G_G_SHIFT; /* geometry shifted */
module_param(dctcp_pc_initial_geometry, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_geometry, "Initial geometry for paced chirping");

static unsigned int dctcp_pc_L __read_mostly = 5;
module_param(dctcp_pc_L, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_L, "Number of packets that make up an excursion");

/* TODO: Figure out of the sensistivty in the anlaysis can be a parameter*/

static struct tcp_congestion_ops dctcp_reno;

static struct cc_chirp* cached_chirp_malloc(struct tcp_sock *tp, struct dctcp *ca)
{
	struct cc_chirp* ptr;

	if (ca->memory_cache) {
		ptr = ca->itr;
		if (ptr->mem_flag & MEM_UNALLOC) {
			ptr->mem_flag |= MEM_CACHE;
			ptr->mem_flag &= ~MEM_UNALLOC;
			ca->itr++;
		        if ( ptr->mem_flag & MEM_LAST )
				ca->itr = ca->memory_cache;
			return ptr;
		}
	}
	
	ptr = kmalloc(sizeof(struct cc_chirp), GFP_KERNEL);
	ptr->mem_flag = MEM_ALLOC;
	return ptr;
}

static void cached_chirp_dealloc(struct tcp_sock *tp, struct cc_chirp *chirp)
{
	if (!chirp)
		return;
	if (chirp->mem_flag & MEM_CACHE) {
		chirp->mem_flag |= MEM_UNALLOC;
	} else if (chirp->mem_flag & MEM_ALLOC) {
		kfree(chirp);
	}
		 
}

static u32 gap_to_Bps_ns(struct sock *sk, struct tcp_sock *tp, u32 gap_ns)
{
	u64 rate;
	if (!gap_ns) return 0;
	rate = tp->mss_cache;
	rate *= NSEC_PER_SEC;
	rate = rate/(u64)gap_ns;
	return (u32)rate;
}


static void exit_paced_chirping(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca)
{
	if (ca->pc_state) {
		tp->snd_cwnd = max(tp->packets_out, 2U);
		tp->snd_ssthresh = tp->snd_cwnd;
	}
	tp->is_chirping = 0;
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
	sk->sk_pacing_rate = ~0U;
	ca->pc_state = 0;
}

static inline void start_new_round(struct tcp_sock *tp, struct dctcp *ca)
{
	if (ca->chirp_number >= 6 && ca->round_sent >= (ca->M>>M_SHIFT)) /* Next chirp to be sent */
		ca->M = (ca->M * ca->gain)>>G_G_SHIFT;

	ca->round_start = ca->chirp_number;
	ca->round_sent = ca->round_length_us = 0;
	
	DEBUG_PRINT(("port=%hu,new_round,start=%u,chirps=%u\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     ca->round_start,
		     ca->M>>M_SHIFT));
}
static u32 should_terminate(struct tcp_sock *tp, struct dctcp *ca)
{
	return tp->srtt_us && ((tp->srtt_us>>3) <= ca->round_length_us);
}
static struct cc_chirp* get_first_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || list_empty(&(ca->chirp_list->list)))
		return NULL;
	return list_first_entry(&(ca->chirp_list->list), struct cc_chirp, list);
}
static struct cc_chirp* get_last_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || list_empty(&(ca->chirp_list->list)))
		return NULL;
	return list_last_entry(&(ca->chirp_list->list), struct cc_chirp, list);
}

static void update_gap_avg(struct tcp_sock *tp, struct dctcp *ca, u32 new_estimate_ns)
{
	u32 prev_estimate_ns = ca->gap_avg_ns;

	if (new_estimate_ns == INVALID_CHIRP) {
		return;
	}
	/* Safety bound for development min 30us, max 10ms (400Mbps ~ 1Mbps)*/
	new_estimate_ns = max(min(new_estimate_ns, 10000000U), 30000U);
	
	if (ca->gap_avg_ns == 0U) {
		ca->gap_avg_ns = new_estimate_ns;
		return;
	}
	ca->gap_avg_ns = prev_estimate_ns -
		(prev_estimate_ns>>GAP_AVG_SHIFT) +
		(new_estimate_ns>>GAP_AVG_SHIFT);
}

static bool enough_data_for_chirp (struct sock *sk, struct tcp_sock *tp, int N)
{
	return SKB_TRUESIZE(tp->mss_cache) * (N + tp->packets_out) <= sk->sk_wmem_queued;
}
static bool enough_data_committed(struct sock *sk, struct tcp_sock *tp)
{
	return SKB_TRUESIZE(tp->mss_cache) * CHIRP_SIZE  < refcount_read(&sk->sk_wmem_alloc);
}

static u32 dctcp_new_chirp (struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	struct cc_chirp *new_chirp;
	struct cc_chirp *last_chirp;
	u32 N = CHIRP_SIZE;
	u32 guard_interval_ns;
	u32 gap_step_ns;
	u32 initial_gap_ns;
	u32 chirp_length_ns;

	if (!tp->is_chirping || !ca->chirp_list || ca->pc_state & STATE_TRANSITION || !(ca->pc_state & STATE_ACTIVE)) {
		DEBUG_PRINT(("port=%hu,dctcp_new_chirp:Called unexpectedly\n",
			     tp->inet_conn.icsk_bind_hash->port));
		return 1;	
	}

	/* Save information */
	if ((last_chirp = get_last_chirp(ca))) {
		if (!last_chirp->fully_sent) {
			last_chirp->begin_seq = tp->chirp.begin_seq;
			last_chirp->end_seq = tp->chirp.end_seq;
			last_chirp->fully_sent = 1;

			DEBUG_PRINT(("port=%hu,chirp%u,sent_at=%llu,out=%u\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     last_chirp->chirp_number,
				     tp->tcp_clock_cache,
				     tp->chirp.packets_out));
		}
	}

	DEBUG_PRINT(("port=%hu,data_queued=%d,required=%lu,data_allocd=%u,e_committed=%u,e_data=%u,sent=%u,M=%u,out=%u\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     sk->sk_wmem_queued,
		     SKB_TRUESIZE(tp->mss_cache) * (N + tp->packets_out),
		     refcount_read(&sk->sk_wmem_alloc),
		     enough_data_committed(sk, tp),
		     enough_data_for_chirp(sk, tp, N),
		     ca->round_sent,
		     ca->M>>M_SHIFT,
		     tp->packets_out));



	/* Do not queue excessively in qDisc etc.*/
	if (enough_data_committed(sk, tp)) {
		DEBUG_PRINT(("port=%hu,Waiting for data to leave Qdisc\n",
			     tp->inet_conn.icsk_bind_hash->port));
		return 1;
	}

	if (ca->round_sent >= (ca->M>>M_SHIFT)) {
		DEBUG_PRINT(("port=%hu,halting chirping because round is scheduled\n",
			     tp->inet_conn.icsk_bind_hash->port));
		return 1;
	}
	  
	if (ca->chirp_number <= 1)
		N = 5;
	else if (ca->chirp_number <= 3)
		N = 8;
	if (!enough_data_for_chirp(sk, tp, N)) /*TODO: Use TCP slow start as fallback.*/ {
		DEBUG_PRINT(("port=%hu,Not enough data for full chirp. Send immediately\n",
			     tp->inet_conn.icsk_bind_hash->port));
		return 0;
	}

	if (!(new_chirp = cached_chirp_malloc(tp, ca))) {
		trace_printk("port=%hu,ERROR_MALLOC\n",
			     tp->inet_conn.icsk_bind_hash->port);
		return 0;	
	}
        
	gap_step_ns = switch_divide((((ca->geometry - (1<<G_G_SHIFT))<<1))*ca->gap_avg_ns , N, 1U) >> G_G_SHIFT;
	initial_gap_ns = (ca->gap_avg_ns * ca->geometry)>>G_G_SHIFT;
	chirp_length_ns = initial_gap_ns + (((N-2) * ((initial_gap_ns<<1) - N*gap_step_ns + gap_step_ns))>>1);
	guard_interval_ns = switch_divide((tp->srtt_us>>3), (ca->M>>M_SHIFT), 0) << 10;
	guard_interval_ns = (guard_interval_ns > chirp_length_ns) ? max(ca->gap_avg_ns, guard_interval_ns - chirp_length_ns): ca->gap_avg_ns;

	/* Provide the kernel with the pacing information */
	tp->chirp.packets = new_chirp->N = N;
	tp->chirp.gap_ns = initial_gap_ns;
	tp->chirp.gap_step_ns = gap_step_ns;
	tp->chirp.guard_interval_ns = guard_interval_ns;
	tp->chirp.scheduled_gaps = new_chirp->scheduled_gaps;
	tp->chirp.packets_out = 0;

	
	/* Save needed info */
	new_chirp->chirp_number = ca->chirp_number++;
	new_chirp->end_seq = new_chirp->begin_seq = tp->snd_nxt;
	new_chirp->qdelay_index = 0;
	new_chirp->fully_sent = 0;
	

	ca->round_sent += 1;
	ca->round_length_us += chirp_length_ns>>10;
	
	list_add_tail(&(new_chirp->list), &(ca->chirp_list->list));
	tp->snd_cwnd += N;
	
	DEBUG_PRINT(("port=%hu,schedule_chirp=%u,at=%llu,N=%u,gap=%u,step=%u,guard=%u,cwnd=%u,length=%u,rtt=%u\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     new_chirp->chirp_number,
		     tp->tcp_clock_cache,
		     tp->chirp.packets,
		     tp->chirp.gap_ns,
		     tp->chirp.gap_step_ns,
		     tp->chirp.guard_interval_ns,
		     tp->snd_cwnd,
		     ca->round_length_us,
		     tp->srtt_us>>3));

	return 0;
}




static void dctcp_release(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *chirp;
	if (ca->chirp_list) {
		while ((chirp = get_first_chirp(ca))) {
			list_del(&(chirp->list));
			cached_chirp_dealloc(tp, chirp);
		}
		kfree(ca->chirp_list);
	}
	if (ca->memory_cache)
		kfree(ca->memory_cache);
}

static u32 analyze_chirp(struct sock *sk, struct cc_chirp *chirp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 N = chirp->qdelay_index;
	int i, j, l = N-1;
	u64 gap_avg = 0;
	u32 *q = chirp->qdelay;
	ktime_t *s;
	u32 L = dctcp_pc_L;
	u32 max_q = 0;
	u32 excursion_cnt = 0;
	u32 excursion_start = 0;
	u32 E[CHIRP_SIZE];
	
	int q_diff = 0;

	if (N < 2)
		return INVALID_CHIRP;

	s = chirp->scheduled_gaps;
	
	print_u64_array((u64*)s, N, "sendtimes", tp);
	print_u32_array(q, N, "queue", tp);
										     
	for (i = 1; i < N; ++i) {
		E[i] = 0;
		/*Check if currently tracking a possible excursion*/
		q_diff = (int)q[i] - (int)q[excursion_start];
		
		if(excursion_cnt && q_diff >= 0 &&
		   ((u32)q_diff > ((max_q>>1) + (max_q>>3)))) {
			max_q = max(max_q, (u32)q_diff);
			excursion_cnt++;
		} else { /*Excursion has ended or never started.*/
			if (excursion_cnt >= L) {
				for (j = excursion_start;
				     j < excursion_start + excursion_cnt;
				     ++j) {
					if (q[j] < q[j+1])
						E[j] = (uint32_t)s[j];
				}
			}
			excursion_cnt = excursion_start = max_q = 0;
		}
		
		/*Start new excursion*/
		if (!excursion_cnt && (i < (N-1)) && (q[i] < q[i+1])) {
			excursion_start = i;
			max_q = 0U;
			excursion_cnt = 1;
		}
	}

	/* Unterminated excursion */
	if (excursion_cnt && (excursion_cnt+excursion_start) == N ) {
		for (j = excursion_start;
		     j < (excursion_start + excursion_cnt);
		     ++j) {
			E[j] = (uint32_t)s[excursion_start];
		}
		l = excursion_start;
	}

	/*Calculate the average gap*/
	for (i = 1; i < N; ++i) {
		if (E[i] == 0)
			gap_avg += (uint32_t)s[l];
		else
			gap_avg += E[i];
	}
	print_u32_array(E, N, "E", tp);

	gap_avg = gap_avg/(N-1);
	if (gap_avg > U32_MAX)
		gap_avg = INVALID_CHIRP;
	return gap_avg;
}

static void dctcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    	struct cc_chirp *cur_chirp = NULL;
	u32 rtt_us = sample->rtt_us;
	int i;
	u32 new_estimate;

	if (!ca->pc_state || rtt_us == 0)
		return;

	/* We have terminated, but are waiting for scheduled packet to be sent*/
	if (ca->pc_state & STATE_TRANSITION) {
		if ((ca->round_sent++ > (ca->round_start)))
			exit_paced_chirping(sk, tp, ca);
		return;
	}
	for (i = 0; i < sample->pkts_acked; ++i) {
		if (!cur_chirp && !(cur_chirp = get_first_chirp(ca)))
			break;
		if (!before(cur_chirp->begin_seq, tp->snd_una)) {
			DEBUG_PRINT(("port=%hu,ignoring_ack for chirp %u,begin=%u,una=%u,end=%u\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     cur_chirp->chirp_number,
				     cur_chirp->begin_seq,
				     tp->snd_una,
				     cur_chirp->end_seq
					    ));
			continue;
		}

		if (cur_chirp->chirp_number >= 2U && cur_chirp->chirp_number == ca->round_start
		    && cur_chirp->qdelay_index == 0) {
			start_new_round(tp, ca);
		}

		if (cur_chirp->qdelay_index != cur_chirp->N) {
			/*Does not matter if we use minimum rtt for this chirp of for the duration of
			 * the connection because the analysis uses relative queue delay in analysis.
			 * Assumes no reordering or loss. Have to link seq number to array index. */
			cur_chirp->qdelay[cur_chirp->qdelay_index++] = rtt_us - tcp_min_rtt(tp);
		}

		
		
		/*Chirp is completed*/
		if (cur_chirp->qdelay_index >= cur_chirp->N &&
		    (cur_chirp->fully_sent && !after(cur_chirp->end_seq, tp->snd_una))) {
			
			new_estimate = analyze_chirp(sk, cur_chirp);
			update_gap_avg(tp, ca, new_estimate);
			DEBUG_PRINT(("port=%hu,chirp_analysed=%u,new_estimate=%u,new_avg=%u\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     cur_chirp->chirp_number,
				     new_estimate,
				     ca->gap_avg_ns));
			
			/* Second round starts when the first chirp has been analyzed. */
			if (cur_chirp->chirp_number == 0U) {
				start_new_round(tp, ca);
			}
			list_del(&(cur_chirp->list));
			cached_chirp_dealloc(tp, cur_chirp);
			cur_chirp = NULL;

			if (should_terminate(tp, ca)) {
				u32 rate = gap_to_Bps_ns(sk, tp, min(5000000U, ca->gap_avg_ns));
				sk->sk_pacing_rate = rate;

				/*Send for one bdp*/
				ca->round_sent = 0;
				ca->round_start = (u32)((u64)(tcp_min_rtt(tp) * 1000U)/max(1U, (u32)ca->gap_avg_ns));
				tp->snd_cwnd = max((u32)(ca->round_start<<1), 10U);
				DEBUG_PRINT(("port=%hu,final_gap=%u,cwnd=%d,target=%u,rate_Bps=%u\n",
					     tp->inet_conn.icsk_bind_hash->port,
					     ca->gap_avg_ns, tp->snd_cwnd, ca->round_start,rate));
		
				ca->pc_state |= STATE_TRANSITION;
				tp->is_chirping = 0;
			}
		}
	}
}

/* Modification of tcp_reno_cong_avoid */
static void dctcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk) || ca->pc_state)
		return;

	/* In "safe" area, increase. */
	if ((tp->snd_cwnd <= tp->snd_ssthresh)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

static void init_paced_chirping(struct sock *sk, struct tcp_sock *tp,
				struct dctcp *ca)
{
	int i;
	ca->chirp_list = kmalloc(sizeof(*ca->chirp_list), GFP_KERNEL);
	if (!ca->chirp_list) {
		return;
	}
	INIT_LIST_HEAD(&(ca->chirp_list->list));

	ca->memory_cache = ca->itr = NULL;
	if (MEMORY_CACHE_SIZE_CHIRPS) {
		ca->memory_cache = kmalloc(MEMORY_CACHE_SIZE_BYTES, GFP_KERNEL);
		if (ca->memory_cache) {
			ca->itr = ca->memory_cache;
			for (i = 0; i < MEMORY_CACHE_SIZE_CHIRPS; ++i)
				ca->memory_cache[i].mem_flag = MEM_UNALLOC;
			ca->memory_cache[MEMORY_CACHE_SIZE_CHIRPS-1].mem_flag |= MEM_LAST;
		}
	}

	/* Alter kernel behaviour*/
	sk->sk_pacing_rate = ~0U; /*This disables pacing until I explicitly set it.*/
	sk_pacing_shift_update(sk, 5);
	tp->disable_kernel_pacing_calculation = 1;
	tp->disable_cwr_upon_ece = 1;
	tp->is_chirping = 1;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		
	ca->gap_avg_ns = 200000; /* 200 us */
	ca->chirp_number = 0;
	ca->round_start = 0;
	ca->round_sent = 0;
	ca->round_length_us = 0;
		
	ca->M = (2<<M_SHIFT);
	ca->gain = max(dctcp_pc_initial_gain, 1U << G_G_SHIFT);
	ca->geometry = min(max(dctcp_pc_initial_geometry, 1U << G_G_SHIFT), 3U << G_G_SHIFT);

	ca->pc_state = STATE_ACTIVE;
}


static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

static void dctcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

		ca->loss_cwnd = 0;
		ca->ce_state = 0;

		ca->pc_state = 0;
		if (dctcp_pc_enabled)
			init_paced_chirping(sk, tp, ca);

		dctcp_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for DCTCP.
	 */
	inet_csk(sk)->icsk_ca_ops = &dctcp_reno;
	INET_ECN_dontxmit(sk);

	/*Exit paced chirping if initialized with it*/
	ca->pc_state = 0;
	exit_paced_chirping(sk, tp, ca);
}

static u32 dctcp_ssthresh(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

static void dctcp_update_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u32 alpha = ca->dctcp_alpha;

		/* alpha = (1 - g) * alpha + g * F */

		alpha -= min_not_zero(alpha, alpha >> dctcp_shift_g);
		if (bytes_ecn) {
			/* If dctcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - dctcp_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, DCTCP_MAX_ALPHA);
		}
		/* dctcp_alpha can be read from dctcp_get_info() without
		 * synchro, so we ask compiler to not use dctcp_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->dctcp_alpha, alpha);
		dctcp_reset(tp, ca);
	}
}

static void dctcp_state(struct sock *sk, u8 new_state)
{
	if (dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	} else if (new_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);
		if (ca->pc_state) {
			exit_paced_chirping(sk, tcp_sk(sk), ca);
		}
	}
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
        struct dctcp *ca = inet_csk_ca(sk);
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
	case CA_EVENT_ECN_NO_CE:
	        dctcp_ece_ack_update(sk, ev, &ca->prior_rcv_nxt, &ca->ce_state);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t dctcp_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->dctcp, 0, sizeof(info->dctcp));
		if (inet_csk(sk)->icsk_ca_ops != &dctcp_reno) {
			info->dctcp.dctcp_enabled = 1;
			info->dctcp.dctcp_ce_state = (u16) ca->ce_state;
			info->dctcp.dctcp_alpha = ca->dctcp_alpha;
			info->dctcp.dctcp_ab_ecn = ca->acked_bytes_ecn;
			info->dctcp.dctcp_ab_tot = ca->acked_bytes_total;
		}

		*attr = INET_DIAG_DCTCPINFO;
		return sizeof(info->dctcp);
	}
	return 0;
}

static u32 dctcp_cwnd_undo(struct sock *sk)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static struct tcp_congestion_ops dctcp __read_mostly = {
	.init		= dctcp_init,
	.in_ack_event   = dctcp_update_alpha,
	.cwnd_event	= dctcp_cwnd_event,
	.ssthresh	= dctcp_ssthresh,
	/*.cong_avoid	= tcp_reno_cong_avoid,*/

	.cong_avoid     = dctcp_cong_avoid,
	.release        = dctcp_release,
	.pkts_acked     = dctcp_acked,
	.new_chirp      = dctcp_new_chirp,
	
	.undo_cwnd	= dctcp_cwnd_undo,
	.set_state	= dctcp_state,
	.get_info	= dctcp_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "chirping",
};

static struct tcp_congestion_ops dctcp_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= dctcp_get_info,
	.owner		= THIS_MODULE,
	.name		= "dctcp-reno",
};

static int __init dctcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct dctcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&dctcp);
}

static void __exit dctcp_unregister(void)
{
	tcp_unregister_congestion_control(&dctcp);
}

module_init(dctcp_register);
module_exit(dctcp_unregister);

MODULE_AUTHOR("Daniel Borkmann <dborkman@redhat.com>");
MODULE_AUTHOR("Florian Westphal <fw@strlen.de>");
MODULE_AUTHOR("Glenn Judd <glenn.judd@morganstanley.com>");
MODULE_AUTHOR("Joakim Misund <joakimmi@ifi.uio.no>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DataCenter TCP (DCTCP)");








































static void print_u32_array(u32 *array, u32 size, char *name, struct tcp_sock *tp)
{
	char buf[1000];
	char *ptr = buf;
	int i;
	
	ptr += snprintf(ptr, 1000, "port=%hu,%s:", tp->inet_conn.icsk_bind_hash->port, name);

	for (i = 0; i < size; ++i) {
		if (!ptr)
			continue;

		ptr += snprintf(ptr, 15, "%u,", array[i]); 
	}

	DEBUG_PRINT((buf));
}
static void print_u64_array(u64 *array, u32 size, char *name, struct tcp_sock *tp)
{
	char buf[1000];
	char *ptr = buf;
	int i;
	
	ptr += snprintf(ptr, 1000, "port=%hu,%s:", tp->inet_conn.icsk_bind_hash->port, name);

	for (i = 0; i < size; ++i) {
		if (!ptr)
			continue;

		ptr += snprintf(ptr, 30, "%llu,", array[i]); 
	}

	DEBUG_PRINT((buf));
}
