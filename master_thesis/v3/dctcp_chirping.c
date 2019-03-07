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

/* Paced Chirping flow start extension can be enabled by setting sysctl dctcp_pc_enabled to 1.
 * Paced chirping is described in https://riteproject.files.wordpress.com/2018/07/misundjoakimmastersthesissubmitted180515.pdf
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>

#define DCTCP_MAX_ALPHA	1024U

/*Ifdefs for paced chirping*/
#define INVALID_CHIRP UINT_MAX
#define STATE_TRANSITION 0x20
#define STATE_ACTIVE 0x10
#define STATE_MARK_SENT 0x40
#define GAP_AVG_SHIFT 1
#define M_SHIFT 7                 /*M is the number of chirps in the current round*/
#define G_G_SHIFT 10

#define CHIRP_SIZE 16U
#define MEMORY_PER_CHIRP_BYTES (sizeof(struct chirp) + sizeof(struct chirp_descr) + (sizeof(u32) + sizeof(ktime_t)) * CHIRP_SIZE)
#define MEMORY_CACHE_SIZE_CHIRPS 20U
#define MEMORY_CACHE_SIZE_BYTES (MEMORY_PER_CHIRP_BYTES * MEMORY_CACHE_SIZE_CHIRPS)

#define MEM_UNALLOC 0x01
#define MEM_CACHE 0x02
#define MEM_ALLOC 0x03
#define MEM_LAST 0x10

/*
struct chirp_descr {
	u16 N;
	u16 gaps_used;
	u32 initial_gap_ns;
	u32 gap_step_ns;
	u32 guard_interval_ns;
	
	ktime_t *timestamps_ktime;
	u32 begin_seq; //seq of first packet in chirp
	u32 end_seq; //seq of last packet in chirp
};
*/




struct chirp {
	struct list_head list;
	u16 chirp_number;
	u16 qdelay_index; /* = N - gaps_used*/
	u32 *qdelay;

	u8 mem_flag;

	struct chirp_descr *dscr;
};



struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u32 loss_cwnd;

	/* Paced Chirping vars */
	u8 pc_state;
	struct chirp *chirp_list;

	u32 gap_avg_ns;
	u32 round_length_us; /*Used for termination condition*/
	u16 chirp_number;
	u16 M;               /*Maximum number of chirps in a round*/
	u16 round_start;     /*Chirp number of the first chirp in the round*/
	u16 round_sent;      /*Number of chirps sent in the round*/
	u16 gain;
	u16 geometry;
	u32 MAD;
	char *memory_cache;
	char *itr;
};

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = DCTCP_MAX_ALPHA;
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


static void print_u32_array(u32 *array, u32 size, char *name, struct tcp_sock *tp);
static void print_u64_array(u64 *array, u32 size, char *name, struct tcp_sock *tp);
static struct chirp* cached_chirp_malloc(struct tcp_sock *tp, struct dctcp *ca);
static void cached_chirp_dealloc(struct tcp_sock *tp, struct chirp *chirp);
static uint32_t switch_divide(uint32_t value, uint32_t by, u8 round_up);

static void exit_paced_chirping(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca);
static struct chirp* get_current_chirp(struct dctcp *ca);
static int check_app_limited(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca);
static u32 gap_to_Bps_ns(struct sock *sk, struct tcp_sock *tp, u32 gap_ns);


static void exit_paced_chirping(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca)
{	
	ca->pc_state = 0;
	tp->snd_cwnd = max(tp->packets_out, 2U);
	tp->snd_ssthresh = max(tp->snd_cwnd, (u32)TCP_INIT_CWND);
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;
	tp->is_chirping = 0;
	sk->sk_pacing_rate = ~0U;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
}

static int whole_chirp_sent(struct chirp *chirp)
{
	return chirp->dscr->end_seq || chirp->dscr->gaps_used >= chirp->dscr->N;
}

static inline void start_new_round(struct dctcp *ca)
{
	ca->round_start = ca->chirp_number;
	ca->round_sent = ca->round_length_us = 0;
	if (ca->chirp_number >= 6 &&  (ca->M>>M_SHIFT) < 20U)
		ca->M = (ca->M * (ca->gain>>G_G_SHIFT));
}
static u32 should_terminate(struct tcp_sock *tp, struct dctcp *ca)
{
	return (tp->srtt_us && (tp->srtt_us>>3) <= ca->round_length_us);
}
static struct chirp* get_current_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || list_empty(&(ca->chirp_list->list)))
		return NULL;
	return list_first_entry(&(ca->chirp_list->list), struct chirp, list);
}

static void update_gap_avg(struct tcp_sock *tp, struct dctcp *ca, u32 new_estimate_ns)
{
	u32 prev_estimate_ns = ca->gap_avg_ns;
	s32 error;

	if (new_estimate_ns == INVALID_CHIRP ||
	    new_estimate_ns > 10000000U) {
		return;
	}
	if (ca->gap_avg_ns == 0U) {
		ca->gap_avg_ns = new_estimate_ns;
		return;
	}
	ca->gap_avg_ns = prev_estimate_ns -
		(prev_estimate_ns>>GAP_AVG_SHIFT) +
		(new_estimate_ns>>GAP_AVG_SHIFT);
	error = (s32)new_estimate_ns - (s32)prev_estimate_ns;
	ca->MAD = (ca->MAD>>1) + (abs(error)>>1);
}
static struct chirp_descr* dctcp_get_chirp (struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	struct chirp *new_chirp;
	u32 N = CHIRP_SIZE;
	u32 guard_interval_ns;
	u32 gap_step_ns;
	u32 initial_gap_ns;
	u32 chirp_length_ns;

	if (!tp->is_chirping ||
	    !ca->chirp_list ||
	    ca->pc_state & STATE_TRANSITION ||
	    !(ca->pc_state & STATE_ACTIVE))
		return NULL;
	
	if (ca->chirp_number > 2 && ca->round_sent >= (ca->M>>M_SHIFT)) {
		start_new_round(ca);
	}

	if (ca->chirp_number == 0 || ca->chirp_number == 1)
		N = 5;
	else if (ca->chirp_number == 2 || ca->chirp_number == 3)
		N = 8;

	/* Allocate memory for information about chirp.
	* Decided to allocate memory for 16 packet chirps regardless of the value of N */
	if (!(new_chirp = cached_chirp_malloc(tp, ca))) {
		trace_printk("port=%hu,ERROR_MALLOC\n",
			     tp->inet_conn.icsk_bind_hash->port);
		return NULL;	
	}
	new_chirp->dscr = (struct chirp_descr*) (new_chirp + 1);
	new_chirp->dscr->timestamps_ktime = (ktime_t*) (new_chirp->dscr + 1);
	new_chirp->qdelay = (u32*) (new_chirp->dscr->timestamps_ktime + CHIRP_SIZE);

	guard_interval_ns = switch_divide((tp->srtt_us>>3), (ca->M>>M_SHIFT), 0) << 10;
	gap_step_ns = switch_divide((((ca->geometry - (1<<G_G_SHIFT))<<1))*ca->gap_avg_ns , N, 1U) >> G_G_SHIFT;
	initial_gap_ns = (ca->gap_avg_ns * ca->geometry)>>G_G_SHIFT;
	chirp_length_ns = initial_gap_ns + (((N-2) * ((initial_gap_ns<<1) - N*gap_step_ns + gap_step_ns))>>1);
	
	guard_interval_ns = (guard_interval_ns > chirp_length_ns) ? max(ca->gap_avg_ns, guard_interval_ns - chirp_length_ns): ca->gap_avg_ns;

	new_chirp->dscr->N = N;
	new_chirp->dscr->gaps_used = 0;
	new_chirp->dscr->guard_interval_ns = guard_interval_ns;
	new_chirp->dscr->initial_gap_ns = initial_gap_ns;
	new_chirp->dscr->gap_step_ns = gap_step_ns;
	new_chirp->dscr->begin_seq = tp->snd_nxt;
	new_chirp->dscr->end_seq = 0;
	

	new_chirp->chirp_number = ca->chirp_number++;
	new_chirp->qdelay_index = 0;
	
	tp->snd_cwnd += N;
	list_add_tail(&(new_chirp->list), &(ca->chirp_list->list));
	ca->round_sent += 1;
	ca->round_length_us += chirp_length_ns>>10;

	return new_chirp->dscr;
}




static void dctcp_release(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct chirp *chirp;
	tp->is_chirping = 0;
	return;
	if (ca->chirp_list) {
		list_for_each_entry(chirp, &(ca->chirp_list->list), list) {
			cached_chirp_dealloc(tp, chirp);
		}
		kfree(ca->chirp_list);
	}
	if (ca->memory_cache)
		kfree(ca->memory_cache);
}

static u32 analyze_chirp(struct sock *sk, struct chirp *chirp)
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

	s = chirp->dscr->timestamps_ktime;
	
	print_u64_array(chirp->dscr->timestamps_ktime, N, "ktime", tp);
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
    	struct chirp *cur_chirp = NULL;
	u32 rtt_us = sample->rtt_us;
	int i;
	u32 new_estimate;

	if (!(ca->pc_state & STATE_ACTIVE) || rtt_us == 0)
		return;

	/* We have terminated, but are waiting for scheduled packet to be sent or 
	 * the number of in-flight packets to reach a certain target. */
	if (ca->pc_state & STATE_TRANSITION) {
		/*In TRANSITION, round_sent is ack number
		  from exhausting the pacing list. packets_out is
		  the target number of packets in flight.
		  This is done to conserve space.*/
		if ((ca->round_sent++ > (ca->round_start)))
			exit_paced_chirping(sk, tp, ca);
		return;
	}
	
	for (i = 0; i < sample->pkts_acked; ++i) {

		if (!cur_chirp && !(cur_chirp = get_current_chirp(ca)))
			break;
		
		if (cur_chirp->qdelay_index == 0) {
			if (!before(cur_chirp->dscr->begin_seq, tp->snd_una)) {
				trace_printk("port=%hu,ignoring_ack,begin=%u,una=%u,end=%u\n",
					     tp->inet_conn.icsk_bind_hash->port,
					     cur_chirp->dscr->begin_seq,
					     tp->snd_una,
					     cur_chirp->dscr->end_seq
					);
				continue;
			}
		}
		trace_printk("port=%hu,accept_ack,begin=%u,una=%u,end=%u\n",
					     tp->inet_conn.icsk_bind_hash->port,
					     cur_chirp->dscr->begin_seq,
					     tp->snd_una,
					     cur_chirp->dscr->end_seq
					);

		if (cur_chirp->qdelay_index == cur_chirp->dscr->N-1
		    && (!whole_chirp_sent(cur_chirp) || after(cur_chirp->dscr->end_seq, tp->snd_una)))
			continue;
		if (cur_chirp->qdelay_index != cur_chirp->dscr->N) {
			tp->snd_cwnd--;
			/*Does not matter if we use minimum rtt for this chirp of for the duration of
			 * the connection because the analysis uses relative queue delay in analysis.
			 * Assumes no reordering or loss. Have to link seq number to array index. */
			cur_chirp->qdelay[cur_chirp->qdelay_index++] = rtt_us - tcp_min_rtt(tp);
		}

		
		
		/*Chirp is completed*/
		if (cur_chirp->qdelay_index >= cur_chirp->dscr->N) {
			
			new_estimate = analyze_chirp(sk, cur_chirp);
			//update_gap_avg(tp, ca, new_estimate);
			trace_printk("port=%hu,new_estimate=%u,new_avg=%u\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     new_estimate,
				     ca->gap_avg_ns);
			
			/* Second round starts when the first chirp has been analyzed. */
			if (cur_chirp->chirp_number == 0U) {
				start_new_round(ca);
				tp->snd_cwnd++;
			}
			list_del(&(cur_chirp->list));
			if (cur_chirp->dscr->end_seq)
				cached_chirp_dealloc(tp, cur_chirp);
			cur_chirp = NULL;
		}
	}

	if (should_terminate(tp, ca)) {
		u32 rate = gap_to_Bps_ns(sk, tp, min(1000000U, ca->gap_avg_ns));
		ACCESS_ONCE(sk->sk_pacing_rate) = rate;


		ca->round_sent = 0;
		ca->round_start = (u32)((u64)(tcp_min_rtt(tp) * 1000U)/max(1U, (u32)ca->gap_avg_ns));
		tp->snd_cwnd = ca->round_start<<1;
		tp->snd_cwnd = max(tp->snd_cwnd, 10U);
		trace_printk("port=%hu,final_gap=%u,cwnd=%d,target=%u,rate=%u\n",
			     tp->inet_conn.icsk_bind_hash->port,
			     ca->gap_avg_ns, tp->snd_cwnd, ca->round_start,rate);
		
		ca->pc_state |= STATE_TRANSITION;
		tp->is_chirping = 0;
	}
}

/* Modification of tcp_reno_cong_avoid */
static void dctcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk) || (ca->pc_state & STATE_ACTIVE))
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
	if (MEMORY_CACHE_SIZE_CHIRPS) {
		ca->memory_cache = kmalloc(MEMORY_CACHE_SIZE_BYTES, GFP_KERNEL);
		if (!ca->memory_cache) {
			trace_printk("port=%hu,memory_cache failed size:%lu\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     MEMORY_CACHE_SIZE_BYTES);
		} else {
			ca->itr = ca->memory_cache;
			trace_printk("port=%hu,Allocated:%lu,per_chirp:%lu,end:%p\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     MEMORY_CACHE_SIZE_BYTES,
				     MEMORY_PER_CHIRP_BYTES,
				     ca->memory_cache + MEMORY_CACHE_SIZE_BYTES - MEMORY_PER_CHIRP_BYTES);
			for (i = 0; i < MEMORY_CACHE_SIZE_CHIRPS; ++i)
				((struct chirp *)(ca->memory_cache + i * MEMORY_PER_CHIRP_BYTES))->mem_flag = MEM_UNALLOC;
			((struct chirp *)(ca->memory_cache + (MEMORY_CACHE_SIZE_CHIRPS-1) * MEMORY_PER_CHIRP_BYTES))->mem_flag |= MEM_LAST;
		}
	}
	
	INIT_LIST_HEAD(&(ca->chirp_list->list));
	/* Alter kernel behaviour*/
	/* Actually, setting to ~0 instead of 0 is important (?) to avoid issues with TSQ.*/
	sk->sk_pacing_rate = ~0; /*This disables pacing until I explicitly set it.*/
	tp->disable_kernel_pacing_calculation = 1;
	tp->disable_cwr_upon_ece = 1;
	tp->is_chirping = 1;

	/*Note that if FQ is attached to outgoing interface we are probably screwed*/
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		
	ca->gap_avg_ns = 100000; /* 100 us */
	ca->chirp_number = 0;
	ca->round_start = 0;
	ca->round_sent = 0;
	ca->round_length_us = 0;
	ca->MAD = 0;
		
	ca->M = (2<<M_SHIFT);
	ca->gain = max(dctcp_pc_initial_gain, 1U << G_G_SHIFT);
	ca->geometry = min(max(dctcp_pc_initial_geometry, 1U << G_G_SHIFT), 3U << G_G_SHIFT);

	ca->pc_state = STATE_ACTIVE;
}

/* END OF NEW FUNCTIONALITY */

static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

static void dctcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		struct dctcp *ca = inet_csk_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

		ca->delayed_ack_reserved = 0;
		ca->loss_cwnd = 0;
		ca->ce_state = 0;

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
}

static u32 dctcp_ssthresh(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void dctcp_ce_state_0_to_1(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
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
		struct tcp_sock *tp = tcp_sk(sk);
		exit_paced_chirping(sk, tp, ca);
	}
}

static void dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct dctcp *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		dctcp_update_ack_reserved(sk, ev);
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
	.get_chirp      = dctcp_get_chirp,
	
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


































static u32 gap_to_Bps_ns(struct sock *sk, struct tcp_sock *tp, u32 gap_ns)
{
	u64 rate;
	if (!gap_ns)
		return 0;
	rate = tp->mss_cache;
	rate *= NSEC_PER_SEC;
	rate = rate/(u64)gap_ns;
	return (u32)rate;
}





static int check_app_limited(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca)
{
	int app_limited = 0;

	trace_printk("port=%hu,free=%u,mss=%u\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     tp->write_seq - tp->snd_nxt, (tp->mss_cache<<4));
	/*if(tp->write_seq - tp->snd_nxt < (tp->mss_cache<<1))
		app_limited = 1;
	*/if (app_limited) {
		exit_paced_chirping(sk, tp, ca);
		
		tp->snd_cwnd = TCP_INIT_CWND;
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
		
		trace_printk("port=%hu,app_limited!\n",
			     tp->inet_conn.icsk_bind_hash->port);
		
		return 1;
	}
	return 0;
}






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

	trace_printk(buf);
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

	trace_printk(buf);
}


static struct chirp* cached_chirp_malloc(struct tcp_sock *tp, struct dctcp *ca)
{
	struct chirp* ptr;

	if (ca->memory_cache) {
		ptr = (struct chirp *) ca->itr;
		if (ptr->mem_flag & MEM_UNALLOC) {
			ptr->mem_flag |= MEM_CACHE;
			ptr->mem_flag &= ~MEM_UNALLOC;
			ca->itr += MEMORY_PER_CHIRP_BYTES;
			if ( ptr->mem_flag & MEM_LAST )
				ca->itr -= MEMORY_CACHE_SIZE_BYTES;
			trace_printk("port=%hu,cached_alloc:%p\n",
				     tp->inet_conn.icsk_bind_hash->port,
				     (char*)ptr);
			return ptr;
		}
	}
	
	ptr = kmalloc(MEMORY_PER_CHIRP_BYTES, GFP_KERNEL);
	ptr->mem_flag |= MEM_ALLOC;
	trace_printk("port=%hu,regular_alloc:%p\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     (char*)ptr);
	return ptr;
}

static void cached_chirp_dealloc(struct tcp_sock *tp, struct chirp *chirp)
{
	if (!chirp)
		return;
	if (chirp->mem_flag & MEM_CACHE) {
		chirp->mem_flag |= MEM_UNALLOC;
		trace_printk("port=%hu,cached_free:%p\n",
			     tp->inet_conn.icsk_bind_hash->port,
			     (char*)chirp);
	} else if (chirp->mem_flag & MEM_ALLOC) {
		kfree((char*)chirp);
		trace_printk("port=%hu,regular_free:%p\n",
			     tp->inet_conn.icsk_bind_hash->port,
			     (char*)chirp);
	}
		 
}

static uint32_t switch_divide(uint32_t value, uint32_t by, u8 round_up)
{
	switch(by) {
	case 1:
		return value;
	case 2:
		return value >> 1;
	case 4:
		return value >> 2;
	case 8:
		return value >> 3;
	case 16:
		return value >> 4;
	case 32:
		return value >> 5;
	case 0:
		trace_printk("Divide by zero!\n");
		return value;
	}
	if (round_up) {
		return DIV_ROUND_UP(value, by);
	} else {
		return value/by;
	}
			
}
