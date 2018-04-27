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

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/version.h>
#include <linux/random.h>

#define DCTCP_MAX_ALPHA	1024U

/********************* NEW Definitions **********************************/
#define CONGESTION_ECN 0x02

#define BURST_AND_CHIRP 0

#define DISCARD_INVALID_CHIRPS 1
#define INVALID_CHIRP UINT_MAX

#define ACCELERATE_AFTER_LIST_EMPTY 1
#define TRANSITION 0x40

#define MAX_N 16U

#define EST_EWMA_SHIFT 1 
#define MAX_NUM_CHIRPS_IN_ROUND_SHIFT 7

/** Printing and measurments **/
#define TRACE_PRINTK 0
#define DO_TIME 0


struct chirp {
	struct list_head list;
	u32 id;
	u32 N;
	u32 index;                  /* Index used for Queue delay and inter arrival time */
	u32 rate_entries_examined;  /* Index for recorded inter send times and examine entries */
	
	u32 start_seq;
	u32 end_seq;

	u64 last_ack_time_ns;       /* Used for inter-arrival time of acks */
	ktime_t prev_timestamp;     /* Used for recorded inter send times */

	u32 new_to_send;            /* Used to limit number of chirps scheduled with the same estimate */

	u32 q_delay[MAX_N];
	u32 recorded_inter_send_time_us[MAX_N];
	u32 inter_arrival_time_ns[MAX_N]; /* Can be reduced to 5 or just be a sum..
					   A sum does not allow for post-collection filtering of 
					   measurements.*/
};

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u8 ce_state;
	u8 delayed_ack_reserved;
	u32 loss_cwnd;

	/*********************** NEW variables ****************************/
	u8 in_initial_slow_start;
	u8 slow_start_state;

	struct chirp *chirp;
	u16 chirp_list_size;

	u16 gap_avg_us;
	u32 round_length;
	u16 chirp_number;
	u32 max_num_chirps_in_round;
	u16 round_start;
	u16 round_sent;
	u16 gain;
	u16 geometry;
	u32 MAD;

};

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = 1;//DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

static unsigned int dctcp_ss_gain __read_mostly = 200; /* gain times 100 */
module_param(dctcp_ss_gain, uint, 0644);
MODULE_PARM_DESC(dctcp_ss_gain, "gain for slow start");

static unsigned int dctcp_chirp_geometry __read_mostly = 200; /* geometry times 100 */
module_param(dctcp_chirp_geometry, uint, 0644);
MODULE_PARM_DESC(dctcp_chirp_geometry, "geometry of chirps");

static unsigned int dctcp_chirp_L __read_mostly = 5;
module_param(dctcp_chirp_L, uint, 0644);
MODULE_PARM_DESC(dctcp_chirp_L, "Chirp L. Excursion length");

static struct tcp_congestion_ops dctcp_reno;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)


/* Here follow some debugging functions. */
static void print_chirp(struct tcp_sock *tp, struct chirp *chirp)
{
#if TRACE_PRINTK
	trace_printk("port=%hu,CID=%u,start=%u,end=%u,size=%u,index=%u,rate_entries_examined=%u,cwnd=%u\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     chirp->id,
		     chirp->start_seq,
		     chirp->end_seq,
		     chirp->N,
		     chirp->index,
		     chirp->rate_entries_examined,
		     tp->snd_cwnd

		);
#endif
}

static void print_u32_array(u32 *array, u32 size, char *name, struct tcp_sock *tp)
{
	#if TRACE_PRINTK
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
	#endif
}

static inline ktime_t start_timer(void)
{
#if DO_TIME
	return ktime_get();
#else
	return 0;
#endif
}


static inline void end_timer(ktime_t start_time, char *function_name, struct tcp_sock *tp)
{
#if DO_TIME
	trace_printk("port=%hu,func=%s,time_ns=%llu\n",
		     tp->inet_conn.icsk_bind_hash->port,
		     function_name,
		     (ktime_to_ns(ktime_get()) - ktime_to_ns(start_time)));
#else
	return;
#endif
}
/******************************** End debugging functions *****************************************/

static void update_gap_estimate(struct tcp_sock *tp, struct dctcp *ca, u32 new_estimate)
{
	u32 prev_estimate = ca->gap_avg_us;
	s32 error;
	u32 shift = EST_EWMA_SHIFT;

	if (new_estimate == INVALID_CHIRP) {
		return;
	}

	if (ca->gap_avg_us == 0U) {
		ca->gap_avg_us = new_estimate;
		return;
	}

	//shift = min(3U, max(1U, 4U - (ca->gain-100U)/25));
	
	error = (s32)new_estimate - (s32)prev_estimate;
	ca->gap_avg_us = prev_estimate - (prev_estimate>>shift) + (new_estimate>>shift);

	ca->MAD = (ca->MAD>>1) + (abs(error)>>1);
}

static void update_gain_and_geometry(struct tcp_sock *tp, struct dctcp *ca)
{
	u32 threshold = 30U;
	u32 fraction = (ca->MAD<<10) / threshold;
	
	if(threshold < ca->MAD) {
		ca->gain = 120U;
		ca->geometry = min(200U, ca->geometry + 40U);
	} else {
		ca->gain = min(300U, ca->gain + 20U);
		ca->geometry = max(120U, ca->geometry - 20U);
	}
}

static inline void start_new_round(struct dctcp *ca)
{
	ca->round_start = ca->chirp_number;
	ca->round_sent = 0;
	ca->round_length = 0;
}

static void add_chirp(struct dctcp *ca, struct chirp *chirp)
{
	if (ca->chirp) {
		list_add_tail(&(chirp->list), &(ca->chirp->list));
		ca->chirp_list_size++;
	}
}

static void remove_chirp(struct dctcp *ca, struct chirp *chirp)
{
	if (ca->chirp) {
		list_del(&(chirp->list));
		ca->chirp_list_size--;
	}
}

static struct chirp* get_current_chirp(struct dctcp *ca)
{
	if (!ca->chirp || ca->chirp_list_size == 0 || list_empty_careful(&(ca->chirp->list)))
		return NULL;
	return list_first_entry(&(ca->chirp->list), struct chirp, list);
}

static u32 should_terminate(struct tcp_sock *tp, struct dctcp *ca)
{
	return ((tp->srtt_us>>3) <= ca->round_length);
}

static u32 can_schedule_new_chirp(struct tcp_sock *tp, struct dctcp *ca, u32 size)
{
	return ca->round_sent < (ca->max_num_chirps_in_round>>MAX_NUM_CHIRPS_IN_ROUND_SHIFT) &&
		!should_terminate(tp, ca);
}

static u32 gap_to_Bps_us(struct sock *sk, struct tcp_sock *tp, u32 gap_us)
{
	u64 rate;
	
	if (!gap_us)
		return 0;

	rate = tp->mss_cache;
	rate *= USEC_PER_SEC;
	rate = rate/(u64)gap_us;
	
	return (u32)rate;
}

static void exit_initial_slow_start(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
		
	ca->in_initial_slow_start = 0;
	ca->slow_start_state = 0;
	sk->sk_pacing_rate = 0;
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;
	/*Prevent burst of packets*/
	tp->snd_cwnd = tp->packets_out+1U;
	tp->snd_ssthresh = tp->snd_cwnd;
	
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
}

static void dctcp_release(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct chirp *chirp;
	if (ca->chirp) {
		while ((chirp = get_current_chirp(ca)) != NULL) {
			remove_chirp(ca, chirp);
			kfree(chirp);
		}
		kfree(ca->chirp);
	}
}

static u32 estimate_inter_arrival_time_us(struct tcp_sock *tp, struct dctcp *ca, struct chirp *chirp)
{
	u32 sum_ns = 0, cnt;
	for(cnt = 1; cnt < chirp->index; cnt++) {
		/*This is to handle known case if syn-ack is dropped.
		 *This should be fixed with ECT0 on the synack when 
		 *DCTCP is configured per route and non-ECN used as default CC.*/
		if (chirp->inter_arrival_time_ns[cnt] <= 2000000U)
			sum_ns += chirp->inter_arrival_time_ns[cnt];
	}
	if (--cnt > 0) {
		cnt *= 1000U;
		return sum_ns/cnt;
	} else {
		return INVALID_CHIRP;
	}
}


static u32 analyze_chirp(struct sock *sk, struct chirp *chirp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	int N = chirp->index;
	int i, j, l = N-1;
	int gap_avg = 0;
	u32 *q = chirp->q_delay;
	u32 *s = chirp->recorded_inter_send_time_us;
	u32 L = dctcp_chirp_L;
	u32 max_q = 0;
	int excursion_cnt = 0;
	int excursion_start = 0;
	u32 E[MAX_N];
	
	int q_diff = 0;
	u32 strikes = 0; /*Number of rate decreases*/
	u32 s_i = 1; /*Index of the lowest sending gap*/

	if (N < 2)
		return INVALID_CHIRP;

	/*These are the two initial chirps/packet trains*/
	if (chirp->id == 0 || (!BURST_AND_CHIRP && (chirp->id == 1))) {
		return estimate_inter_arrival_time_us(tp, ca, chirp);
	}

	memset(E, 0, sizeof(E));

	for (i = 1; i < N; ++i) {
#if DISCARD_INVALID_CHIRPS
		if (s[i] > (s[s_i] + (s[s_i]>>2))) { /*if current gap is greater than previous gap * 1.25*/
			trace_printk("port=%hu,INVALID_CHIRP=1,si=%u,ssi=%u\n",
				     tp->inet_conn.icsk_bind_hash->port,s[i], s[s_i]);
			return INVALID_CHIRP;
		}
		if (s[i] > s[s_i]) { /*Strictly greater to deal with i = 1*/
			if (++strikes >= L) {
				trace_printk("port=%hu,INVALID_CHIRP=1,si=%u,ssi=%u,strikes=%u\n",
					     tp->inet_conn.icsk_bind_hash->port,s[i], s[s_i],strikes);
				return INVALID_CHIRP;
			}
		} else {
			s_i = i;
		}
#endif
		
		/*Check if currently tracking a possible excursion*/
		q_diff = (int)q[i] - (int)q[excursion_start];
		
		if(excursion_cnt && q_diff >= 0 &&
		   ((u32)q_diff > ((max_q>>1) + (max_q>>3)))) {
			max_q = max(max_q, (u32)q_diff);
			excursion_cnt++;
		} else { /*Excursion has ended or never started.*/
			if (excursion_cnt >= L) {
				for (j = excursion_start; j < excursion_start +
					     excursion_cnt; ++j) {
					if (q[j] < q[j+1])
						E[j] = s[j];
				}
			}
			
			excursion_cnt = 0;
			excursion_start = 0;
			max_q = 0U;
		}
		
		/*Start new excursion*/
		if (!excursion_cnt && (i < (N-1)) && (q[i] < q[i+1])) {
			excursion_start = i;
			max_q = 0U;
			excursion_cnt = 1;
		}
	}

	/*Unterminated excursion*/
	if (excursion_cnt && (excursion_cnt+excursion_start) == N ) {
		for (j = excursion_start; j < (excursion_start +
					       excursion_cnt); ++j) {
			E[j] = s[excursion_start];
		}
		l = excursion_start;
	}

	/*Calculate the average gap*/
	for (i = 1; i < N; ++i) {
		if (E[i] == 0)
			gap_avg += s[l];
		else
			gap_avg += E[i];
	}

	return gap_avg/(N-1);
}


static u32 schedule_chirp(struct sock *sk, u32 N, u32 gap_avg_us)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_pacing_list *pacing_entry;
	struct chirp *new_chirp;
	int i;
	u32 geometry = ca->geometry;//max(dctcp_chirp_geometry, 100U);
	u32 gap;
	u32 gap_step;
	u32 total_memory_size = sizeof(struct chirp) + sizeof(struct tcp_pacing_list) * N;
	u32 prev_gap;
	u32 guard_band = 0;
	u32 chirp_length_us = 0;

	if (!ca->chirp)
		return 1;

	/*Calculate the guard band based on number of chirps*/
	if (ca->chirp_number != 1U) {
		guard_band = (tp->srtt_us>>3)/max((u32)1U, (u32)(ca->max_num_chirps_in_round>>MAX_NUM_CHIRPS_IN_ROUND_SHIFT));
	}

	/*Allocate memory*/
	if (!(new_chirp = kmalloc(total_memory_size, GFP_KERNEL))) {
		trace_printk("port=%hu,WARNING_MALLOC=1,errormalloc=1\n",
			     tp->inet_conn.icsk_bind_hash->port);
		return 1;	
	}
	pacing_entry = (struct tcp_pacing_list *) (new_chirp + 1);	

	/* First chirp. Assumes that the next packet will trigger the use of the first
	 * entry of the first chirp. */
	if (unlikely(ca->chirp_number == 0U))
		new_chirp->start_seq  = tp->snd_nxt;

	new_chirp->index = 0;
	new_chirp->rate_entries_examined = 0;
	new_chirp->end_seq = 0;
	new_chirp->start_seq = 0;
	new_chirp->last_ack_time_ns = 0;
	new_chirp->prev_timestamp = 0;
	new_chirp->N = N;
	new_chirp->id = ca->chirp_number++;

	/*Calculate gap step*/
	gap_step = max(1U, DIV_ROUND_UP((((geometry - 100)<<1))*gap_avg_us, N * 100));

	/*Strictly not neccessary. Used for debugging*/
	new_chirp->recorded_inter_send_time_us[0] = gap_avg_us;

	for (i = 1; i < new_chirp->N; ++i, pacing_entry++) {
		/* This is if either of the two first chirps is in fact a chirp.
		 * The last gap should be line-rate. */
		if (BURST_AND_CHIRP && new_chirp->id < 2U && i == (new_chirp->N-1)) {
			gap = 0;
		} else {
			if (i == 1)
				gap = (gap_avg_us * geometry) / 100;
			else
				gap = max(gap_step, prev_gap) - gap_step;	
		}
		
		pacing_entry->rate = gap_to_Bps_us(sk, tp, gap);
		
		list_add_tail(&pacing_entry->list, &tp->pacing_rate_list.list);
		prev_gap = gap; /*prev_gap can probably be replaced by gap, but this is clearer*/
		chirp_length_us += gap;

	}
	
	/*Calculate and schedule guard band*/
	if (guard_band > chirp_length_us)
		gap = max(gap_avg_us, guard_band - chirp_length_us);
	else
		gap = gap_avg_us;

	pacing_entry->rate = gap_to_Bps_us(sk, tp, gap);
	list_add_tail(&pacing_entry->list, &tp->pacing_rate_list.list);

	/*Allow the packets to be sent*/
	tp->snd_cwnd += new_chirp->N;
	
	ca->round_length += gap_avg_us + chirp_length_us;
	ca->round_sent++;
	
	add_chirp(ca, new_chirp);

	return 0;
}




static void measure_inter_arrival_time_ns(struct sock *sk, u32 acked_bytes)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    
	u64 cur_time_ns;
	u64 diff_time_ns;
	struct chirp *chirp = get_current_chirp(ca);

	if (chirp) {
		cur_time_ns = ktime_to_ns(ktime_get());
		if (chirp->last_ack_time_ns && acked_bytes) {
			diff_time_ns = cur_time_ns - chirp->last_ack_time_ns;

			/* Inter arrival time is assumed to be for mss_cache sized packets*/
			if (acked_bytes == tp->mss_cache)
				chirp->inter_arrival_time_ns[chirp->index] = diff_time_ns;
			else
				chirp->inter_arrival_time_ns[chirp->index] = (diff_time_ns *
									      ((max(1U, tp->mss_cache)<<3)/acked_bytes))>>3;
		}
		if (acked_bytes)
			chirp->last_ack_time_ns = cur_time_ns;
	}

}


/*Note that this check will not see wheter or not the paced chirping kernel is used.*/
/* This function is called before dctcp_acked. It examins the used
 * pacing rate entries, register ECN marks and note down the number of bytes acked.*/
static void dctcp_update_alpha_slow_start(struct sock *sk, u32 acked_bytes, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_pacing_list *entry;
	struct chirp *cur_chirp;
	int max_itrs = 2, i = ca->chirp_list_size;
	
	/* Check if the packet/ack was marked */
	if (acked_bytes) {
		if (flags & CA_ACK_ECE) {
			/*Currently unused..*/
			ca->slow_start_state |= CONGESTION_ECN;
		}
	}

	if (!ca->chirp || (ca->slow_start_state & TRANSITION) || !(cur_chirp = get_current_chirp(ca)))
		return;

	/* Only measure inter-arrival time for two first bursts/chirps.
	 * It might be useful to change this in the future.. */
	if (cur_chirp->id < 2U)
		measure_inter_arrival_time_ns(sk, acked_bytes);
	/* For use in dctcp_acked. Used in measure_inter_arrival_time_us to handle packets less than MSS */

	/* Clean the used pacing rate list.
	 * max_itrs limits the number of entries examined. As long as there is one ack for each data packet and no loss
	 * the while can be changed to an if-statement. Further it should really depend on the number of packets acked by the
	 * current ack. */
	while (max_itrs-- > 0 &&
	       !list_empty_careful(&tp->used_pacing_rate_list.list)) {
		entry = list_last_entry(&tp->used_pacing_rate_list.list, struct tcp_pacing_list, list);
		
		/* All the entries of this chirp have been examined and removed.
		 * Move on to the next chirp. It is also possible to break at this point and say that
		 * the entry has to examined when an ack that belonds ot the next chirp arrives.*/
		while((cur_chirp->rate_entries_examined >= cur_chirp->N) && (--i > 0)) {
			cur_chirp = list_first_entry(&(cur_chirp->list), struct chirp, list);
		}

		
		if (cur_chirp->rate_entries_examined >= cur_chirp->N) {
			/* Something is seriously wrong. The entry does not belong to any of the chirps*/
			trace_printk("port=%hu,WARNING: Entry not belonging to a chirp. list_size=%u\n", tp->inet_conn.icsk_bind_hash->port, ca->chirp_list_size);
			list_del(&entry->list);
			break;
		}


		/*Sequence number of last packet in chirp*/
		if (cur_chirp->rate_entries_examined == (cur_chirp->N-1)) {
			cur_chirp->end_seq = entry->seq;
		}
		/* Note down starting sequence */
		if (!cur_chirp->start_seq) {
			cur_chirp->start_seq = entry->seq;
		}	
		/*Record the inter send time.*/
		if (cur_chirp->prev_timestamp) {
			/* This calulation can be optimized. To support higher rates nano-second is required.
			 * The current solution does not handle very high rates due to noise anyway.  Some smart kernel developers can probably do a better job :) */
			cur_chirp->recorded_inter_send_time_us[cur_chirp->rate_entries_examined] =
				(ktime_to_ns(entry->timestamp) - ktime_to_ns(cur_chirp->prev_timestamp))/1000;
		}

		cur_chirp->prev_timestamp = entry->timestamp;
		cur_chirp->rate_entries_examined++;
		list_del(&entry->list);
	}
}

static void dctcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    	struct chirp *cur_chirp;
	u32 rtt_us = sample->rtt_us;

	if (!ca->in_initial_slow_start || rtt_us == 0)
		return;



	/* We have terminated, but are waiting for scheduled packet to be sent or 
	 * the number of in-flight packets to reach a certain target. */
	if (ca->slow_start_state & TRANSITION) {
		/*In TRANSITION, round_sent is ack number
		  from exhausting the pacing list. packets_out is
		  the target number of packets in flight.
		  This is done to conserve space.*/
		if (list_empty_careful(&tp->pacing_rate_list.list)) {
#if ACCELERATE_AFTER_LIST_EMPTY
			if ((ca->round_sent++ > (ca->round_start)) ||
			    (tp->packets_out >= (ca->round_start-2U)))
				exit_initial_slow_start(sk);

#else
			exit_initial_slow_start(sk);
#endif
		}
		return;
	}

	if (!(cur_chirp = get_current_chirp(ca)))
		return;

	/*Clock out packet*/
	tp->snd_cwnd = tp->snd_cwnd == 0 ? 0: tp->snd_cwnd-1;

	/*Check if the ack is part of the current chirp.
	  Does not check if it is for the next chirp*/
	if (!cur_chirp->start_seq || !after(tp->snd_una, cur_chirp->start_seq)) {
		/*Marker packet should end up here.*/
		/* In the third round we send two chirps of 16 packets each.
		 * Theses are currently triggered by the marking packet.
		 * A more sophisticated check for marking packet and handling loss of it should
		 * be implemented. */
		if (ca->chirp_number == 4U) {
			start_new_round(ca);
			schedule_chirp(sk,
				    MAX_N,
				    ca->gap_avg_us);
			schedule_chirp(sk,
				    MAX_N,
				    ca->gap_avg_us);
			
		}
		return;
	}
	

	/* Send marking packet when the first ack of the first chirp/burst arrives. */
	if (unlikely(cur_chirp->id == 0 &&
		     cur_chirp->index == 0)) {
		tp->snd_cwnd++;
		hrtimer_cancel(&tcp_sk(sk)->pacing_timer);
	} else if (cur_chirp->id >= 4U) {

		/*Start a new round*/
		if (cur_chirp->id == ca->round_start &&
		    cur_chirp->index == 0) {
			start_new_round(ca);
			ca->max_num_chirps_in_round = (ca->max_num_chirps_in_round * ca->gain) / 100U;
		}
		
		/*The number of chirps this chirp can trigger.*/
		if (cur_chirp->index == 0)
			cur_chirp->new_to_send = DIV_ROUND_UP(ca->gain, 100U);

		/*Schedule new chirps if possible*/
		while(cur_chirp->new_to_send > 0 &&
		      can_schedule_new_chirp(tp, ca, MAX_N)) {
			schedule_chirp(sk,
				    MAX_N,
				    ca->gap_avg_us);
			cur_chirp->new_to_send--;
		}
	}


	/*Does not matter if we use minimum rtt for this chirp of for the duration of
	 * the connection because the analysis uses relative queue delay in analysis.
	 * Assumes no reordereing or loss. Have to link seq number to array index. */
	cur_chirp->q_delay[cur_chirp->index++] = rtt_us - minmax_get(&tp->rtt_min);
	
        /*Chirp is completed*/
	if (cur_chirp->index >= cur_chirp->N ||
	    (cur_chirp->end_seq && after(tp->snd_una, cur_chirp->end_seq))) {

		u32 new_estimate = analyze_chirp(sk, cur_chirp);
		update_gap_estimate(tp, ca, new_estimate);
		/*
		  Naive adaption of gain and geometry.
		if (new_estimate != INVALID_CHIRP && cur_chirp->id > 1U) {
			update_gain_and_geometry(tp, ca);
			}*/
		/* Second round starts when the first chirp has been analyzed. */
		if (cur_chirp->id == 0U) {
			start_new_round(ca);
			schedule_chirp(sk, 8U, ca->gap_avg_us);
			schedule_chirp(sk, 8U, ca->gap_avg_us);
		}
		remove_chirp(ca, cur_chirp);
		kfree(cur_chirp);
	}
	
	/* Terminate */
	if (should_terminate(tp, ca)) {
		u32 rate = gap_to_Bps_us(sk, tp, ca->gap_avg_us);
		ACCESS_ONCE(sk->sk_pacing_rate) = rate;

		trace_printk("port=%hu,final_gap=%u\n",
			     tp->inet_conn.icsk_bind_hash->port,
			     ca->gap_avg_us);
		ca->round_sent = 0;
		ca->round_start = (minmax_get(&tp->rtt_min)/max(1U, (u32)ca->gap_avg_us));
		ca->slow_start_state |= TRANSITION;

	}
}


/*modification of tcp_slow_start*/
static u32 dctcp_slow_start(struct tcp_sock *tp, struct dctcp *ca, u32 ack, u32 acked)
{
	u32 cwnd = tp->snd_cwnd + acked;

	if (ca->in_initial_slow_start) {
		return 0;
	}
	
	acked -= cwnd - tp->snd_cwnd;
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
	
	return acked;
}

/* Modification of tcp_reno_cong_avoid */
static void dctcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In "safe" area, increase. */
	if ((tp->snd_cwnd <= tp->snd_ssthresh) || ca->in_initial_slow_start) {
		acked = dctcp_slow_start(tp, ca, ack, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

#endif
/************************************************************************/

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
		ca->next_seq = 0;


		ca->in_initial_slow_start = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)
		/**** Init new variables ****/
		ca->in_initial_slow_start = 1;	

		/* Alter kernel behaviour*/
		sk->sk_pacing_rate = 0; /*This disables pacing until I explicitly set it*/
		tp->disable_kernel_pacing_calculation = 1;
		tp->disable_cwr_upon_ece = 1;

		/*Note that if FQ is attached to outgoing interface we are probably screwed*/
		cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		
		tp->snd_cwnd = 0; //This will be overwritten by the socket init function
		
		ca->gap_avg_us = 0;
		ca->chirp_number = 0;
		ca->round_start = 0;
		ca->round_sent = 0;
		ca->round_length = 0;
		ca->chirp_list_size = 0;
		ca->MAD = 0;
		
		ca->max_num_chirps_in_round = (2<<MAX_NUM_CHIRPS_IN_ROUND_SHIFT);
		ca->gain = max(dctcp_ss_gain, 100U);
		ca->geometry = dctcp_chirp_geometry;

		ca->chirp = kmalloc(sizeof(*ca->chirp), GFP_KERNEL);
		if (ca->chirp) {

			INIT_LIST_HEAD(&(ca->chirp->list));

			schedule_chirp(sk, (TCP_INIT_CWND>>1), 0);
			
			if (BURST_AND_CHIRP)
				/* Start with a gap avg of 100 us */
				schedule_chirp(sk, (TCP_INIT_CWND>>1), 100);
			else
				schedule_chirp(sk, (TCP_INIT_CWND>>1), 0);
		} else {
			cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
			ca->in_initial_slow_start = 0;
			tp->disable_cwr_upon_ece = 0;
			tp->disable_kernel_pacing_calculation = 0;
		}
#endif
		
		dctcp_reset(tp, ca);
		return;
	}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;
#endif

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

	/**************** NEW FUNCTION TO BE CALLED IN SS****************/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)
	if (ca->in_initial_slow_start) {
		dctcp_update_alpha_slow_start(sk, acked_bytes, flags);
	}
#endif
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
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)
	/*Terminate flow start in case of loss (*hum*)*/
	if (new_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);
		if (ca->in_initial_slow_start)
			exit_initial_slow_start(sk);
	}
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,16)
	.cong_avoid     = dctcp_cong_avoid,
	.release        = dctcp_release,
	.pkts_acked     = dctcp_acked,
#else
	.cong_avoid	= tcp_reno_cong_avoid,
#endif
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
	.name		= "myowncc-reno",
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
MODULE_DESCRIPTION("DataCenter TCP (DCTCP) with PacedChirping");
