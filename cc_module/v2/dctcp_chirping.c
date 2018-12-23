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

#define CHIRP_SIZE 16U

struct chirp {
	struct list_head list;
	u32 chirp_number;
	u32 N;
	u32 qdelay_index;
	u32 pacing_entries_examined;

	u32 start_seq;
	u32 end_seq;

	u64 prev_ack_time_ns;
	ktime_t prev_entry_timestamp;

	u32 schedule_limit;

	u32 *qdelay;
	u32 *recorded_inter_send_time_ns;
	u32 *inter_arrival_time_ns;
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
	// tcp_in_initial_slowstart
	u8 pc_state;
	struct chirp *chirp_list;
	u16 chirp_list_size; /* Is chirp list size really necessary?*/

	u32 gap_avg_ns;
	u32 round_length_us; /*Used for termination condition*/
	u16 chirp_number;
	u16 M;               /*Maximum number of chirps in a round*/
	u16 round_start;     /*Chirp number of the first chirp in the round*/
	u16 round_sent;      /*Number of chirps sent in the round*/
	u16 gain;
	u16 geometry;
	u32 MAD;
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

static unsigned int dctcp_pc_initial_gain __read_mostly = 200; /* gain times 100 */
module_param(dctcp_pc_initial_gain, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_gain, "Initial gain for paced chirping");

static unsigned int dctcp_pc_initial_geometry __read_mostly = 200; /* geometry times 100 */
module_param(dctcp_pc_initial_geometry, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_geometry, "Initial geometry for paced chirping");

static unsigned int dctcp_pc_L __read_mostly = 5;
module_param(dctcp_pc_L, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_L, "Number of packets that make up an excursion");

/* TODO: Figure out of the sensistivty in the anlaysis can be a parameter*/

static struct tcp_congestion_ops dctcp_reno;


/* New functions */
static void update_gap_avg(struct tcp_sock *tp, struct dctcp *ca, u32 new_estimate_ns)
{
	u32 prev_estimate_ns = ca->gap_avg_ns;
	s32 error;

	if (new_estimate_ns == INVALID_CHIRP) {
		return;
	}

	if (ca->gap_avg_ns == 0U) {
		ca->gap_avg_ns = new_estimate_ns;
		return;
	}

	ca->gap_avg_ns = prev_estimate_ns -
		(prev_estimate_ns>>GAP_AVG_SHIFT) +
		(new_estimate_ns>>GAP_AVG_SHIFT);

	/*TODO Maybe init ca->MAD to error if first value.*/
	error = (s32)new_estimate_ns - (s32)prev_estimate_ns;
	ca->MAD = (ca->MAD>>1) + (abs(error)>>1);
}

static void update_gain_and_geometry(struct tcp_sock *tp, struct dctcp *ca)
{
	/*Currently not implemented. Feel free to experiment*/
}

static inline void start_new_round(struct dctcp *ca)
{
	ca->round_start = ca->chirp_number;
	ca->round_sent = 0;
	ca->round_length_us = 0;
}

static void remove_chirp(struct dctcp *ca, struct chirp *chirp)
{
	if (ca->chirp_list) {
		list_del(&(chirp->list));
		ca->chirp_list_size--;
	}
}

static struct chirp* get_current_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || ca->chirp_list_size == 0 || list_empty_careful(&(ca->chirp_list->list)))
		return NULL;
	return list_first_entry(&(ca->chirp_list->list), struct chirp, list);
}

static u32 should_terminate(struct tcp_sock *tp, struct dctcp *ca)
{
	return ((tp->srtt_us>>3) <= ca->round_length_us);
}

static u32 can_schedule_new_chirp(struct tcp_sock *tp, struct dctcp *ca, u32 size)
{
	return ca->round_sent < (ca->M>>M_SHIFT) &&
		!should_terminate(tp, ca);
}

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

static void exit_paced_chirping(struct sock *sk, struct tcp_sock *tp, struct dctcp *ca)
{	
	ca->pc_state = 0;
	tp->snd_cwnd = tp->packets_out;
	tp->snd_ssthresh = tp->snd_cwnd;
	tp->disable_cwr_upon_ece = 0;
	tp->disable_kernel_pacing_calculation = 0;
	sk->sk_pacing_rate = ~0U;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
}

static void dctcp_release(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct chirp *chirp;
	if (ca->chirp_list) {
		while ((chirp = get_current_chirp(ca)) != NULL) {
			remove_chirp(ca, chirp);
			kfree(chirp);
		}
		kfree(ca->chirp_list);
	}
}

static u32 estimate_inter_arrival_time_ns(struct tcp_sock *tp, struct dctcp *ca, struct chirp *chirp)
{
	u64 sum_ns = 0, cnt;
	for(cnt = 1; cnt < chirp->qdelay_index; cnt++) {
		/*This is to handle known case if syn-ack is dropped. (disabled when published).
		 *This should be fixed with ECT0 on the synack when 
		 *DCTCP is configured per destination and non-ECN used as default CC.*/
		if (chirp->inter_arrival_time_ns[cnt] <= 2000000U)
			sum_ns += chirp->inter_arrival_time_ns[cnt];
	}
	if (--cnt > 0) {
		return sum_ns/cnt;
	} else {
		return INVALID_CHIRP;
	}
}

static u32 analyze_chirp(struct sock *sk, struct chirp *chirp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	int N = chirp->qdelay_index;
	int i, j, l = N-1;
	u64 gap_avg = 0;
	u32 *q = chirp->qdelay;
	u32 *s = chirp->recorded_inter_send_time_ns;
	u32 L = dctcp_pc_L;
	u32 max_q = 0;
	int excursion_cnt = 0;
	int excursion_start = 0;
	u32 E[CHIRP_SIZE];
	
	int q_diff = 0;
	u32 strikes = 0; /*Number of rate decreases*/
	u32 s_i = 1; /*Index of the lowest sending gap*/

	if (N < 2)
		return INVALID_CHIRP;

	/*These are the two initial chirps/packet trains*/
	if (chirp->chirp_number < 2U) {
		return estimate_inter_arrival_time_ns(tp, ca, chirp);
	}

	memset(E, 0, sizeof(E));

	for (i = 1; i < N; ++i) {
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

static struct chirp* schedule_chirp(struct sock *sk, u32 N, u32 gap_avg_ns)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_pacing_list *pacing_entry;
	struct chirp *new_chirp;

	int i;
	u32 prev_gap = 0;
	u32 gap_step;
	u32 gap;
	u32 geometry = ca->geometry;
	u32 guard_interval_ns = 0;
	u32 memory_required = sizeof(struct chirp) +
		sizeof(struct tcp_pacing_list) * N +
		sizeof(u32) * N * 3;
	u32 chirp_length_ns = 0;

	if (!ca->chirp_list)
		return NULL;

	if (!(new_chirp = kmalloc(memory_required, GFP_KERNEL))) {
		trace_printk("port=%hu,ERROR_MALLOC\n",
			     tp->inet_conn.icsk_bind_hash->port);
		return NULL;	
	}
	new_chirp->qdelay = (u32*) (new_chirp + 1);
	new_chirp->recorded_inter_send_time_ns = (u32*) (new_chirp->qdelay + N);
	new_chirp->inter_arrival_time_ns = (u32*) (new_chirp->recorded_inter_send_time_ns + N);
	
	pacing_entry = (struct tcp_pacing_list *) (new_chirp->inter_arrival_time_ns + N);
	
	/*Calculate guard interval*/
	if (ca->chirp_number != 1U)
		guard_interval_ns = ((tp->srtt_us>>3) / (ca->M>>M_SHIFT))<<10;

	/* Initialize chirp members */
	if (unlikely(ca->chirp_number == 0U)) {
		new_chirp->start_seq  = tp->snd_nxt;
	}
	new_chirp->qdelay_index = 0;
	new_chirp->pacing_entries_examined = 0;
	new_chirp->end_seq = 0;
	new_chirp->start_seq = 0;
	new_chirp->prev_ack_time_ns = 0;
	new_chirp->prev_entry_timestamp = 0;
	new_chirp->N = N;
	new_chirp->chirp_number = ca->chirp_number++;

	/*Calculate gap step*/
	gap_step = DIV_ROUND_UP((((geometry - 100)<<1))*gap_avg_ns, N * 100);
	//spin_lock(&tp->pacing_list_lock);
	for (i = 1; i < N; i++, pacing_entry++) {
		if (new_chirp->chirp_number < 2U)
			gap = 0;
		else {
			if (i == 1)
				gap = (gap_avg_ns * geometry) / 100;
			else
				gap = max(gap_step, prev_gap) - gap_step;
		}

		pacing_entry->gap_ns = gap;
		list_add_tail(&pacing_entry->list, &tp->pacing_gap_list.list);
		prev_gap = gap;

		chirp_length_ns += gap;
	}

	if (guard_interval_ns > chirp_length_ns)
		gap = max(gap_avg_ns, guard_interval_ns - chirp_length_ns);
	else
		gap = gap_avg_ns;
	pacing_entry->gap_ns = gap;
	list_add_tail(&pacing_entry->list, &tp->pacing_gap_list.list);
	//spin_unlock(&tp->pacing_list_lock);
	tp->snd_cwnd += N;
	ca->round_length_us += (gap_avg_ns + chirp_length_ns)>>10;
	ca->round_sent++;

	list_add_tail(&(new_chirp->list), &(ca->chirp_list->list));
	ca->chirp_list_size++;
		
	return new_chirp;
}



static void measure_inter_arrival_time_ns(struct sock *sk, u32 acked_bytes)
{
	struct dctcp *ca = inet_csk_ca(sk);

	u64 cur_time_ns;
	u64 diff_time_ns;
	struct chirp *chirp = get_current_chirp(ca);

	if (!chirp)
		return;

	cur_time_ns = ktime_to_ns(ktime_get());
	if (chirp->prev_ack_time_ns && acked_bytes) {
		diff_time_ns = cur_time_ns - chirp->prev_ack_time_ns;

		/*Assuming all packets are tp->mss_cache (?)*/
		chirp->inter_arrival_time_ns[chirp->qdelay_index] = diff_time_ns;
	}
	if (acked_bytes)
		chirp->prev_ack_time_ns = cur_time_ns;
}

static void handle_used_pacing_entry_list(struct tcp_sock *tp, struct dctcp *ca)
{
	struct tcp_pacing_list *entry;
	struct chirp *cur_chirp;
	int max_itrs = 2, i = ca->chirp_list_size;

	if (!(cur_chirp = get_current_chirp(ca)))
		return;
	
	/* Clean the used pacing rate list.
	 * max_itrs limits the number of entries examined. As long as there is one ack for each data packet and no loss
	 * the while can be changed to an if-statement. Further it should really depend on the number of packets acked by the
	 * current ack. */
	//spin_lock(&tp->pacing_list_lock);
	while (max_itrs-- > 0 &&
	       !list_empty_careful(&tp->used_pacing_gap_list.list)) {
		entry = list_last_entry(&tp->used_pacing_gap_list.list, struct tcp_pacing_list, list);
		
		/* All the entries of this chirp have been examined and removed.
		 * Move on to the next chirp. It is also possible to break at this point and say that
		 * the entry has to examined when an ack that belonds ot the next chirp arrives.*/
		while((cur_chirp->pacing_entries_examined >= cur_chirp->N) && (--i > 0)) {
			cur_chirp = list_first_entry(&(cur_chirp->list), struct chirp, list);
		}

		
		if (cur_chirp->pacing_entries_examined >= cur_chirp->N) {
			/* Something is seriously wrong. The entry does not belong to any of the chirps*/
			trace_printk("port=%hu,WARNING: Entry not belonging to a chirp. list_size=%u\n", tp->inet_conn.icsk_bind_hash->port, ca->chirp_list_size);
			list_del(&entry->list);
			break;
		}


		/*Sequence number of last packet in chirp*/
		if (cur_chirp->pacing_entries_examined == (cur_chirp->N-1)) {
			cur_chirp->end_seq = entry->seq_nxt;
		}
		/* Note down starting sequence */
		if (!cur_chirp->start_seq) {
			cur_chirp->start_seq = entry->seq_nxt;
		}	
		/*Record the inter send time.*/
		if (cur_chirp->prev_entry_timestamp) {
			/* This calulation can be optimized. To support higher rates nano-second is required.
			 * The current solution does not handle very high rates due to noise anyway.  Some smart kernel developers can probably do a better job :) */
			cur_chirp->recorded_inter_send_time_ns[cur_chirp->pacing_entries_examined] =
				(ktime_to_ns(entry->timestamp) - ktime_to_ns(cur_chirp->prev_entry_timestamp));
		}

		cur_chirp->prev_entry_timestamp = entry->timestamp;
		cur_chirp->pacing_entries_examined++;
		list_del(&entry->list);
	}
	//spin_unlock(&tp->pacing_list_lock);
}

static void dctcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    	struct chirp *cur_chirp;
	u32 rtt_us = sample->rtt_us;

	if (!(ca->pc_state & STATE_ACTIVE) || rtt_us == 0)
		return;

	/* We have terminated, but are waiting for scheduled packet to be sent or 
	 * the number of in-flight packets to reach a certain target. */
	if (ca->pc_state & STATE_TRANSITION) {
		/*In TRANSITION, round_sent is ack number
		  from exhausting the pacing list. packets_out is
		  the target number of packets in flight.
		  This is done to conserve space.*/
		if (list_empty_careful(&tp->pacing_gap_list.list)) {
			if ((ca->round_sent++ > (ca->round_start)) ||
			    (tp->packets_out >= (ca->round_start-2U)))
				exit_paced_chirping(sk, tp, ca);

		}
		return;
	}

	if (!(cur_chirp = get_current_chirp(ca)))
		return;

	/* Only measure inter-arrival time for two first bursts/chirps.
	 * It might be useful to change this in the future.. */
	if (cur_chirp->chirp_number < 2U)
		measure_inter_arrival_time_ns(sk, 1);

	handle_used_pacing_entry_list(tp, ca);

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
				    CHIRP_SIZE,
				    ca->gap_avg_ns);
			schedule_chirp(sk,
				    CHIRP_SIZE,
				    ca->gap_avg_ns);
			
		}
		return;
	}
	

	/* Send marking packet when the first ack of the first chirp/burst arrives. */
	if (unlikely(cur_chirp->chirp_number == 0 && !(ca->pc_state & STATE_MARK_SENT)) &&
	    list_empty_careful(&tp->pacing_gap_list.list)) {
		tp->snd_cwnd++;
		ca->pc_state |= STATE_MARK_SENT;
		hrtimer_cancel(&tcp_sk(sk)->pacing_timer);
	} else if (cur_chirp->chirp_number >= 4U) {

		/*Start a new round*/
		if (cur_chirp->chirp_number == ca->round_start &&
		    cur_chirp->qdelay_index == 0) {
			start_new_round(ca);
			ca->M = (ca->M * ca->gain) / 100U;
		}
		
		/*The number of chirps this chirp can trigger.*/
		if (cur_chirp->qdelay_index == 0)
			cur_chirp->schedule_limit = DIV_ROUND_UP(ca->gain, 100U);

		/*Schedule new chirps if possible*/
		while(cur_chirp->schedule_limit > 0 &&
		      can_schedule_new_chirp(tp, ca, CHIRP_SIZE)) {
			schedule_chirp(sk,
				    CHIRP_SIZE,
				    ca->gap_avg_ns);
			cur_chirp->schedule_limit--;
		}
	}


	/*Does not matter if we use minimum rtt for this chirp of for the duration of
	 * the connection because the analysis uses relative queue delay in analysis.
	 * Assumes no reordereing or loss. Have to link seq number to array index. */
	cur_chirp->qdelay[cur_chirp->qdelay_index++] = rtt_us - minmax_get(&tp->rtt_min);
	
        /*Chirp is completed*/
	if (cur_chirp->qdelay_index >= cur_chirp->N ||
	    (cur_chirp->end_seq && after(tp->snd_una, cur_chirp->end_seq))) {

		u32 new_estimate = analyze_chirp(sk, cur_chirp);
		update_gap_avg(tp, ca, new_estimate);
		/*
		  Naive adaption of gain and geometry.
		if (new_estimate != INVALID_CHIRP && cur_chirp->chirp_number > 1U) {
			update_gain_and_geometry(tp, ca);
			}*/
		/* Second round starts when the first chirp has been analyzed. */
		if (cur_chirp->chirp_number == 0U) {
			start_new_round(ca);
			schedule_chirp(sk, 8U, ca->gap_avg_ns);
			schedule_chirp(sk, 8U, ca->gap_avg_ns);
		}
		remove_chirp(ca, cur_chirp);
		kfree(cur_chirp);
	}
	
	/* Terminate */
	if (should_terminate(tp, ca)) {
		u32 rate = gap_to_Bps_ns(sk, tp, ca->gap_avg_ns);
		ACCESS_ONCE(sk->sk_pacing_rate) = rate;


		ca->round_sent = 0;
		ca->round_start = (minmax_get(&tp->rtt_min)/max(1U, (u32)ca->gap_avg_ns>>10));

/*		trace_printk("port=%hu,final_gap=%u,cwnd=%d,target=%u,rate=%u\n",
			     tp->inet_conn.icsk_bind_hash->port,
			     ca->gap_avg_ns, tp->snd_cwnd, ca->round_start,rate);
*/		
		ca->pc_state |= STATE_TRANSITION;

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
	ca->chirp_list = kmalloc(sizeof(*ca->chirp_list), GFP_KERNEL);
	if (!ca->chirp_list) {
		return;
	}
	/* Alter kernel behaviour*/
	/* Actually, setting to ~0 instead of 0 is important (?) to avoid issues with TSQ.*/
	sk->sk_pacing_rate = ~0; /*This disables pacing until I explicitly set it.*/
	tp->disable_kernel_pacing_calculation = 1;
	tp->disable_cwr_upon_ece = 1;

	/*Note that if FQ is attached to outgoing interface we are probably screwed*/
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		
	tp->snd_cwnd = 0; /*This will be overwritten by the socket init function*/
		
	ca->gap_avg_ns = 0;
	ca->chirp_number = 0;
	ca->round_start = 0;
	ca->round_sent = 0;
	ca->round_length_us = 0;
	ca->chirp_list_size = 0;
	ca->MAD = 0;
		
	ca->M = (2<<M_SHIFT);
	ca->gain = max(dctcp_pc_initial_gain, 100U);
	ca->geometry = min(max(dctcp_pc_initial_geometry, 100U), 300U);



	INIT_LIST_HEAD(&(ca->chirp_list->list));

	schedule_chirp(sk, (TCP_INIT_CWND>>1), 0);
	schedule_chirp(sk, (TCP_INIT_CWND>>1), 0);

	ca->pc_state |= STATE_ACTIVE;
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
