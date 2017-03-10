/* -*- c++ -*- */
#ifndef AGENTSTATS_H
#define AGENTSTATS_H

#define MAX_HIST_BINS 300

class AgentStats {
public:
  uint64_t rx_bytes, tx_bytes;
  uint64_t gets, sets, get_misses;
  uint64_t skips;

  double start, stop;

  uint64_t get_sampler_entries;
  uint64_t get_sampler[MAX_HIST_BINS];
  uint64_t get_sum;
  uint64_t get_sumsq;
  uint64_t set_sampler_entries;
  uint64_t set_sampler[MAX_HIST_BINS];
  uint64_t set_sum;
  uint64_t set_sumsq;
  uint64_t op_sampler_entries;
  uint64_t op_sampler[MAX_HIST_BINS];
  uint64_t op_sum;
  uint64_t op_sumsq;
};

#endif // AGENTSTATS_H
