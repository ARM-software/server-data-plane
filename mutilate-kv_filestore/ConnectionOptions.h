#ifndef CONNECTIONOPTIONS_H
#define CONNECTIONOPTIONS_H

#include "distributions.h"

typedef struct {
  int connections;
  bool blocking;
  double lambda;
  int qps;
  int records;

  bool binary;

  char keysize[64];
  char valuesize[64];
  char readsize[64];
  // int keysize;
  //  int valuesize;
  char ia[32];
  int maxreadsize;

  // qps_per_connection
  // iadist

  double update;
  int time;
  bool loadonly;
  int depth;
  bool no_nodelay;
  bool noload;
  int threads;
  enum distribution_t iadist;
  int warmup;
  bool skip;

  bool roundrobin;
  int server_given;
  int lambda_denom;

  bool oob_thread;

  bool moderate;
} options_t;

#endif // CONNECTIONOPTIONS_H
