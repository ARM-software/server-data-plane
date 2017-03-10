// -*- c++-mode -*-
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <event2/bufferevent.h>

#include "ConnectionOptions.h"

using namespace std;

class Connection;

class Protocol {
public:
  Protocol(options_t _opts, Connection* _conn, bufferevent* _bev):
    opts(_opts), conn(_conn), bev(_bev) {};
  ~Protocol() {};

  virtual int  read_request(const char* key, uint64_t read_len,
			    uint64_t xaction_uuid) = 0;
  virtual int  write_request(const char* key, const char* value, int len,
			     uint64_t xaction_uuid) = 0;
  virtual int  create_request(const char* key, const char* value, int len,
			      uint64_t xaction_uuid) = 0; 
  virtual bool handle_response(evbuffer* input, bool &done, uint64_t &uuid) = 0;

protected:
  options_t    opts;
  Connection*  conn;
  bufferevent* bev;
};

class ProtocolBinary : public Protocol {
public:
  ProtocolBinary(options_t opts, Connection* conn, bufferevent* bev):
    Protocol(opts, conn, bev) {};
  ~ProtocolBinary() {};

  virtual int  read_request(const char* key, uint64_t read_len,
			    uint64_t xaction_uuid);
  virtual int  write_request(const char* key, const char* value, int len,
			     uint64_t xaction_uuid);
  virtual int  create_request(const char* key, const char* value, int len,
			      uint64_t xaction_uuid);
  virtual bool handle_response(evbuffer* input, bool &done, uint64_t &uuid);
};

#endif
