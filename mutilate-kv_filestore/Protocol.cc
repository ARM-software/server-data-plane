#include <netinet/tcp.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#include "Protocol.h"
#include "Connection.h"
#include "distributions.h"
#include "Generator.h"
#include "mutilate.h"
#include "binary_protocol.h"
#include "util.h"

#define unlikely(x) __builtin_expect((x),0)


/**
 * Send a binary get request.
 */
int ProtocolBinary::read_request(const char* key, uint64_t read_len,
				 uint64_t xaction_uuid) {
  uint64_t keylen = strlen(key);

  // each line is 4-bytes
  struct msg_header h = { MAGIC_NUM, QDOFS_READ, 0, htonll(read_len),
                        htonl(keylen), 0x0,
			htonl(keylen + sizeof(struct msg_footer)),
                        htonll(xaction_uuid)};

  struct msg_footer f = { 0x0 };

  bufferevent_write(bev, &h, sizeof(h)); // size does not include extras
  bufferevent_write(bev, key, keylen);
  bufferevent_write(bev, &f, sizeof(f));
  return (sizeof(struct msg_header) + sizeof(struct msg_footer) + keylen);
}

/**
 * Send a binary set request.
 */
int ProtocolBinary::write_request(const char* key, const char* value, int len,
				  uint64_t xaction_uuid) {
  uint32_t keylen = strlen(key);

  // each line is 4-bytes
  struct msg_header h = { MAGIC_NUM, QDOFS_WRITE, 0, 0, htonl(keylen),
                        htonl(len), htonl(keylen + len + sizeof(struct msg_footer)),
			htonll(xaction_uuid)};
  struct msg_footer f = { 0x0 };

  bufferevent_write(bev, &h, sizeof(h)); // With extras
  bufferevent_write(bev, key, keylen);
  bufferevent_write(bev, value, len);
  bufferevent_write(bev, &f, sizeof(f));
  return (sizeof(struct msg_header) + sizeof(struct msg_footer) + keylen + len);
}

int ProtocolBinary::create_request(const char* key, const char* value, int len,
				   uint64_t xaction_uuid)
{
  uint32_t keylen = strlen(key);

  // each line is 4-bytes
  struct msg_header h = { MAGIC_NUM, QDOFS_CREATE, 0, 0, htonl(keylen),
                        htonl(len), htonl(keylen + len + sizeof(struct msg_footer)),
			htonll(xaction_uuid)};
  struct msg_footer f = { 0x0 };

  bufferevent_write(bev, &h, sizeof(h)); // With extras
  bufferevent_write(bev, key, keylen);
  bufferevent_write(bev, value, len);
  bufferevent_write(bev, &f, sizeof(f));
  return (sizeof(struct msg_header) + sizeof(struct msg_footer) + keylen + len);
}

/**
 * Tries to consume a binary response (in its entirety) from an evbuffer.
 *
 * @param input evBuffer to read response from
 * @return  true if consumed, false if not enough data in buffer.
 */
bool ProtocolBinary::handle_response(evbuffer *input, bool &done, uint64_t &uuid) {
  // Read the first 24 bytes as a header
  unsigned int length = evbuffer_get_length(input);
  if (length < (sizeof(struct msg_header) +
		sizeof(struct msg_footer)))
    return false;

  struct msg_header* h =
          reinterpret_cast<struct msg_header*>(evbuffer_pullup(input, sizeof(struct msg_header)));
  assert(h);

  // Not whole response
  unsigned int targetLen = sizeof(struct msg_header) + ntohl(h->total_payload);
  if (length < targetLen) return false;

  // If something other than success, count it as a miss
  if (h->magic != MAGIC_NUM_RESP) {
    conn->stats.get_misses++;
  }

  // If an error happens, count it as a miss for now
  if (h->msg_type == QDOFS_ERROR) {
    conn->stats.get_misses++;
  }

  uuid = ntohll(h->xaction_uuid);
  evbuffer_drain(input, targetLen);
  conn->stats.rx_bytes += targetLen;
  done = true;
  return true;
}

