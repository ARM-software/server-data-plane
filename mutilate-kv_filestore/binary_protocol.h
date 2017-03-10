#ifndef BINARY_PROTOCOL_H
#define	BINARY_PROTOCOL_H

#define MAGIC_NUM 0xDF
#define MAGIC_NUM_RESP 0xEF

typedef enum {
  QDOFS_CREATE = 0x1,
  QDOFS_WRITE = 0x2,
  QDOFS_READ = 0x3,
  QDOFS_ERROR = 0x4,
  QDOFS_REPLICATE_WRITE = 0x5,
  QDOFS_REPLICATE_CREATE = 0x6,
} msg_type;

struct msg_header {
  uint8_t magic;
  uint8_t msg_type;
  uint64_t file_offset;
  uint64_t file_read_len;
  uint32_t fileid_len;
  uint32_t data_len;
  uint32_t total_payload; // fileid_len + data_len + msg_footer
  uint64_t xaction_uuid;
} __attribute__((packed));

struct msg_footer {
  uint32_t crc;
} __attribute__((packed));

#endif /* BINARY_PROTOCOL_H */
