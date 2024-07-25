/*
  ipclog.c - crash extension module for parsing qcom ipc logs

  Copyright (C) 2024  yeping.ZHENG

  Author: yeping.zheng <yeping.zheng@nio.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "defs.h"

#define MAX_PATHNAME_LENGTH 200

const unsigned char TSV_TYPE_INVALID = 0;
const unsigned char TSV_TYPE_TIMESTAMP = 1;
const unsigned char TSV_TYPE_POINTER = 2;
const unsigned char TSV_TYPE_INT32 = 3;
const unsigned char TSV_TYPE_BYTE_ARRAY = 4;
const unsigned char TSV_TYPE_QTIMER = 5;

static void ipclog_init(void);
static void ipclog_exit(void);

static void cmd_ipclog(void);
static char *help_ipclog[];

static ulong ipc_log_context_list_offset;

static const uint32_t IPC_LOG_CONTEXT_MAGIC_NUM = 0x25874452;
static const uint32_t IPC_LOGGING_MAGIC_NUM = 0x52784425;

static struct command_table_entry command_table[] = {
    {"ipclog", cmd_ipclog, help_ipclog, 0},
    {NULL},
};

// DynamicBuffer for log data
typedef struct {
  char *buffer;
  size_t size;
  size_t length;
} DynamicBuffer;

static void init_dynamic_buffer(DynamicBuffer *buf, size_t init_size) {
  buf->size = init_size;
  buf->length = 0;
  buf->buffer = (char *)malloc(buf->size);
  if (buf->buffer == NULL) {
    perror("Failed to allocate memory\n");
    exit(1);
  }
}

static void ensure_capacity(DynamicBuffer *buf, size_t additional_size) {
  if (buf->length + additional_size > buf->size) {
    size_t new_size = buf->size * 2;
    while (buf->length + additional_size > new_size) {
      new_size *= 2;
    }
    char *new_buffer = (char *)realloc(buf->buffer, new_size);

    if (new_buffer == NULL) {
      perror("Failed to reallocate memory!\n");
      exit(1);
    }
    buf->buffer = new_buffer;
    buf->size = new_size;
  }
}

static void append_buffer(DynamicBuffer *buf, const char *data,
                          size_t data_size) {
  ensure_capacity(buf, data_size);
  memcpy(buf->buffer + buf->length, data, data_size);
  buf->length += data_size;
}

static void free_buffer(DynamicBuffer *buf) {
  free(buf->buffer);
  buf->buffer = NULL;
  buf->size = 0;
  buf->length = 0;
}

static void print_buf(DynamicBuffer *buf) {
  for (int i = 0; i < buf->length; ++i) {
    printf("%c", buf->buffer[i]);
  }
  printf("\n");
}
// End (DynamicBuffer for log data)

static void decode_buffer(DynamicBuffer *buf, FILE *fd) {
  long tsv_header_struct_size = STRUCT_SIZE("tsv_header");
  long pos = 0;
  while (pos < (buf->length)) {
    unsigned char tsv_msg_type, tsv_msg_size;
    memcpy(&tsv_msg_type, buf->buffer + pos, MEMBER_SIZE("tsv_header", "type"));
    pos += MEMBER_SIZE("tsv_header", "type");
    memcpy(&tsv_msg_size, buf->buffer + pos, MEMBER_SIZE("tsv_header", "size"));
    pos += MEMBER_SIZE("tsv_header", "size");

    long cur_msg = pos;

    // TSV_TYPE_TIMESTAMP
    unsigned char cur_msg_type, cur_msg_size;
    memcpy(&cur_msg_type, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "type"));
    cur_msg += MEMBER_SIZE("tsv_header", "type");
    memcpy(&cur_msg_size, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "size"));
    cur_msg += MEMBER_SIZE("tsv_header", "size");

    uint64_t timestamp;
    if (cur_msg_type == TSV_TYPE_TIMESTAMP) {
      if (cur_msg_size != 0) {
        memcpy(&timestamp, buf->buffer + cur_msg, 8);
      }
      cur_msg += cur_msg_size;
    }

    // TSV_TYPE_QTIMER
    uint64_t timeQtimer = 0;

    memcpy(&cur_msg_type, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "type"));
    cur_msg += MEMBER_SIZE("tsv_header", "type");
    memcpy(&cur_msg_size, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "size"));
    cur_msg += MEMBER_SIZE("tsv_header", "size");

    if (cur_msg_type == TSV_TYPE_QTIMER) {
      if (cur_msg_size != 0) {
        memcpy(&timeQtimer, buf->buffer + cur_msg, 8);
      }
      cur_msg += cur_msg_size;
    }

    // TSV_TYPE_BYTE_ARRAY
    memcpy(&cur_msg_type, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "type"));
    cur_msg += MEMBER_SIZE("tsv_header", "type");
    memcpy(&cur_msg_size, buf->buffer + cur_msg,
           MEMBER_SIZE("tsv_header", "size"));
    cur_msg += MEMBER_SIZE("tsv_header", "size");

    if (cur_msg_type == TSV_TYPE_BYTE_ARRAY) {
      fprintf(fd, "[ %10.9f       0x%lx]   ", timestamp / 1000000000.0,
              timeQtimer);
      for (int i = 0; i < cur_msg_size; ++i) {
        fprintf(fd, "%c", buf->buffer[cur_msg + i]);
      }

      if (buf->buffer[cur_msg + cur_msg_size - 1] != '\n') {
        fprintf(fd, "\n");
      }
    }
    pos += tsv_msg_size;
  }
}

static ulong get_next_page(ulong ipc_log_context_addr, ulong curr_read_page) {

  ulong hdr_addr = curr_read_page + MEMBER_OFFSET("ipc_log_page", "hdr");
  ulong list_addr = hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "list");

  ulong next;
  readmem(list_addr, KVADDR, &next, STRUCT_SIZE("list_head") / 2,
          "read next addr", FAULT_ON_ERROR); // read *next

  ulong pagelist_addr = ipc_log_context_addr +
                        MEMBER_OFFSET("struct ipc_log_context", "page_list");

  if (next == pagelist_addr) {
    readmem(list_addr, KVADDR, &next, STRUCT_SIZE("list_head") / 2,
            "read next addr", FAULT_ON_ERROR); // read *next
  }

  hdr_addr = next - MEMBER_OFFSET("ipc_log_page_header", "list");

  ulong ipc_log_page = hdr_addr - MEMBER_OFFSET("ipc_log_page", "hdr");
  return ipc_log_page;
}

static int ipc_log_callback(void *node, void *arg) {
  uint32_t magic_num;
  ulong ipc_log_context_addr = (ulong)node - ipc_log_context_list_offset;

  readmem(ipc_log_context_addr + 0, KVADDR, &magic_num,
          MEMBER_SIZE("ipc_log_context", "magic"), "read ipc_log_context.magic",
          FAULT_ON_ERROR);

  if (magic_num != IPC_LOG_CONTEXT_MAGIC_NUM) {
    return 0;
  }

  ulong name_addr =
      MEMBER_OFFSET("ipc_log_context", "name") + ipc_log_context_addr;
  char name[100];
  readmem(name_addr, KVADDR, name, MEMBER_SIZE("ipc_log_context", "name"),
          "read ipc_log_context.name", FAULT_ON_ERROR);

  ulong nd_read_page_addr =
      ipc_log_context_addr + MEMBER_OFFSET("ipc_log_context", "nd_read_page");
  ulong nd_read_page_ptr;
  readmem(nd_read_page_addr, KVADDR, &nd_read_page_ptr,
          MEMBER_SIZE("ipc_log_context", "nd_read_page"), "read nd_read_page",
          FAULT_ON_ERROR);

  ulong start_read_page = nd_read_page_ptr;
  ulong curr_read_page = start_read_page;

  ulong hdr_addr = start_read_page + MEMBER_OFFSET("ipc_log_page", "hdr");
  uint32_t ipc_logging_magic_num;
  readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "magic"), KVADDR,
          &ipc_logging_magic_num, MEMBER_SIZE("ipc_log_page_header", "magic"),
          "read magic in ipc_log_page_header", FAULT_ON_ERROR);

  if (ipc_logging_magic_num != IPC_LOGGING_MAGIC_NUM) {
    return 0;
  }

  char filePath[MAX_PATHNAME_LENGTH]; // set max filepath to 100
  snprintf(filePath, sizeof(filePath), "./ipclog/%s.log", name);

  FILE *file = fopen(filePath, "w");
  if (file == NULL) {
    perror("Error opening file, set output to stdout\n");
    file = stdout;
  }
  fprintf(file, "=====================================================\n");
  fprintf(file, "IPC log for %s, (struct ipc_log_context *) %#lx\n", name,
          ipc_log_context_addr);
  fprintf(file, "=====================================================\n");

  ulong log_page_data_size =
      STRUCT_SIZE("ipc_log_page") - MEMBER_OFFSET("ipc_log_page", "data");

  uint16_t nd_read_offset, write_offset;
  readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "nd_read_offset"),
          KVADDR, &nd_read_offset,
          MEMBER_SIZE("ipc_log_page_header", "nd_read_offset"),
          "read ipc_log_page_header.nd_read_offset", FAULT_ON_ERROR);
  readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "write_offset"),
          KVADDR, &write_offset,
          MEMBER_SIZE("ipc_log_page_header", "write_offset"),
          "read ipc_log_page_header.write_offset", FAULT_ON_ERROR);

  uint wrapped_around = (nd_read_offset <= write_offset) ? 0 : 1;

  uint stop_copy = 0;
  long bytes_to_copy = 0;
  ulong next_page;
  DynamicBuffer dbuf;
  init_dynamic_buffer(&dbuf, 16); // set default buffer size to 16
  ulong start_addr;

  while (stop_copy != 1) {
    hdr_addr = curr_read_page + MEMBER_OFFSET("ipc_log_page", "hdr");

    readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "nd_read_offset"),
            KVADDR, &nd_read_offset,
            MEMBER_SIZE("ipc_log_page_header", "nd_read_offset"),
            "read ipc_log_page_header.nd_read_offset", FAULT_ON_ERROR);
    readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "write_offset"),
            KVADDR, &write_offset,
            MEMBER_SIZE("ipc_log_page_header", "write_offset"),
            "read ipc_log_page_header.write_offset", FAULT_ON_ERROR);

    start_addr =
        curr_read_page + MEMBER_OFFSET("ipc_log_page", "data") + nd_read_offset;
    bytes_to_copy = (nd_read_offset <= write_offset)
                        ? (write_offset - nd_read_offset)
                        : (log_page_data_size - nd_read_offset);

    if (bytes_to_copy < 0) {
      stop_copy = 1;
      break;
    }

    next_page = get_next_page(ipc_log_context_addr, curr_read_page);

    if (next_page == start_read_page) {
      stop_copy = 1;
    }

    if (bytes_to_copy > 0) {
      char cur_data_buf[bytes_to_copy];
      readmem(start_addr, KVADDR, cur_data_buf, bytes_to_copy,
              "read cur data buf", FAULT_ON_ERROR);
      append_buffer(&dbuf, cur_data_buf, bytes_to_copy);
    }

    if ((wrapped_around == 0) && write_offset < log_page_data_size) {
      break;
    }

    curr_read_page = next_page;
  }

  if (wrapped_around == 1) {
    hdr_addr = start_read_page + MEMBER_OFFSET("ipc_log_page", "hdr");
    readmem(hdr_addr + MEMBER_OFFSET("ipc_log_page_header", "write_offset"),
            KVADDR, &write_offset,
            MEMBER_SIZE("ipc_log_page_header", "write_offset"),
            "read ipc_log_page_header.write_offset", FAULT_ON_ERROR);
    bytes_to_copy = write_offset;
    start_addr = start_read_page + MEMBER_OFFSET("ipc_log_page", "data");
    if (bytes_to_copy > 0) {
      char cur_data_buf[bytes_to_copy];
      readmem(start_addr, KVADDR, cur_data_buf, bytes_to_copy,
              "read cur data buf", FAULT_ON_ERROR);
      append_buffer(&dbuf, cur_data_buf, bytes_to_copy);
    }
  }
  decode_buffer(&dbuf, file);
  free_buffer(&dbuf);
  fflush(file);
  if (fclose(file) != 0) {
    perror("Failed to close file!");
  }
  printf("Decode ipclog for %s successfully!\n", name);
  return 0;
}

static int mkdir_ipclog(void) {
  struct stat st;
  if (stat("ipclog", &st) == 0 && S_ISDIR(st.st_mode)) {
    printf("ipclog dir exists, Please rm it first!\n");
    return 1;
  }

  if (mkdir("ipclog", 0755) == 0) {
    printf("Directory created successfully\n");
  } else {
    perror("Error creating directory\n");
    return 1;
  }
  return 0;
}

static void parser(void) {
  ulong ipc_log_conetxt_list_addr;
  ipc_log_conetxt_list_addr = symbol_value("ipc_log_context_list");
  ipc_log_context_list_offset = MEMBER_OFFSET("ipc_log_context", "list");

  struct list_data list_data, *ld;
  ld = &list_data;
  BZERO(ld, sizeof(struct list_data));

  ld->flags |= (LIST_CALLBACK | CALLBACK_RETURN);
  ld->start = ipc_log_conetxt_list_addr;
  ld->callback_func = ipc_log_callback;

  do_list(ld);
}

static void __attribute__((constructor)) ipclog_init(void) {
  register_extension(command_table);
}

static void __attribute__((destructor)) ipclog_exit(void) {
  error(INFO, "exit ipclog\n");
}

static void cmd_ipclog(void) {
  if (mkdir_ipclog()) {
    return;
  }

  parser();
}

static char *help_ipclog[] = {"ipclog",           /* command name */
                              "Save all ipc log", /* short description */
                              "", /* argument synopsis, or " " if none */

                              "  This command save all ipclogs.",
                              "\nEXAMPLE",
                              "  Generate all ipc log:\n",
                              "    crash> ipclog",
                              "    Will save all ipclog in specific files",
                              NULL};
