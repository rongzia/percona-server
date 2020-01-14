/***********************************************************************

Copyright (c) 1995, 2019, Oracle and/or its affiliates. All Rights Reserved.
Copyright (c) 2009, 2016, Percona Inc.

Portions of this file contain modifications contributed and copyrighted
by Percona Inc.. Those modifications are
gratefully acknowledged and are described briefly in the InnoDB
documentation. The contributions by Percona Inc. are incorporated with
their permission, and subject to the conditions contained in the file
COPYING.Percona.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2.0,
as published by the Free Software Foundation.

This program is also distributed with certain software (including
but not limited to OpenSSL) that is licensed under separate terms,
as designated in a particular file or component or in included license
documentation.  The authors of MySQL hereby grant you an additional
permission to link the program and your derivative works with the
separately licensed software that they have included with MySQL.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License, version 2.0, for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

***********************************************************************/

/** @file os/os0file.cc
 The interface to the operating system file i/o primitives

 Created 10/21/1995 Heikki Tuuri
 *******************************************************/
#include "mysys/my_static.h"

#include "os0file.h"
#include "btr0types.h"
#include "fil0crypt.h"
#include "fil0fil.h"
#include "ha_prototypes.h"
#include "log0log.h"
#include "my_compiler.h"
#include "my_dbug.h"
#include "my_inttypes.h"
#include "my_io.h"
#include "sql_const.h"
#include "srv0srv.h"
#include "srv0start.h"
#include "system_key.h"
#include "trx0trx.h"
#ifndef UNIV_HOTBACKUP
#include "os0event.h"
#include "os0thread.h"
#endif /* !UNIV_HOTBACKUP */

#ifdef _WIN32
#include <errno.h>
#include <mbstring.h>
#include <sys/stat.h>
#include <tchar.h>
#include <codecvt>
#endif /* _WIN32 */

#ifdef __linux__
#include <sys/sendfile.h>
#endif /* __linux__ */

#ifdef LINUX_NATIVE_AIO
#ifndef UNIV_HOTBACKUP
#include <libaio.h>
#else /* !UNIV_HOTBACKUP */
#undef LINUX_NATIVE_AIO
#endif /* !UNIV_HOTBACKUP */
#endif /* LINUX_NATIVE_AIO */

#ifdef HAVE_FALLOC_PUNCH_HOLE_AND_KEEP_SIZE
#include <fcntl.h>
#include <linux/falloc.h>
#endif /* HAVE_FALLOC_PUNCH_HOLE_AND_KEEP_SIZE */

#include <errno.h>
#include <lz4.h>
#include "buf0buf.h"
#include "my_aes.h"
#include "my_rnd.h"
#include "mysql/service_mysql_keyring.h"
#include "mysqld.h"

#include <sys/types.h>
#include <zlib.h>
#include <ctime>
#include <functional>
#include <new>
#include <vector>

#ifdef UNIV_HOTBACKUP
#include <data0type.h>
#endif /* UNIV_HOTBACKUP */

/* Flush after each os_fsync_threshold bytes */
unsigned long long os_fsync_threshold = 0;

/** Insert buffer segment id */
static const ulint IO_IBUF_SEGMENT = 0;

/** Log segment id */
static const ulint IO_LOG_SEGMENT = 1;

/** Number of retries for partial I/O's */
static const ulint NUM_RETRIES_ON_PARTIAL_IO = 10;

/** Blocks for doing IO, used in the transparent compression
and encryption code. */
struct Block {
  /** Default constructor */
  Block() : m_ptr(), m_in_use() {}

  byte *m_ptr;

  byte pad[INNOBASE_CACHE_LINE_SIZE - sizeof(ulint)];
  lock_word_t m_in_use;
};

/** For storing the allocated blocks */
typedef std::vector<Block> Blocks;

/** Block collection */
static Blocks *block_cache;

/** Number of blocks to allocate for sync read/writes */
static const size_t MAX_BLOCKS = 128;

/** Block buffer size */
#define BUFFER_BLOCK_SIZE ((ulint)(UNIV_PAGE_SIZE * 1.3))

/** Disk sector size of aligning write buffer for DIRECT_IO */
static ulint os_io_ptr_align = UNIV_SECTOR_SIZE;

/** Set to true when default master key is used. This variable
main purpose is to avoid extra Encryption::get_master_key() when there
are no encrypted tablespaces */
bool default_master_key_used = false;

/** Determine if O_DIRECT is supported
@retval	true	if O_DIRECT is supported.
@retval	false	if O_DIRECT is not supported. */
bool os_is_o_direct_supported() {
#if !defined(NO_FALLOCATE) && defined(UNIV_LINUX)
  char *path = srv_data_home;
  char *file_name;
  os_file_t file_handle;
  ulint dir_len;
  ulint path_len;
  bool add_os_path_separator = false;

  /* If the srv_data_home is empty, set the path to current dir. */
  char current_dir[3];
  if (*path == 0) {
    current_dir[0] = FN_CURLIB;
    current_dir[1] = FN_LIBCHAR;
    current_dir[2] = 0;
    path = current_dir;
  }

  /* Get the path length. */
  if (path[strlen(path) - 1] == OS_PATH_SEPARATOR) {
    /* path is ended with OS_PATH_SEPARATOR */
    dir_len = strlen(path);
  } else {
    /* path is not ended with OS_PATH_SEPARATOR */
    dir_len = strlen(path) + 1;
    add_os_path_separator = true;
  }

  /* Allocate a new path and move the directory path to it. */
  path_len = dir_len + sizeof "o_direct_test";
  file_name = static_cast<char *>(ut_zalloc_nokey(path_len));
  if (add_os_path_separator == true) {
    memcpy(file_name, path, dir_len - 1);
    file_name[dir_len - 1] = OS_PATH_SEPARATOR;
  } else {
    memcpy(file_name, path, dir_len);
  }

  /* Construct a temp file name. */
  strcat(file_name + dir_len, "o_direct_test");

  /* Try to create a temp file with O_DIRECT flag. */
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:" << file_name << ", call by os_is_o_direct_supported().";
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  file_handle =
      ::open(file_name, O_CREAT | O_TRUNC | O_WRONLY | O_DIRECT, S_IRWXU);
//! to remote_fun :
#else
  file_handle =
          remote_client->remote_open(file_name, O_CREAT | O_TRUNC | O_WRONLY | O_DIRECT, S_IRWXU);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:" << file_name << ", fd:" << file_handle;
#endif // MULTI_MASTER_ZHANG_LOG

  /* If Failed */
  if (file_handle == -1) {
    ut_free(file_name);
    return (false);
  }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] unlink";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  ::close(file_handle);
  unlink(file_name);
//! to remote_fun :
#else
  remote_client->remote_close(file_handle);
  remote_client->remote_unlink(file_name);
#endif
  ut_free(file_name);

  return (true);
#else
  return (false);
#endif /* !NO_FALLOCATE && UNIV_LINUX */
}

/* This specifies the file permissions InnoDB uses when it creates files in
Unix; the value of os_innodb_umask is initialized in ha_innodb.cc to
my_umask */

#ifndef _WIN32
/** Umask for creating files */
static ulint os_innodb_umask = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
#else
/** Umask for creating files */
static ulint os_innodb_umask = 0;

/* On Windows when using native AIO the number of AIO requests
that a thread can handle at a given time is limited to 32
i.e.: SRV_N_PENDING_IOS_PER_THREAD */
#define SRV_N_PENDING_IOS_PER_THREAD OS_AIO_N_PENDING_IOS_PER_THREAD

#endif /* _WIN32 */

/** In simulated aio, merge at most this many consecutive i/os */
static const ulint OS_AIO_MERGE_N_CONSECUTIVE = 64;

/** Checks if the page_cleaner is in active state. */
bool buf_flush_page_cleaner_is_active();

#ifndef UNIV_HOTBACKUP
/**********************************************************************

InnoDB AIO Implementation:
=========================

We support native AIO for Windows and Linux. For rest of the platforms
we simulate AIO by special IO-threads servicing the IO-requests.

Simulated AIO:
==============

On platforms where we 'simulate' AIO, the following is a rough explanation
of the high level design.
There are four io-threads (for ibuf, log, read, write).
All synchronous IO requests are serviced by the calling thread using
os_file_write/os_file_read. The Asynchronous requests are queued up
in an array (there are four such arrays) by the calling thread.
Later these requests are picked up by the IO-thread and are serviced
synchronously.

Windows native AIO:
==================

If srv_use_native_aio is not set then Windows follow the same
code as simulated AIO. If the flag is set then native AIO interface
is used. On windows, one of the limitation is that if a file is opened
for AIO no synchronous IO can be done on it. Therefore we have an
extra fifth array to queue up synchronous IO requests.
There are innodb_file_io_threads helper threads. These threads work
on the four arrays mentioned above in Simulated AIO. No thread is
required for the sync array.
If a synchronous IO request is made, it is first queued in the sync
array. Then the calling thread itself waits on the request, thus
making the call synchronous.
If an AIO request is made the calling thread not only queues it in the
array but also submits the requests. The helper thread then collects
the completed IO request and calls completion routine on it.

Linux native AIO:
=================

If we have libaio installed on the system and innodb_use_native_aio
is set to true we follow the code path of native AIO, otherwise we
do simulated AIO.
There are innodb_file_io_threads helper threads. These threads work
on the four arrays mentioned above in Simulated AIO.
If a synchronous IO request is made, it is handled by calling
os_file_write/os_file_read.
If an AIO request is made the calling thread not only queues it in the
array but also submits the requests. The helper thread then collects
the completed IO request and calls completion routine on it.

**********************************************************************/

#ifdef UNIV_PFS_IO
/* Keys to register InnoDB I/O with performance schema */
mysql_pfs_key_t innodb_log_file_key;
mysql_pfs_key_t innodb_data_file_key;
mysql_pfs_key_t innodb_temp_file_key;
mysql_pfs_key_t innodb_arch_file_key;
mysql_pfs_key_t innodb_clone_file_key;
mysql_pfs_key_t innodb_bmp_file_key;
mysql_pfs_key_t innodb_parallel_dblwrite_file_key;
#endif /* UNIV_PFS_IO */

#endif /* !UNIV_HOTBACKUP */
/** The asynchronous I/O context */
struct Slot {
  /** index of the slot in the aio array */
  uint16_t pos{0};

  /** true if this slot is reserved */
  bool is_reserved{false};

  /** time when reserved */
  ib_time_monotonic_t reservation_time{0};

  /** buffer used in i/o */
  byte *buf{nullptr};

  /** Buffer pointer used for actual IO. We advance this
  when partial IO is required and not buf */
  byte *ptr{nullptr};

  /** OS_FILE_READ or OS_FILE_WRITE */
  IORequest type{IORequest::UNSET};

  /** file offset in bytes */
  os_offset_t offset{0};

  /** file where to read or write */
  pfs_os_file_t file{
#ifdef UNIV_PFS_IO
      nullptr,  // m_psi
#endif
      0  // m_file
  };

  /** file name or path */
  const char *name{nullptr};

  /** used only in simulated aio: true if the physical i/o
  already made and only the slot message needs to be passed
  to the caller of os_aio_simulated_handle */
  bool io_already_done{false};

  space_id_t space_id;

  /** The file node for which the IO is requested. */
  fil_node_t *m1{nullptr};

  /** the requester of an aio operation and which can be used
  to identify which pending aio operation was completed */
  void *m2{nullptr};

  /** AIO completion status */
  dberr_t err{DB_ERROR_UNSET};

#ifdef WIN_ASYNC_IO
  /** handle object we need in the OVERLAPPED struct */
  HANDLE handle{INVALID_HANDLE_VALUE};

  /** Windows control block for the aio request */
  OVERLAPPED control{0, 0};

  /** bytes written/read */
  DWORD n_bytes{0};

  /** length of the block to read or write */
  DWORD len{0};

#elif defined(LINUX_NATIVE_AIO)
  /** Linux control block for aio */
  struct iocb control;

  /** AIO return code */
  int ret{0};

  /** bytes written/read. */
  ssize_t n_bytes{0};

  /** length of the block to read or write */
  ulint len{0};
#else
  /** length of the block to read or write */
  ulint len{0};

  /** bytes written/read. */
  ulint n_bytes{0};
#endif /* WIN_ASYNC_IO */

  /** Length of the block before it was compressed */
  uint32 original_len{0};

  /** Buffer block for compressed pages or encrypted pages */
  Block *buf_block{nullptr};

  /** true, if we shouldn't punch a hole after writing the page */
  bool skip_punch_hole{false};

  /** Buffer for encrypt log */
  void *encrypt_log_buf{nullptr};

  Slot() {
#if defined(LINUX_NATIVE_AIO)
    memset(&control, 0, sizeof(control));
#endif /* LINUX_NATIVE_AIO */
  }
};

/** The asynchronous i/o array structure */
class AIO {
 public:
  /** Constructor
  @param[in]	id		Latch ID
  @param[in]	n		Number of slots to configure
  @param[in]	segments	Number of segments to configure */
  AIO(latch_id_t id, ulint n, ulint segments);

  /** Destructor */
  ~AIO();

  /** Initialize the instance
  @return DB_SUCCESS or error code */
  dberr_t init();

  /** Requests for a slot in the aio array. If no slot is available, waits
  until not_full-event becomes signaled.

  @param[in,out]	type	IO context
  @param[in,out]	m1	message to be passed along with the AIO
                          operation
  @param[in,out]	m2	message to be passed along with the AIO
                          operation
  @param[in]	file	file handle
  @param[in]	name	name of the file or path as a null-terminated
                          string
  @param[in,out]	buf	buffer where to read or from which to write
  @param[in]	offset	file offset, where to read from or start writing
  @param[in]	len	length of the block to read or write
  @return pointer to slot */
  Slot *reserve_slot(IORequest &type, fil_node_t *m1, void *m2,
                     pfs_os_file_t file, const char *name, void *buf,
                     os_offset_t offset, ulint len, space_id_t space_id)
      MY_ATTRIBUTE((warn_unused_result));

  /** @return number of reserved slots */
  ulint pending_io_count() const;

  /** Returns a pointer to the nth slot in the aio array.
  @param[in]	i	Index of the slot in the array
  @return pointer to slot */
  const Slot *at(ulint i) const MY_ATTRIBUTE((warn_unused_result)) {
    ut_a(i < m_slots.size());

    return (&m_slots[i]);
  }

  /** Non const version */
  Slot *at(ulint i) MY_ATTRIBUTE((warn_unused_result)) {
    ut_a(i < m_slots.size());

    return (&m_slots[i]);
  }

  /** Frees a slot in the AIO array, assumes caller owns the mutex.
  @param[in,out]	slot	Slot to release */
  void release(Slot *slot);

  /** Frees a slot in the AIO array, assumes caller doesn't own the mutex.
  @param[in,out]	slot	Slot to release */
  void release_with_mutex(Slot *slot);

  /** Prints info about the aio array.
  @param[in,out]	file	Where to print */
  void print(FILE *file);

  /** @return the number of slots per segment */
  ulint slots_per_segment() const MY_ATTRIBUTE((warn_unused_result)) {
    return (m_slots.size() / m_n_segments);
  }

  /** @return accessor for n_segments */
  ulint get_n_segments() const MY_ATTRIBUTE((warn_unused_result)) {
    return (m_n_segments);
  }

#ifdef UNIV_DEBUG
  /** @return true if the thread owns the mutex */
  bool is_mutex_owned() const MY_ATTRIBUTE((warn_unused_result)) {
    return (mutex_own(&m_mutex));
  }
#endif /* UNIV_DEBUG */

  /** Acquire the mutex */
  void acquire() const { mutex_enter(&m_mutex); }

  /** Release the mutex */
  void release() const { mutex_exit(&m_mutex); }

  /** Write out the state to the file/stream
  @param[in, out]	file	File to write to */
  void to_file(FILE *file) const;

  /** Submit buffered AIO requests on the given segment to the kernel.
  (low level function).
  @param[in] acquire_mutex specifies whether to lock array mutex */
  static void os_aio_dispatch_read_array_submit_low(bool acquire_mutex);

#ifdef LINUX_NATIVE_AIO
  /** Dispatch an AIO request to the kernel.
  @param[in,out]	slot	an already reserved slot
        @param[in]	should_buffer	should buffer the request
                                        rather than submit
  @return true on success. */
  bool linux_dispatch(Slot *slot, bool should_buffer)
      MY_ATTRIBUTE((warn_unused_result));

  /** Accessor for an AIO event
  @param[in]	index	Index into the array
  @return the event at the index */
  io_event *io_events(ulint index) MY_ATTRIBUTE((warn_unused_result)) {
    ut_a(index < m_events.size());

    return (&m_events[index]);
  }

  /** Accessor for the AIO context
  @param[in]	segment	Segment for which to get the context
  @return the AIO context for the segment */
  io_context *io_ctx(ulint segment) MY_ATTRIBUTE((warn_unused_result)) {
    ut_ad(segment < get_n_segments());

    return (m_aio_ctx[segment]);
  }

  /** Creates an io_context for native linux AIO.
  @param[in]	max_events	number of events
  @param[out]	io_ctx		io_ctx to initialize.
  @return true on success. */
  static bool linux_create_io_ctx(ulint max_events, io_context_t *io_ctx)
      MY_ATTRIBUTE((warn_unused_result));

  /** Checks if the system supports native linux aio. On some kernel
  versions where native aio is supported it won't work on tmpfs. In such
  cases we can't use native aio as it is not possible to mix simulated
  and native aio.
  @return true if supported, false otherwise. */
  static bool is_linux_native_aio_supported()
      MY_ATTRIBUTE((warn_unused_result));
#endif /* LINUX_NATIVE_AIO */

#ifdef WIN_ASYNC_IO
  /** Wakes up all async i/o threads in the array in Windows async I/O at
  shutdown. */
  void signal() {
    for (ulint i = 0; i < m_slots.size(); ++i) {
      SetEvent(m_slots[i].handle);
    }
  }

  /** Wake up all AIO threads in Windows native aio */
  static void wake_at_shutdown() {
    s_reads->signal();

    if (s_writes != NULL) {
      s_writes->signal();
    }

    if (s_ibuf != NULL) {
      s_ibuf->signal();
    }

    if (s_log != NULL) {
      s_log->signal();
    }
  }
#endif /* WIN_ASYNC_IO */

#ifdef _WIN32
  /** This function can be called if one wants to post a batch of reads
  and prefers an I/O - handler thread to handle them all at once later.You
  must call os_aio_simulated_wake_handler_threads later to ensure the
  threads are not left sleeping! */
  static void simulated_put_read_threads_to_sleep();

  /** The non asynchronous IO array.
  @return the synchronous AIO array instance. */
  static AIO *sync_array() MY_ATTRIBUTE((warn_unused_result)) {
    return (s_sync);
  }

  /**
  Get the AIO handles for a segment.
  @param[in]	segment		The local segment.
  @return the handles for the segment. */
  HANDLE *handles(ulint segment) MY_ATTRIBUTE((warn_unused_result)) {
    ut_ad(segment < m_handles->size() / slots_per_segment());

    return (&(*m_handles)[segment * slots_per_segment()]);
  }

  /** @return true if no slots are reserved */
  bool is_empty() const MY_ATTRIBUTE((warn_unused_result)) {
    ut_ad(is_mutex_owned());
    return (m_n_reserved == 0);
  }
#endif /* _WIN32 */

  /** Create an instance using new(std::nothrow)
  @param[in]	id		Latch ID
  @param[in]	n		The number of AIO request slots
  @param[in]	n_segments	The number of segments
  @return a new AIO instance */
  static AIO *create(latch_id_t id, ulint n, ulint n_segments)
      MY_ATTRIBUTE((warn_unused_result));

  /** Initializes the asynchronous io system. Creates one array each
  for ibuf and log I/O. Also creates one array each for read and write
  where each array is divided logically into n_readers and n_writers
  respectively. The caller must create an i/o handler thread for each
  segment in these arrays. This function also creates the sync array.
  No I/O handler thread needs to be created for that
  @param[in]	n_per_seg	maximum number of pending aio
                                  operations allowed per segment
  @param[in]	n_readers	number of reader threads
  @param[in]	n_writers	number of writer threads
  @param[in]	n_slots_sync	number of slots in the sync aio array
  @return true if AIO sub-system was started successfully */
  static bool start(ulint n_per_seg, ulint n_readers, ulint n_writers,
                    ulint n_slots_sync) MY_ATTRIBUTE((warn_unused_result));

  /** Free the AIO arrays */
  static void shutdown();

  /** Print all the AIO segments
  @param[in,out]	file		Where to print */
  static void print_all(FILE *file);

  /** Calculates local segment number and aio array from global
  segment number.
  @param[out]	array		AIO wait array
  @param[in]	segment		global segment number
  @return local segment number within the aio array */
  static ulint get_array_and_local_segment(AIO **array, ulint segment)
      MY_ATTRIBUTE((warn_unused_result));

  /** Select the IO slot array
  @param[in,out]	type		Type of IO, READ or WRITE
  @param[in]	read_only	true if running in read-only mode
  @param[in]	aio_mode	IO mode
  @return slot array or NULL if invalid mode specified */
  static AIO *select_slot_array(IORequest &type, bool read_only,
                                AIO_mode aio_mode)
      MY_ATTRIBUTE((warn_unused_result));

  /** Calculates segment number for a slot.
  @param[in]	array		AIO wait array
  @param[in]	slot		slot in this array
  @return segment number (which is the number used by, for example,
          I/O handler threads) */
  static ulint get_segment_no_from_slot(const AIO *array, const Slot *slot)
      MY_ATTRIBUTE((warn_unused_result));

  /** Wakes up a simulated AIO I/O-handler thread if it has something
  to do.
  @param[in]	global_segment	the number of the segment in the
                                  AIO arrays */
  static void wake_simulated_handler_thread(ulint global_segment);

  /** Check if it is a read request
  @param[in]	aio		The AIO instance to check
  @return true if the AIO instance is for reading. */
  static bool is_read(const AIO *aio) MY_ATTRIBUTE((warn_unused_result)) {
    return (s_reads == aio);
  }

  /** Wait on an event until no pending writes */
  static void wait_until_no_pending_writes() {
    os_event_wait(AIO::s_writes->m_is_empty);
  }

  /** Print to file
  @param[in]	file		File to write to */
  static void print_to_file(FILE *file);

  /** Check for pending IO. Gets the count and also validates the
  data structures.
  @return count of pending IO requests */
  static ulint total_pending_io_count();

 private:
  /** Initialise the slots
  @return DB_SUCCESS or error code */
  dberr_t init_slots() MY_ATTRIBUTE((warn_unused_result));

  /** Wakes up a simulated AIO I/O-handler thread if it has something
  to do for a local segment in the AIO array.
  @param[in]	global_segment	the number of the segment in the
                                  AIO arrays
  @param[in]	segment		the local segment in the AIO array */
  void wake_simulated_handler_thread(ulint global_segment, ulint segment);

  /** Prints pending IO requests per segment of an aio array.
  We probably don't need per segment statistics but they can help us
  during development phase to see if the IO requests are being
  distributed as expected.
  @param[in,out]	file		file where to print
  @param[in]	segments	pending IO array */
  void print_segment_info(FILE *file, const ulint *segments);

#ifdef LINUX_NATIVE_AIO
  /** Initialise the Linux native AIO data structures
  @return DB_SUCCESS or error code */
  dberr_t init_linux_native_aio() MY_ATTRIBUTE((warn_unused_result));
#endif /* LINUX_NATIVE_AIO */

 private:
  typedef std::vector<Slot> Slots;

  /** the mutex protecting the aio array */
  mutable SysMutex m_mutex;

  /** Pointer to the slots in the array.
  Number of elements must be divisible by n_threads. */
  Slots m_slots;

  /** Number of segments in the aio array of pending aio requests.
  A thread can wait separately for any one of the segments. */
  ulint m_n_segments;

  /** The event which is set to the signaled state when
  there is space in the aio outside the ibuf segment */
  os_event_t m_not_full;

  /** The event which is set to the signaled state when
  there are no pending i/os in this array */
  os_event_t m_is_empty;

  /** Number of reserved slots in the AIO array outside
  the ibuf segment */
  ulint m_n_reserved;

#ifdef _WIN32
  typedef std::vector<HANDLE, ut_allocator<HANDLE>> Handles;

  /** Pointer to an array of OS native event handles where
  we copied the handles from slots, in the same order. This
  can be used in WaitForMultipleObjects; used only in Windows */
  Handles *m_handles;
#endif /* _WIN32 */

#if defined(LINUX_NATIVE_AIO)
  typedef std::vector<io_event> IOEvents;

  /** completion queue for IO. There is one such queue per
  segment. Each thread will work on one ctx exclusively. */
  io_context_t *m_aio_ctx;

  /** The array to collect completed IOs. There is one such
  event for each possible pending IO. The size of the array
  is equal to m_slots.size(). */
  IOEvents m_events;

  /** Array to buffer the not-submitted aio requests. The array length
  is n_slots. It is divided into n_segments segments. Pending requests
  on each segment are buffered separately. */
  struct iocb **m_pending;

  /** Array of length n_segments. Each element counts the number of not
  submitted aio request on that segment. */
  ulint *m_count;
#endif /* LINUX_NATIV_AIO */

  /** The aio arrays for non-ibuf i/o and ibuf i/o, as well as
  sync AIO. These are NULL when the module has not yet been
  initialized. */

  /** Insert buffer */
  static AIO *s_ibuf;

  /** Redo log */
  static AIO *s_log;

  /** Reads */
  static AIO *s_reads;

  /** Writes */
  static AIO *s_writes;

  /** Synchronous I/O */
  static AIO *s_sync;
};

/** Static declarations */
AIO *AIO::s_reads;
AIO *AIO::s_writes;
AIO *AIO::s_ibuf;
AIO *AIO::s_log;
AIO *AIO::s_sync;

#if defined(LINUX_NATIVE_AIO)
/** timeout for each io_getevents() call = 500ms. */
static const ulint OS_AIO_REAP_TIMEOUT = 500000000UL;

/** time to sleep, in microseconds if io_setup() returns EAGAIN. */
static const ulint OS_AIO_IO_SETUP_RETRY_SLEEP = 500000UL;

/** number of attempts before giving up on io_setup(). */
static const int OS_AIO_IO_SETUP_RETRY_ATTEMPTS = 5;
#endif /* LINUX_NATIVE_AIO */

/** Array of events used in simulated AIO */
static os_event_t *os_aio_segment_wait_events = NULL;

/** Number of asynchronous I/O segments.  Set by os_aio_init(). */
static ulint os_aio_n_segments = ULINT_UNDEFINED;

/** If the following is true, read i/o handler threads try to
wait until a batch of new read requests have been posted */
static bool os_aio_recommend_sleep_for_read_threads = false;

ulint os_n_file_reads = 0;
static ulint os_bytes_read_since_printout = 0;
ulint os_n_file_writes = 0;
ulint os_n_fsyncs = 0;
static ulint os_n_file_reads_old = 0;
static ulint os_n_file_writes_old = 0;
static ulint os_n_fsyncs_old = 0;
/** Number of pending write operations */
ulint os_n_pending_writes = 0;
/** Number of pending read operations */
ulint os_n_pending_reads = 0;

static ib_time_monotonic_t os_last_printout;
bool os_has_said_disk_full = false;

/** Default Zip compression level */
extern uint page_zip_level;

static_assert(DATA_TRX_ID_LEN <= 6, "COMPRESSION_ALGORITHM will not fit!");

/** Validates the consistency of the aio system.
@return true if ok */
static bool os_aio_validate();

/** Does error handling when a file operation fails.
@param[in]	name		File name or NULL
@param[in]	operation	Name of operation e.g., "read", "write"
@return true if we should retry the operation */
static bool os_file_handle_error(const char *name, const char *operation);

/** Free storage space associated with a section of the file.
@param[in]      fh              Open file handle
@param[in]      off             Starting offset (SEEK_SET)
@param[in]      len             Size of the hole
@return DB_SUCCESS or error code */
dberr_t os_file_punch_hole(os_file_t fh, os_offset_t off, os_offset_t len);

/**
Does error handling when a file operation fails.
@param[in]	name		File name or NULL
@param[in]	operation	Name of operation e.g., "read", "write"
@param[in]	on_error_silent	if true then don't print any message to the log.
@return true if we should retry the operation */
static bool os_file_handle_error_no_exit(const char *name,
                                         const char *operation,
                                         bool on_error_silent);

/** Decompress after a read and punch a hole in the file if it was a write
@param[in]	type		IO context
@param[in]	fh		Open file handle
@param[in,out]	buf		Buffer to transform
@param[in,out]	scratch		Scratch area for read decompression
@param[in]	src_len		Length of the buffer before compression
@param[in]	offset		file offset from the start where to read
@param[in]	len		Compressed buffer length for write and size
                                of buf len for read
@return DB_SUCCESS or error code */
static dberr_t os_file_io_complete(const IORequest &type, os_file_t fh,
                                   byte *buf, byte *scratch, ulint src_len,
                                   os_offset_t offset, ulint len);

/** Does simulated AIO. This function should be called by an i/o-handler
thread.

@param[in]	global_segment	The number of the segment in the aio arrays to
                                await for; segment 0 is the ibuf i/o thread,
                                segment 1 the log i/o thread, then follow the
                                non-ibuf read threads, and as the last are the
                                non-ibuf write threads
@param[out]	m1		the messages passed with the AIO request; note
                                that also in the case where the AIO operation
                                failed, these output parameters are valid and
                                can be used to restart the operation, for
                                example
@param[out]	m2		Callback argument
@param[in]	type		IO context
@return DB_SUCCESS or error code */
static dberr_t os_aio_simulated_handler(ulint global_segment, fil_node_t **m1,
                                        void **m2, IORequest *type);

#ifdef WIN_ASYNC_IO
/** This function is only used in Windows asynchronous i/o.
Waits for an aio operation to complete. This function is used to wait the
for completed requests. The aio array of pending requests is divided
into segments. The thread specifies which segment or slot it wants to wait
for. NOTE: this function will also take care of freeing the aio slot,
therefore no other thread is allowed to do the freeing!
@param[in]	segment		The number of the segment in the aio arrays to
wait for; segment 0 is the ibuf I/O thread,
segment 1 the log I/O thread, then follow the
non-ibuf read threads, and as the last are the
non-ibuf write threads; if this is
ULINT_UNDEFINED, then it means that sync AIO
is used, and this parameter is ignored
@param[in]	pos		this parameter is used only in sync AIO:
wait for the aio slot at this position
@param[out]	m1		the messages passed with the AIO request; note
that also in the case where the AIO operation
failed, these output parameters are valid and
can be used to restart the operation,
for example
@param[out]	m2		callback message
@param[out]	type		OS_FILE_WRITE or ..._READ
@return DB_SUCCESS or error code */
static dberr_t os_aio_windows_handler(ulint segment, ulint pos, fil_node_t **m1,
                                      void **m2, IORequest *type);
#endif /* WIN_ASYNC_IO */

/** Check the file type and determine if it can be deleted.
@param[in]	name		Filename/Path to check
@return true if it's a file or a symlink and can be deleted */
static bool os_file_can_delete(const char *name) {
  switch (Fil_path::get_file_type(name)) {
    case OS_FILE_TYPE_FILE:
    case OS_FILE_TYPE_LINK:
      return (true);

    case OS_FILE_TYPE_DIR:

      ib::warn(ER_IB_MSG_743) << "'" << name << "'"
                              << " is a directory, can't delete!";
      break;

    case OS_FILE_TYPE_BLOCK:

      ib::warn(ER_IB_MSG_744) << "'" << name << "'"
                              << " is a block device, can't delete!";
      break;

    case OS_FILE_TYPE_FAILED:

      ib::warn(ER_IB_MSG_745) << "'" << name << "'"
                              << " get file type failed, won't delete!";
      break;

    case OS_FILE_TYPE_UNKNOWN:

      ib::warn(ER_IB_MSG_746) << "'" << name << "'"
                              << " unknown file type, won't delete!";
      break;

    case OS_FILE_TYPE_NAME_TOO_LONG:

      ib::warn(ER_IB_MSG_747) << "'" << name << "'"
                              << " name too long, can't delete!";
      break;

    case OS_FILE_PERMISSION_ERROR:
      ib::warn(ER_IB_MSG_748) << "'" << name << "'"
                              << " permission error, can't delete!";
      break;

    case OS_FILE_TYPE_MISSING:
      break;
  }

  return (false);
}

/** Allocate a page for sync IO
@return pointer to page */
static Block *os_alloc_block() {
  size_t pos;
  Blocks &blocks = *block_cache;
  size_t i = static_cast<size_t>(my_timer_cycles());
  const size_t size = blocks.size();
  ulint retry = 0;
  Block *block;

  DBUG_EXECUTE_IF("os_block_cache_busy", retry = MAX_BLOCKS * 3;);

  for (;;) {
    /* After go through the block cache for 3 times,
    allocate a new temporary block. */
    if (retry == MAX_BLOCKS * 3) {
      byte *ptr;

      ptr = static_cast<byte *>(
          ut_malloc_nokey(sizeof(*block) + BUFFER_BLOCK_SIZE));

      block = new (ptr) Block();
      block->m_ptr = static_cast<byte *>(ptr + sizeof(*block));
      block->m_in_use = 1;

      break;
    }

    pos = i++ % size;

    if (TAS(&blocks[pos].m_in_use, 1) == 0) {
      block = &blocks[pos];
      break;
    }

    os_thread_yield();

    ++retry;
  }

  ut_a(block->m_in_use != 0);

  return (block);
}

/** Free a page after sync IO
@param[in,out]	block		The block to free/release */
static void os_free_block(Block *block) {
  ut_ad(block->m_in_use == 1);

  TAS(&block->m_in_use, 0);

  /* When this block is not in the block cache, and it's
  a temporary block, we need to free it directly. */
  if (std::less<Block *>()(block, &block_cache->front()) ||
      std::greater<Block *>()(block, &block_cache->back())) {
    ut_free(block);
  }
}

/** Generic AIO Handler methods. Currently handles IO post processing. */
class AIOHandler {
 public:
  /** Do any post processing after a read/write
  @return DB_SUCCESS or error code. */
  static dberr_t post_io_processing(Slot *slot);

  /** Decompress after a read and punch a hole in the file if
  it was a write */
  static dberr_t io_complete(const Slot *slot) {
    ut_a(slot->offset > 0);
    ut_a(slot->type.is_read() || !slot->skip_punch_hole);
    return (os_file_io_complete(slot->type, slot->file.m_file, slot->buf, NULL,
                                slot->original_len, slot->offset, slot->len));
  }

 private:
  /** Check whether the page was encrypted.
  @param[in]	slot		The slot that contains the IO request
  @return true if it was an encyrpted page */
  static bool is_encrypted_page(const Slot *slot) {
    return (Encryption::is_encrypted_page(slot->buf));
  }

  /** Check whether the page was compressed.
  @param[in]	slot		The slot that contains the IO request
  @return true if it was a compressed page */
  static bool is_compressed_page(const Slot *slot) {
    const byte *src = slot->buf;

    ulint page_type = mach_read_from_2(src + FIL_PAGE_TYPE);

    return (page_type == FIL_PAGE_COMPRESSED);
  }

  /** Get the compressed page size.
  @param[in]	slot		The slot that contains the IO request
  @return number of bytes to read for a successful decompress */
  static ulint compressed_page_size(const Slot *slot) {
    ut_ad(slot->type.is_read());
    ut_ad(is_compressed_page(slot));

    ulint size;
    const byte *src = slot->buf;

    size = mach_read_from_2(src + FIL_PAGE_COMPRESS_SIZE_V1);

    return (size + FIL_PAGE_DATA);
  }

  /** Check if the page contents can be decompressed.
  @param[in]	slot		The slot that contains the IO request
  @return true if the data read has all the compressed data */
  static bool can_decompress(const Slot *slot) {
    ut_ad(slot->type.is_read());
    ut_ad(is_compressed_page(slot));

    ulint version;
    const byte *src = slot->buf;

    version = mach_read_from_1(src + FIL_PAGE_VERSION);

    ut_a(version == 1);

    /* Includes the page header size too */
    ulint size = compressed_page_size(slot);

    return (size <= (slot->ptr - slot->buf) + (ulint)slot->n_bytes);
  }

  /** Check if we need to read some more data.
  @param[in]	slot		The slot that contains the IO request
  @param[in]	n_bytes		Total bytes read so far
  @return DB_SUCCESS or error code */
  static dberr_t check_read(Slot *slot, ulint n_bytes);
};

/** Helper class for doing synchronous file IO. Currently, the objective
is to hide the OS specific code, so that the higher level functions aren't
peppered with "#ifdef". Makes the code flow difficult to follow.  */
class SyncFileIO {
 public:
  /** Constructor
  @param[in]	fh	File handle
  @param[in,out]	buf	Buffer to read/write
  @param[in]	n	Number of bytes to read/write
  @param[in]	offset	Offset where to read or write */
  SyncFileIO(os_file_t fh, void *buf, ulint n, os_offset_t offset)
      : m_fh(fh), m_buf(buf), m_n(static_cast<ssize_t>(n)), m_offset(offset) {
    ut_ad(m_n > 0);
  }

  /** Destructor */
  ~SyncFileIO() { /* No op */
  }

  /** Do the read/write
  @param[in]	request	The IO context and type
  @return the number of bytes read/written or negative value on error */
  ssize_t execute(const IORequest &request);

  /** Do the read/write
  @param[in,out]	slot	The IO slot, it has the IO context
  @return the number of bytes read/written or negative value on error */
  static ssize_t execute(Slot *slot);

  /** Move the read/write offset up to where the partial IO succeeded.
  @param[in]	n_bytes	The number of bytes to advance */
  void advance(ssize_t n_bytes) {
    m_offset += n_bytes;

    ut_ad(m_n >= n_bytes);

    m_n -= n_bytes;

    m_buf = reinterpret_cast<uchar *>(m_buf) + n_bytes;
  }

 private:
  /** Open file handle */
  os_file_t m_fh;

  /** Buffer to read/write */
  void *m_buf;

  /** Number of bytes to read/write */
  ssize_t m_n;

  /** Offset from where to read/write */
  os_offset_t m_offset;
};

/** If it is a compressed page return the compressed page data + footer size
@param[in]	buf		Buffer to check, must include header + 10 bytes
@return ULINT_UNDEFINED if the page is not a compressed page or length
        of the compressed data (including footer) if it is a compressed page */
ulint os_file_compressed_page_size(const byte *buf) {
  ulint type = mach_read_from_2(buf + FIL_PAGE_TYPE);

  if (type == FIL_PAGE_COMPRESSED) {
    ulint version = mach_read_from_1(buf + FIL_PAGE_VERSION);
    ut_a(version == 1);
    return (mach_read_from_2(buf + FIL_PAGE_COMPRESS_SIZE_V1));
  }

  return (ULINT_UNDEFINED);
}

/** If it is a compressed page return the original page data + footer size
@param[in] buf		Buffer to check, must include header + 10 bytes
@return ULINT_UNDEFINED if the page is not a compressed page or length
        of the original data + footer if it is a compressed page */
ulint os_file_original_page_size(const byte *buf) {
  ulint type = mach_read_from_2(buf + FIL_PAGE_TYPE);

  if (type == FIL_PAGE_COMPRESSED) {
    ulint version = mach_read_from_1(buf + FIL_PAGE_VERSION);
    ut_a(version == 1);

    return (mach_read_from_2(buf + FIL_PAGE_ORIGINAL_SIZE_V1));
  }

  return (ULINT_UNDEFINED);
}

/** Check if we need to read some more data.
@param[in]	slot		The slot that contains the IO request
@param[in]	n_bytes		Total bytes read so far
@return DB_SUCCESS or error code */
dberr_t AIOHandler::check_read(Slot *slot, ulint n_bytes) {
  dberr_t err;

  ut_ad(slot->type.is_read());
  ut_ad(slot->original_len > slot->len);

  if (is_compressed_page(slot)) {
    if (can_decompress(slot)) {
      ut_a(slot->offset > 0);

      slot->len = slot->original_len;
#ifdef _WIN32
      slot->n_bytes = static_cast<DWORD>(n_bytes);
#else
      slot->n_bytes = static_cast<ulint>(n_bytes);
#endif /* _WIN32 */

      err = io_complete(slot);
      ut_a(err == DB_SUCCESS);
    } else {
      /* Read the next block in */
      ut_ad(compressed_page_size(slot) >= n_bytes);

      err = DB_FAIL;
    }
  } else if (is_encrypted_page(slot) ||
             (slot->type.is_log() && slot->offset >= LOG_FILE_HDR_SIZE)) {
    ut_a(slot->offset > 0);

    slot->len = slot->original_len;
#ifdef _WIN32
    slot->n_bytes = static_cast<DWORD>(n_bytes);
#else
    slot->n_bytes = static_cast<ulint>(n_bytes);
#endif /* _WIN32 */

    err = io_complete(slot);
    ut_a(err == DB_SUCCESS);

  } else {
    err = DB_FAIL;
  }

  if (slot->buf_block != NULL) {
    os_free_block(slot->buf_block);
    slot->buf_block = NULL;
  }

  if (slot->encrypt_log_buf != NULL) {
    ut_free(slot->encrypt_log_buf);
    slot->encrypt_log_buf = NULL;
  }

  return (err);
}

/** Do any post processing after a read/write
@return DB_SUCCESS or error code. */
dberr_t AIOHandler::post_io_processing(Slot *slot) {
  dberr_t err;

  ut_ad(slot->is_reserved);

  /* Total bytes read so far */
  ulint n_bytes = (slot->ptr - slot->buf) + slot->n_bytes;

  /* Compressed writes can be smaller than the original length.
  Therefore they can be processed without further IO. */
  if (n_bytes == slot->original_len ||
      (slot->type.is_write() && slot->type.is_compressed() &&
       slot->len == static_cast<ulint>(slot->n_bytes))) {
    if ((slot->type.is_log() && slot->offset >= LOG_FILE_HDR_SIZE) ||
        is_compressed_page(slot) || is_encrypted_page(slot)) {
      ut_a(slot->offset > 0);

      if (slot->type.is_read()) {
        slot->len = slot->original_len;
      }

      /* The punch hole has been done on collect() */

      if (slot->type.is_read()) {
        err = io_complete(slot);
      } else {
        err = DB_SUCCESS;
      }

      ut_ad(err == DB_SUCCESS || err == DB_UNSUPPORTED ||
            err == DB_CORRUPTION || err == DB_IO_DECOMPRESS_FAIL);
    } else if (!slot->type.is_log() && slot->type.is_read() &&
               Encryption::can_page_be_keyring_encrypted(slot->buf) &&
               !slot->type.is_encryption_disabled()) {
      ut_ad(is_encrypted_page(slot) == false);
      // we did not go to io_complete - so mark read page as unencrypted here
      mach_write_to_4(slot->buf + FIL_PAGE_ENCRYPTION_KEY_VERSION,
                      ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED);
      err = DB_SUCCESS;
    } else {
      err = DB_SUCCESS;
    }

    if (slot->buf_block != NULL) {
      os_free_block(slot->buf_block);
      slot->buf_block = NULL;
    }

    if (slot->encrypt_log_buf != NULL) {
      ut_free(slot->encrypt_log_buf);
      slot->encrypt_log_buf = NULL;
    }
  } else if ((ulint)slot->n_bytes == (ulint)slot->len) {
    /* It *must* be a partial read. */
    ut_ad(slot->len < slot->original_len);

    /* Has to be a read request, if it is less than
    the original length. */
    ut_ad(slot->type.is_read());
    err = check_read(slot, n_bytes);

  } else {
    err = DB_FAIL;
  }

  return (err);
}

/** Count the number of free slots
@return number of reserved slots */
ulint AIO::pending_io_count() const {
  acquire();

#ifdef UNIV_DEBUG
  ut_a(m_n_segments > 0);
  ut_a(!m_slots.empty());

  ulint count = 0;

  for (ulint i = 0; i < m_slots.size(); ++i) {
    const Slot &slot = m_slots[i];

    if (slot.is_reserved) {
      ++count;
      ut_a(slot.len > 0);
    }
  }

  ut_a(m_n_reserved == count);
#endif /* UNIV_DEBUG */

  ulint reserved = m_n_reserved;

  release();

  return (reserved);
}

/** Compress a data page
@param[in]	compression	Compression algorithm
@param[in]	block_size	File system block size
@param[in]	src		Source contents to compress
@param[in]	src_len		Length in bytes of the source
@param[out]	dst		Compressed page contents
@param[out]	dst_len		Length in bytes of dst contents
@return buffer data, dst_len will have the length of the data */
byte *os_file_compress_page(Compression compression, ulint block_size,
                            byte *src, ulint src_len, byte *dst, ulint *dst_len,
                            bool will_be_encrypted_with_keyring) {
  ulint len = 0;
  ulint compression_level = page_zip_level;
  ulint page_type = mach_read_from_2(src + FIL_PAGE_TYPE);

  /* The page size must be a multiple of the OS punch hole size. */
  ut_ad(!(src_len % block_size));

  /* Shouldn't compress an already compressed page. */
  ut_ad(page_type != FIL_PAGE_COMPRESSED);

  /* The page must be at least twice as large as the file system
  block size if we are to save any space. Ignore R-Tree pages for now,
  they repurpose the same 8 bytes in the page header. No point in
  compressing if the file system block size >= our page size. */

  if (page_type == FIL_PAGE_RTREE || block_size == ULINT_UNDEFINED ||
      compression.m_type == Compression::NONE || src_len < block_size * 2) {
    *dst_len = src_len;

    return (src);
  }

  /* Leave the header alone when compressing. */
  ut_ad(block_size >= FIL_PAGE_DATA * 2);

  ut_ad(src_len > FIL_PAGE_DATA + block_size);

  /* Must compress to <= N-1 FS blocks. */
  /* There need to be at least 4 bytes for key version and 4 bytes for post
  encryption checksum */
  ulint out_len = src_len - (FIL_PAGE_DATA + block_size +
                             ((will_be_encrypted_with_keyring) ? 8 : 0));

  /* This is the original data page size - the page header. */
  ulint content_len = src_len - FIL_PAGE_DATA;

  ut_ad(out_len >= block_size - FIL_PAGE_DATA +
                       ((will_be_encrypted_with_keyring) ? 8 : 0));
  ut_ad(out_len <= src_len - (block_size + FIL_PAGE_DATA +
                              (will_be_encrypted_with_keyring ? 8 : 0)));

  /* Only compress the data + trailer, leave the header alone */

  switch (compression.m_type) {
    case Compression::NONE:
      ut_error;

    case Compression::ZLIB: {
      uLongf zlen = static_cast<uLongf>(out_len);

      if (compress2(dst + FIL_PAGE_DATA, &zlen, src + FIL_PAGE_DATA,
                    static_cast<uLong>(content_len),
                    static_cast<int>(compression_level)) != Z_OK) {
        *dst_len = src_len;

        return (src);
      }

      len = static_cast<ulint>(zlen);

      break;
    }

    case Compression::LZ4:

      len = LZ4_compress_default(reinterpret_cast<char *>(src) + FIL_PAGE_DATA,
                                 reinterpret_cast<char *>(dst) + FIL_PAGE_DATA,
                                 static_cast<int>(content_len),
                                 static_cast<int>(out_len));

      ut_a(len <= src_len - FIL_PAGE_DATA);

      if (len == 0 || len >= out_len) {
        *dst_len = src_len;

        return (src);
      }

      break;

    default:
      *dst_len = src_len;
      return (src);
  }

  ut_a(len <= out_len);

  ut_ad(memcmp(src + FIL_PAGE_LSN + 4,
               src + src_len - FIL_PAGE_END_LSN_OLD_CHKSUM + 4, 4) == 0);

  /* Copy the header as is. */
  memmove(dst, src, FIL_PAGE_DATA);

  /* Add compression control information. Required for decompressing. */
  mach_write_to_2(dst + FIL_PAGE_TYPE, FIL_PAGE_COMPRESSED);

  mach_write_to_1(dst + FIL_PAGE_VERSION, 1);

  mach_write_to_1(dst + FIL_PAGE_ALGORITHM_V1, compression.m_type);

  mach_write_to_2(dst + FIL_PAGE_ORIGINAL_TYPE_V1, page_type);

  mach_write_to_2(dst + FIL_PAGE_ORIGINAL_SIZE_V1, content_len);

  mach_write_to_2(dst + FIL_PAGE_COMPRESS_SIZE_V1, len);

  /* Round to the next full block size */

  len += FIL_PAGE_DATA;
  if (will_be_encrypted_with_keyring) {
    len += 8;
  }

  // For encryption with keyring keys we required that there will be at least 8
  // bytes left 4 bytes for key version and 4 bytes for post encryption checksum
  *dst_len = ut_calc_align(len, block_size);

  ut_ad(*dst_len >= len);
  ut_ad(*dst_len <=
        out_len + FIL_PAGE_DATA + (will_be_encrypted_with_keyring ? 8 : 0));

  /* Clear out the unused portion of the page. */
  if (len % block_size) {
    memset(dst + len, 0x0, block_size - (len % block_size));
  }

  return (dst);
}

#ifdef UNIV_DEBUG
#ifndef UNIV_HOTBACKUP
/** Validates the consistency the aio system some of the time.
@return true if ok or the check was skipped */
static bool os_aio_validate_skip() {
/** Try os_aio_validate() every this many times */
#define OS_AIO_VALIDATE_SKIP 13

  /** The os_aio_validate() call skip counter.
  Use a signed type because of the race condition below. */
  static int os_aio_validate_count = OS_AIO_VALIDATE_SKIP;

  /* There is a race condition below, but it does not matter,
  because this call is only for heuristic purposes. We want to
  reduce the call frequency of the costly os_aio_validate()
  check in debug builds. */
  --os_aio_validate_count;

  if (os_aio_validate_count > 0) {
    return (true);
  }

  os_aio_validate_count = OS_AIO_VALIDATE_SKIP;
  return (os_aio_validate());
}
#endif /* !UNIV_HOTBACKUP */
#endif /* UNIV_DEBUG */

#undef USE_FILE_LOCK
#define USE_FILE_LOCK
#if defined(UNIV_HOTBACKUP) || defined(_WIN32)
/* InnoDB Hot Backup does not lock the data files.
 * On Windows, mandatory locking is used.
 */
#undef USE_FILE_LOCK
#endif /* UNIV_HOTBACKUP || _WIN32 */
#ifdef USE_FILE_LOCK
/** Obtain an exclusive lock on a file.
@param[in]	fd		file descriptor
@param[in]	name		file name
@return 0 on success */
static int os_file_lock(int fd, const char *name) {
  struct flock lk;

  lk.l_type = F_WRLCK;
  lk.l_whence = SEEK_SET;
  lk.l_start = lk.l_len = 0;
///**
//@AUTHOR (rrzhang, 张融荣)
// * 注释掉文件锁，可以实现多进程读同一个 data 目录功能。
// * The function of reading the same data directory by multiple processes can be realized by commenting out the file lock.
// */
//#ifdef MULTI_MASTER_ZHANG_DEBUG
//  int flag = 0;
//#else
//  int flag = fcntl(fd, F_SETLK, &lk);
//#endif
//#ifdef MULTI_MASTER_ZHANG_NORMAL
//EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "fcntl";
//#endif

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] fcntl";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  if (fcntl(fd, F_SETLK, &lk) == -1) {
#else
//! to remote_fun :
  int flag = remote_client->remote_fcntl(fd, F_SETLK, &lk);
  if (flag == -1) {
#endif
    ib::error(ER_IB_MSG_749)
        << "Unable to lock " << name << " error: " << errno;

    if (errno == EAGAIN || errno == EACCES) {
      ib::info(ER_IB_MSG_750) << "Check that you do not already have"
                                 " another mysqld process using the"
                                 " same InnoDB data or log files.";
    }

    return (-1);
  }

  return (0);
}
#endif /* USE_FILE_LOCK */

/** Calculates local segment number and aio array from global segment number.
@param[out]	array		aio wait array
@param[in]	segment		global segment number
@return local segment number within the aio array */
ulint AIO::get_array_and_local_segment(AIO **array, ulint segment) {
  ulint local_segment;
  ulint n_extra_segs = (srv_read_only_mode) ? 0 : 2;

  ut_a(segment < os_aio_n_segments);

  if (!srv_read_only_mode && segment < n_extra_segs) {
    /* We don't support ibuf/log IO during read only mode. */

    if (segment == IO_IBUF_SEGMENT) {
      *array = s_ibuf;

    } else if (segment == IO_LOG_SEGMENT) {
      *array = s_log;

    } else {
      *array = NULL;
    }

    local_segment = 0;

  } else if (segment < s_reads->m_n_segments + n_extra_segs) {
    *array = s_reads;
    local_segment = segment - n_extra_segs;

  } else {
    *array = s_writes;

    local_segment = segment - (s_reads->m_n_segments + n_extra_segs);
  }

  return (local_segment);
}

/** Frees a slot in the aio array. Assumes caller owns the mutex.
@param[in,out]	slot		Slot to release */
void AIO::release(Slot *slot) {
  ut_ad(is_mutex_owned());

  ut_ad(slot->is_reserved);

  slot->is_reserved = false;

  --m_n_reserved;

  if (m_n_reserved == m_slots.size() - 1) {
    os_event_set(m_not_full);
  }

  if (m_n_reserved == 0) {
    os_event_set(m_is_empty);
  }

#ifdef WIN_ASYNC_IO

  ResetEvent(slot->handle);

#elif defined(LINUX_NATIVE_AIO)

  if (srv_use_native_aio) {
    memset(&slot->control, 0x0, sizeof(slot->control));
    slot->ret = 0;
    slot->n_bytes = 0;
  } else {
    /* These fields should not be used if we are not
    using native AIO. */
    ut_ad(slot->n_bytes == 0);
    ut_ad(slot->ret == 0);
  }

#endif /* WIN_ASYNC_IO */
}

/** Frees a slot in the AIO array. Assumes caller doesn't own the mutex.
@param[in,out]	slot		Slot to release */
void AIO::release_with_mutex(Slot *slot) {
  acquire();

  release(slot);

  release();
}

#ifndef UNIV_HOTBACKUP
/** Creates a temporary file.  This function is like tmpfile(3), but
the temporary file is created in the given parameter path. If the path
is NULL then it will create the file in the MySQL server configuration
parameter (--tmpdir).
@param[in]	path	location for creating temporary file
@return temporary file handle, or NULL on error */
FILE *os_file_create_tmpfile(const char *path) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "os_file_create_tmpfile(), arg[path]:" << path << "invoke ha_innodb.cc::innobase_mysql_tmpfile()";
#endif // MULTI_MASTER_ZHANG_LOG
  FILE *file = NULL;
  int fd = innobase_mysql_tmpfile(path);
//#ifdef MULTI_MASTER_ZHANG_LOG
//  char path_buf[1024];
//  GetPathByFd(fd, path_buf);
//  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "os_file_create_tmpfile() create file:" << path_buf << ", fd:" << fd;
//#endif // MULTI_MASTER_ZHANG_LOG
  if (fd >= 0) {
    file = fdopen(fd, "w+b");
//#ifdef MULTI_MASTER_ZHANG_LOG
//  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "os_file_create_tmpfile() create file: " << path_buf << ", fd:" << file->_fileno;
//#endif // MULTI_MASTER_ZHANG_LOG
  }

  if (file == NULL) {
    ib::error(ER_IB_MSG_751)
        << "Unable to create temporary file; errno: " << errno;

    if (fd >= 0) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "close fd:" << fd;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
      close(fd);
#else
//! to remote_fun :
      remote_client->remote_close(fd);
#endif // MULTI_MASTER_ZHANG_REMOTE
    }
  }
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "return fileno:" << file->_fileno;
#endif // MULTI_MASTER_ZHANG_LOG
  return (file);
}
#endif /* !UNIV_HOTBACKUP */

/** Rewind file to its start, read at most size - 1 bytes from it to str, and
NUL-terminate str. All errors are silently ignored. This function is
mostly meant to be used with temporary files.
@param[in,out]	file		File to read from
@param[in,out]	str		Buffer where to read
@param[in]	size		Size of buffer */
void os_file_read_string(FILE *file, char *str, ulint size) {
  if (size != 0) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] rewind";
#endif
    rewind(file);

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] fread";
#endif

    size_t flen = fread(str, 1, size - 1, file);

    str[flen] = '\0';
  }
}

static dberr_t verify_post_encryption_checksum(const IORequest &type,
                                               Encryption &encryption,
                                               byte *buf, ulint src_len) {
  bool is_crypt_checksum_correct =
      false;  // For MK encryption is_crypt_checksum_correct stays false
  ulint original_type =
      static_cast<uint16_t>(mach_read_from_2(buf + FIL_PAGE_ORIGINAL_TYPE_V1));

  if (encryption.m_type == Encryption::KEYRING &&
      Encryption::can_page_be_keyring_encrypted(original_type)) {
    if (type.is_page_zip_compressed()) {
      byte zip_magic[ENCRYPTION_ZIP_PAGE_KEYRING_ENCRYPTION_MAGIC_LEN];
      memcpy(zip_magic, buf + FIL_PAGE_ZIP_KEYRING_ENCRYPTION_MAGIC,
             ENCRYPTION_ZIP_PAGE_KEYRING_ENCRYPTION_MAGIC_LEN);
      is_crypt_checksum_correct =
          memcmp(zip_magic, ENCRYPTION_ZIP_PAGE_KEYRING_ENCRYPTION_MAGIC,
                 ENCRYPTION_ZIP_PAGE_KEYRING_ENCRYPTION_MAGIC_LEN) == 0;
    } else {
      is_crypt_checksum_correct = fil_space_verify_crypt_checksum(
          buf, src_len, type.is_page_zip_compressed(),
          encryption.is_encrypted_and_compressed(buf));
    }

    if (encryption.m_encryption_rotation == Encryption::NO_ROTATION &&
        !is_crypt_checksum_correct) {  // There is no re-encryption going on
      const auto space_id =
          mach_read_from_4(buf + FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID);
      const auto page_no = mach_read_from_4(buf + FIL_PAGE_OFFSET);
      ib::error() << "Post - encryption checksum verification failed - "
                     "decryption failed for space id = "
                  << space_id << " page_no = " << page_no;
      return (DB_IO_DECRYPT_FAIL);
    }
  }

  if (encryption.m_encryption_rotation ==
      Encryption::MASTER_KEY_TO_KEYRING) {  // There is re-encryption going on
    encryption.m_type =
        is_crypt_checksum_correct
            ? Encryption::KEYRING  // assume page is RK encrypted
            : Encryption::AES;     // assume page is MK encrypted
  }
  return DB_SUCCESS;
}

static void assing_key_version(byte *buf, Encryption &encryption,
                               bool is_page_encrypted) {
  if (is_page_encrypted && encryption.m_type == Encryption::KEYRING) {
    mach_write_to_2(buf + FIL_PAGE_ORIGINAL_TYPE_V1, FIL_PAGE_ENCRYPTED);
    ut_ad(encryption.m_key_version != ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED);
    mach_write_to_4(buf + FIL_PAGE_ENCRYPTION_KEY_VERSION,
                    encryption.m_key_version);
  } else {
    mach_write_to_4(buf + FIL_PAGE_ENCRYPTION_KEY_VERSION,
                    ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED);
  }
}

static bool load_key_needed_for_decryption(const IORequest &type,
                                           Encryption &encryption, byte *buf) {
  if (encryption.m_type == Encryption::KEYRING) {
    ulint key_version_read_from_page = ENCRYPTION_KEY_VERSION_INVALID;
    ulint page_type = mach_read_from_2(buf + FIL_PAGE_TYPE);
    if (page_type == FIL_PAGE_COMPRESSED_AND_ENCRYPTED) {
      key_version_read_from_page = mach_read_from_4(buf + FIL_PAGE_DATA + 4);
    } else {
      ut_ad(page_type == FIL_PAGE_ENCRYPTED);
      key_version_read_from_page =
          mach_read_from_4(buf + FIL_PAGE_ENCRYPTION_KEY_VERSION);
    }

    ut_ad(key_version_read_from_page != ENCRYPTION_KEY_VERSION_INVALID);
    ut_ad(key_version_read_from_page != ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED);

    // in rare cases - when (re-)encryption was aborted there can be pages
    // encrypted with different key versions in a given tablespace - retrieve
    // needed key here

    byte *key_read;

    size_t key_len;
    if (Encryption::get_tablespace_key(encryption.m_key_id,
                                       key_version_read_from_page, &key_read,
                                       &key_len) == false) {
      return false;
    }

    // For test
    if (key_version_read_from_page == encryption.m_key_version) {
      ut_ad(memcmp(key_read, encryption.m_key, key_len) == 0);
    }

    // TODO: Allocated or not depends on whether key was taken from cache or
    // keyring
    encryption.set_key(key_read, static_cast<ulint>(key_len), true);
    // encryption.m_key = key_read;
    //******

    encryption.m_key_version = key_version_read_from_page;
  } else {
    ut_ad(encryption.m_type == Encryption::AES);
    if (encryption.m_encryption_rotation == Encryption::NO_ROTATION)
      return true;  // we are all set - needed key was alread loaded into
                    // encryption module

    ut_ad(encryption.m_encryption_rotation ==
          Encryption::MASTER_KEY_TO_KEYRING);
    ut_ad(encryption.m_tablespace_iv != NULL);
    encryption.m_iv = encryption.m_tablespace_iv;  // iv comes from tablespace
                                                   // header for MK encryption
    ut_ad(encryption.m_tablespace_key != NULL);
    encryption.set_key(encryption.m_tablespace_key, ENCRYPTION_KEY_LEN, false);
  }

  return true;
}

/** Decompress after a read and punch a hole in the file if it was a write
@param[in]	type		IO context
@param[in]	fh		Open file handle
@param[in,out]	buf		Buffer to transform
@param[in,out]	scratch		Scratch area for read decompression
@param[in]	src_len		Length of the buffer before compression
@param[in]	offset		file offset from the start where to read
@param[in]	len		Used buffer length for write and output
                                buf len for read
@return DB_SUCCESS or error code */
static dberr_t os_file_io_complete(const IORequest &type, os_file_t fh,
                                   byte *buf, byte *scratch, ulint src_len,
                                   os_offset_t offset, ulint len) {
  dberr_t ret = DB_SUCCESS;

  /* We never compress/decompress the first page */
  ut_a(offset > 0);
  ut_ad(type.validate());

  if (!type.is_compression_enabled()) {
    if (type.is_log() && offset >= LOG_FILE_HDR_SIZE &&
        !type.is_encryption_disabled()) {
      Encryption encryption(type.encryption_algorithm());

      ret = encryption.decrypt_log(type, buf, src_len, scratch, len);
    }

    return (ret);
  } else if (type.is_read()) {
    Encryption encryption(type.encryption_algorithm());

    bool is_page_encrypted = type.is_encryption_disabled()
                                 ? false
                                 : encryption.is_encrypted_page(buf);

    if (is_page_encrypted && encryption.m_type != Encryption::NONE) {
      dberr_t err =
          verify_post_encryption_checksum(type, encryption, buf, src_len);
      if (err != DB_SUCCESS) return err;

      if (!load_key_needed_for_decryption(type, encryption, buf))
        return DB_IO_DECRYPT_FAIL;
    }

    ret = encryption.decrypt(type, buf, src_len, scratch, len);
    if (ret != DB_SUCCESS) return ret;

    ret = os_file_decompress_page(type.is_dblwr_recover(), buf, scratch, len);
    if (ret != DB_SUCCESS) return ret;
    if (Encryption::can_page_be_keyring_encrypted(buf) &&
        !type.is_encryption_disabled())
      assing_key_version(buf, encryption,
                         is_page_encrypted);  // is_page_encrypted meaning page
                                              // was encrypted before calling
                                              // decrypt

  } else if (type.punch_hole()) {
    ut_ad(len <= src_len);
    ut_ad(!type.is_log());
    ut_ad(type.is_write());
    ut_ad(type.is_compressed());

    /* Nothing to do. */
    if (len == src_len) {
      return (DB_SUCCESS);
    }

#ifdef UNIV_DEBUG
    const ulint block_size = type.block_size();
#endif /* UNIV_DEBUG */

    /* We don't support multiple page sizes in the server
    at the moment. */
    ut_ad(src_len == srv_page_size);

    /* Must be a multiple of the compression unit size. */
    ut_ad((len % block_size) == 0);
    ut_ad((offset % block_size) == 0);

    ut_ad(len + block_size <= src_len);

    offset += len;

    return (os_file_punch_hole(fh, offset, src_len - len));
  }

#ifdef UNIV_DEBUG
  if (type.is_write() &&
      type.encryption_algorithm().m_type == Encryption::KEYRING) {
    Encryption encryption(type.encryption_algorithm());
    bool was_page_encrypted = encryption.is_encrypted_page(buf);

    // TODO:Robert czy bez type.is_page_zip_compressed to działa - powinno
    ut_ad(!was_page_encrypted ||  //! type.is_page_zip_compressed() ||
          fil_space_verify_crypt_checksum(
              buf, src_len, type.is_page_zip_compressed(),
              encryption.is_encrypted_and_compressed(buf)));
  }
#endif

  ut_ad(!type.is_log());

  return (DB_SUCCESS);
}

/** Check if the path refers to the root of a drive using a pointer
to the last directory separator that the caller has fixed.
@param[in]	path		path name
@param[in]	last_slash	last directory separator in the path
@return true if this path is a drive root, false if not */
UNIV_INLINE
bool os_file_is_root(const char *path, const char *last_slash) {
  return (
#ifdef _WIN32
      (last_slash == path + 2 && path[1] == ':') ||
#endif /* _WIN32 */
      last_slash == path);
}

/** Return the parent directory component of a null-terminated path.
Return a new buffer containing the string up to, but not including,
the final component of the path.
The path returned will not contain a trailing separator.
Do not return a root path, return NULL instead.
The final component trimmed off may be a filename or a directory name.
If the final component is the only component of the path, return NULL.
It is the caller's responsibility to free the returned string after it
is no longer needed.
@param[in]	path		Path name
@return own: parent directory of the path */
static char *os_file_get_parent_dir(const char *path) {
  bool has_trailing_slash = false;

  /* Find the offset of the last slash */
  const char *last_slash = strrchr(path, OS_PATH_SEPARATOR);

  if (!last_slash) {
    /* No slash in the path, return NULL */
    return (NULL);
  }

  /* Ok, there is a slash. Is there anything after it? */
  if (static_cast<size_t>(last_slash - path + 1) == strlen(path)) {
    has_trailing_slash = true;
  }

  /* Reduce repetative slashes. */
  while (last_slash > path && last_slash[-1] == OS_PATH_SEPARATOR) {
    last_slash--;
  }

  /* Check for the root of a drive. */
  if (os_file_is_root(path, last_slash)) {
    return (NULL);
  }

  /* If a trailing slash prevented the first strrchr() from trimming
  the last component of the path, trim that component now. */
  if (has_trailing_slash) {
    /* Back up to the previous slash. */
    last_slash--;
    while (last_slash > path && last_slash[0] != OS_PATH_SEPARATOR) {
      last_slash--;
    }

    /* Reduce repetative slashes. */
    while (last_slash > path && last_slash[-1] == OS_PATH_SEPARATOR) {
      last_slash--;
    }
  }

  /* Check for the root of a drive. */
  if (os_file_is_root(path, last_slash)) {
    return (NULL);
  }

  /* Non-trivial directory component */

  return (mem_strdupl(path, last_slash - path));
}
#ifdef UNIV_ENABLE_UNIT_TEST_GET_PARENT_DIR

/* Test the function os_file_get_parent_dir. */
void test_os_file_get_parent_dir(const char *child_dir,
                                 const char *expected_dir) {
  char *child = mem_strdup(child_dir);
  char *expected = expected_dir == NULL ? NULL : mem_strdup(expected_dir);

  /* os_file_get_parent_dir() assumes that separators are
  converted to OS_PATH_SEPARATOR. */
  Fil_path::normalize(child);
  Fil_path::normalize(expected);

  char *parent = os_file_get_parent_dir(child);

  bool unexpected =
      (expected == NULL ? (parent != NULL) : (0 != strcmp(parent, expected)));
  if (unexpected) {
    ib::fatal(ER_IB_MSG_752)
        << "os_file_get_parent_dir('" << child << "') returned '" << parent
        << "', instead of '" << expected << "'.";
  }
  ut_free(parent);
  ut_free(child);
  ut_free(expected);
}

/* Test the function os_file_get_parent_dir. */
void unit_test_os_file_get_parent_dir() {
  test_os_file_get_parent_dir("/usr/lib/a", "/usr/lib");
  test_os_file_get_parent_dir("/usr/", NULL);
  test_os_file_get_parent_dir("//usr//", NULL);
  test_os_file_get_parent_dir("usr", NULL);
  test_os_file_get_parent_dir("usr//", NULL);
  test_os_file_get_parent_dir("/", NULL);
  test_os_file_get_parent_dir("//", NULL);
  test_os_file_get_parent_dir(".", NULL);
  test_os_file_get_parent_dir("..", NULL);
#ifdef _WIN32
  test_os_file_get_parent_dir("D:", NULL);
  test_os_file_get_parent_dir("D:/", NULL);
  test_os_file_get_parent_dir("D:\\", NULL);
  test_os_file_get_parent_dir("D:/data", NULL);
  test_os_file_get_parent_dir("D:/data/", NULL);
  test_os_file_get_parent_dir("D:\\data\\", NULL);
  test_os_file_get_parent_dir("D:///data/////", NULL);
  test_os_file_get_parent_dir("D:\\\\\\data\\\\\\\\", NULL);
  test_os_file_get_parent_dir("D:/data//a", "D:/data");
  test_os_file_get_parent_dir("D:\\data\\\\a", "D:\\data");
  test_os_file_get_parent_dir("D:///data//a///b/", "D:///data//a");
  test_os_file_get_parent_dir("D:\\\\\\data\\\\a\\\\\\b\\",
                              "D:\\\\\\data\\\\a");
#endif /* _WIN32 */
}
#endif /* UNIV_ENABLE_UNIT_TEST_GET_PARENT_DIR */

/** Creates all missing subdirectories along the given path.
@param[in]	path		Path name
@return DB_SUCCESS if OK, otherwise error code. */
dberr_t os_file_create_subdirs_if_needed(const char *path) {
  if (srv_read_only_mode) {
    ib::error(ER_IB_MSG_753) << "read only mode set. Can't create "
                             << "subdirectories '" << path << "'";

    return (DB_READ_ONLY);
  }

  char *subdir = os_file_get_parent_dir(path);

  if (subdir == NULL) {
    /* subdir is root or cwd, nothing to do */
    return (DB_SUCCESS);
  }

  /* Test if subdir exists */
  os_file_type_t type;
  bool subdir_exists;
  bool success = os_file_status(subdir, &subdir_exists, &type);

  if (success && !subdir_exists) {
    /* Subdir does not exist, create it */
    dberr_t err = os_file_create_subdirs_if_needed(subdir);

    if (err != DB_SUCCESS) {
      ut_free(subdir);

      return (err);
    }

    success = os_file_create_directory(subdir, false);
  }

  ut_free(subdir);

  return (success ? DB_SUCCESS : DB_ERROR);
}

/** Allocate the buffer for IO on a transparently compressed table.
@param[in]	type		IO flags
@param[out]	buf		buffer to read or write
@param[in,out]	n		number of bytes to read/write, starting from
                                offset
@return pointer to allocated page, compressed data is written to the offset
        that is aligned on the disk sector size */
static Block *os_file_compress_page(IORequest &type, void *&buf, ulint *n) {
  ut_ad(!type.is_log());
  ut_ad(type.is_write());
  ut_ad(type.is_compressed());

  ulint n_alloc = *n * 2;

  ut_a(n_alloc <= UNIV_PAGE_SIZE_MAX * 2);
  ut_a(type.compression_algorithm().m_type != Compression::LZ4 ||
       static_cast<ulint>(LZ4_COMPRESSBOUND(*n)) < n_alloc);

  Block *block = os_alloc_block();

  ulint old_compressed_len;
  ulint compressed_len = *n;

  old_compressed_len = mach_read_from_2(reinterpret_cast<byte *>(buf) +
                                        FIL_PAGE_COMPRESS_SIZE_V1);

  if (old_compressed_len > 0) {
    old_compressed_len =
        ut_calc_align(old_compressed_len + FIL_PAGE_DATA, type.block_size());
  } else {
    old_compressed_len = *n;
  }

  byte *compressed_page;

  compressed_page =
      static_cast<byte *>(ut_align(block->m_ptr, os_io_ptr_align));

  byte *buf_ptr;

  buf_ptr = os_file_compress_page(
      type.compression_algorithm(), type.block_size(),
      reinterpret_cast<byte *>(buf), *n, compressed_page, &compressed_len,
      type.encryption_algorithm().m_type == Encryption::KEYRING &&
          type.encryption_algorithm().m_key != NULL);

  if (buf_ptr != buf) {
    /* Set new compressed size to uncompressed page. */
    memcpy(reinterpret_cast<byte *>(buf) + FIL_PAGE_COMPRESS_SIZE_V1,
           buf_ptr + FIL_PAGE_COMPRESS_SIZE_V1, 2);

    buf = buf_ptr;
    *n = compressed_len;

    if (compressed_len >= old_compressed_len) {
      ut_ad(old_compressed_len <= UNIV_PAGE_SIZE);

      type.clear_punch_hole();
    }
  }

  return (block);
}

/** Encrypt a page content when write it to disk.
@param[in]	type		IO flags
@param[out]	buf		buffer to read or write
@param[in,out]	n		number of bytes to read/write, starting from
                                offset
@return pointer to the encrypted page */
static Block *os_file_encrypt_page(const IORequest &type, void *&buf,
                                   ulint *n) {
  byte *encrypted_page;
  ulint encrypted_len = *n;
  byte *buf_ptr;
  Encryption encryption(type.encryption_algorithm());

  ut_ad(type.is_write());
  ut_ad(type.is_encrypted());

  Block *block = os_alloc_block();

  encrypted_page = static_cast<byte *>(ut_align(block->m_ptr, os_io_ptr_align));

  buf_ptr = encryption.encrypt(type, reinterpret_cast<byte *>(buf), *n,
                               encrypted_page, &encrypted_len);

  bool encrypted = buf_ptr != buf;

  if (encrypted) {
    buf = buf_ptr;
    *n = encrypted_len;
  }

  return (block);
}

/** Encrypt log blocks content when write it to disk.
@param[in]	type		IO flags
@param[in,out]	buf		buffer to read or write
@param[in,out]	scratch		buffer for encrypting log
@param[in,out]	n		number of bytes to read/write, starting from
                                offset
@return pointer to the encrypted log blocks */
static Block *os_file_encrypt_log(const IORequest &type, void *&buf,
                                  byte *&scratch, ulint *n) {
  byte *encrypted_log;
  ulint encrypted_len = *n;
  byte *buf_ptr;
  Encryption encryption(type.encryption_algorithm());
  Block *block = NULL;

  ut_ad(type.is_write());
  ut_ad(type.is_encrypted());
  ut_ad(type.is_log());
  ut_ad(*n % OS_FILE_LOG_BLOCK_SIZE == 0);

  if (*n <= BUFFER_BLOCK_SIZE - os_io_ptr_align) {
    block = os_alloc_block();
    buf_ptr = block->m_ptr;
    scratch = NULL;
  } else {
    buf_ptr = static_cast<byte *>(ut_malloc_nokey(*n + os_io_ptr_align));
    scratch = buf_ptr;
  }

  encrypted_log = static_cast<byte *>(ut_align(buf_ptr, os_io_ptr_align));

  encrypted_log = encryption.encrypt_log(type, reinterpret_cast<byte *>(buf),
                                         *n, encrypted_log, &encrypted_len);

  bool encrypted = encrypted_log != buf;

  if (encrypted) {
    buf = encrypted_log;
    *n = encrypted_len;
  }

  return (block);
}

#ifndef _WIN32

/** Do the read/write
@param[in]	request	The IO context and type
@return the number of bytes read/written or negative value on error */
ssize_t SyncFileIO::execute(const IORequest &request) {
  ssize_t n_bytes;

  if (request.is_read()) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] pread fd:" << m_fh << ", size:" << m_n;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    n_bytes = pread(m_fh, m_buf, m_n, m_offset);
#else
//! to remote_fun :
    n_bytes = remote_client->remote_pread(m_fh, m_buf, m_n, m_offset);
#endif // MULTI_MASTER_ZHANG_REMOTE
  } else {
    ut_ad(request.is_write());
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] pwrite fd:" << m_fh << ", size:" << m_n;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    n_bytes = pwrite(m_fh, m_buf, m_n, m_offset);
#else
//! to remote_fun :
    n_bytes = remote_client->remote_pwrite(m_fh, m_buf, m_n, m_offset);
#endif // MULTI_MASTER_ZHANG_REMOTE
  }

  return (n_bytes);
}

MY_ATTRIBUTE((warn_unused_result))
static std::string os_file_find_path_for_fd(os_file_t fd) {
  char fdname[FN_REFLEN];
  snprintf(fdname, sizeof fdname, "/proc/%d/fd/%d", getpid(), fd);
  char filename[FN_REFLEN];
  const auto err_filename = my_readlink(filename, fdname, MYF(0));
  return std::string((err_filename != -1) ? filename : "");
}

/** Free storage space associated with a section of the file.
@param[in]	fh		Open file handle
@param[in]	off		Starting offset (SEEK_SET)
@param[in]	len		Size of the hole
@return DB_SUCCESS or error code */
static dberr_t os_file_punch_hole_posix(os_file_t fh, os_offset_t off,
                                        os_offset_t len) {
#ifdef HAVE_FALLOC_PUNCH_HOLE_AND_KEEP_SIZE
  const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] fallocate";
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = fallocate(fh, mode, off, len);
#else
//! to remote_fun :
  int ret =
  remote_client->remote_fallocate(fh, mode, off, len);
  EasyLoggerWithTrace("/home/zhangrongrong/LOG_REMOTE_CLIENT", EasyLogger::info).force_flush()
  << " [lib_function] fallocate fd:" << fh << ", ret:" << ret;
#endif // MULTI_MASTER_ZHANG_REMOTE

  if (ret == 0) {
    return (DB_SUCCESS);
  }

  ut_a(ret == -1);

  if (errno == ENOTSUP) {
    return (DB_IO_NO_PUNCH_HOLE);
  }

  const auto fd_path = os_file_find_path_for_fd(fh);
  if (!fd_path.empty()) {
    ib::warn(ER_IB_MSG_754)
        << "fallocate(" << fh << " (" << fd_path
        << "), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, " << off << ", "
        << len << ") returned errno: " << errno;
  } else {
    ib::warn(ER_IB_MSG_754)
        << "fallocate(" << fh
        << ", FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, " << off << ", "
        << len << ") returned errno: " << errno;
  }

  return (DB_IO_ERROR);

#elif defined(UNIV_SOLARIS)

  // Use F_FREESP

#endif /* HAVE_FALLOC_PUNCH_HOLE_AND_KEEP_SIZE */

  return (DB_IO_NO_PUNCH_HOLE);
}

#if defined(LINUX_NATIVE_AIO)

/** Linux native AIO handler */
class LinuxAIOHandler {
 public:
  /**
  @param[in] global_segment	The global segment*/
  LinuxAIOHandler(ulint global_segment) : m_global_segment(global_segment) {
    /* Should never be doing Sync IO here. */
    ut_a(m_global_segment != ULINT_UNDEFINED);

    /* Find the array and the local segment. */

    m_segment = AIO::get_array_and_local_segment(&m_array, m_global_segment);

    m_n_slots = m_array->slots_per_segment();
  }

  /** Destructor */
  ~LinuxAIOHandler() {
    // No op
  }

  /**
  Process a Linux AIO request
  @param[out]	m1		the messages passed with the
  @param[out]	m2		AIO request; note that in case the
                                  AIO operation failed, these output
                                  parameters are valid and can be used to
                                  restart the operation.
  @param[out]	request		IO context
  @return DB_SUCCESS or error code */
  dberr_t poll(fil_node_t **m1, void **m2, IORequest *request);

 private:
  /** Resubmit an IO request that was only partially successful
  @param[in,out]	slot		Request to resubmit
  @return DB_SUCCESS or DB_FAIL if the IO resubmit request failed */
  dberr_t resubmit(Slot *slot);

  /** Check if the AIO succeeded
  @param[in,out]	slot		The slot to check
  @return DB_SUCCESS, DB_FAIL if the operation should be retried or
          DB_IO_ERROR on all other errors */
  dberr_t check_state(Slot *slot);

  /** @return true if a shutdown was detected */
  bool is_shutdown() const {
    return (srv_shutdown_state.load() == SRV_SHUTDOWN_EXIT_THREADS &&
            !buf_flush_page_cleaner_is_active());
  }

  /** If no slot was found then the m_array->m_mutex will be released.
  @param[out]	n_pending	The number of pending IOs
  @return NULL or a slot that has completed IO */
  Slot *find_completed_slot(ulint *n_pending);

  /** This is called from within the IO-thread. If there are no completed
  IO requests in the slot array, the thread calls this function to
  collect more requests from the Linux kernel.
  The IO-thread waits on io_getevents(), which is a blocking call, with
  a timeout value. Unless the system is very heavy loaded, keeping the
  IO-thread very busy, the io-thread will spend most of its time waiting
  in this function.
  The IO-thread also exits in this function. It checks server status at
  each wakeup and that is why we use timed wait in io_getevents(). */
  void collect();

 private:
  /** Slot array */
  AIO *m_array;

  /** Number of slots inthe local segment */
  ulint m_n_slots;

  /** The local segment to check */
  ulint m_segment;

  /** The global segment */
  ulint m_global_segment;
};

/** Resubmit an IO request that was only partially successful
@param[in,out]	slot		Request to resubmit
@return DB_SUCCESS or DB_FAIL if the IO resubmit request failed */
dberr_t LinuxAIOHandler::resubmit(Slot *slot) {
#ifdef UNIV_DEBUG
  /* Bytes already read/written out */
  ulint n_bytes = slot->ptr - slot->buf;

  ut_ad(m_array->is_mutex_owned());

  ut_ad(n_bytes < slot->original_len);
  ut_ad(static_cast<ulint>(slot->n_bytes) < slot->original_len - n_bytes);
  /* Partial read or write scenario */
  ut_ad(slot->len >= static_cast<ulint>(slot->n_bytes));
#endif /* UNIV_DEBUG */

  slot->len -= slot->n_bytes;
  slot->ptr += slot->n_bytes;
  slot->offset += slot->n_bytes;

  /* Resetting the bytes read/written */
  slot->n_bytes = 0;
  slot->io_already_done = false;

  /* make sure that slot->offset fits in off_t */
  ut_ad(sizeof(off_t) >= sizeof(os_offset_t));
  struct iocb *iocb = &slot->control;
  if (slot->type.is_read()) {
    io_prep_pread(iocb, slot->file.m_file, slot->ptr, slot->len, slot->offset);

  } else {
    ut_a(slot->type.is_write());

    io_prep_pwrite(iocb, slot->file.m_file, slot->ptr, slot->len, slot->offset);
  }
  iocb->data = slot;

  /* Resubmit an I/O request */
  int ret = io_submit(m_array->io_ctx(m_segment), 1, &iocb);

  if (ret < -1) {
    errno = -ret;
  }

  return (ret < 0 ? DB_IO_PARTIAL_FAILED : DB_SUCCESS);
}

/** Check if the AIO succeeded
@param[in,out]	slot		The slot to check
@return DB_SUCCESS, DB_FAIL if the operation should be retried or
        DB_IO_ERROR on all other errors */
dberr_t LinuxAIOHandler::check_state(Slot *slot) {
  ut_ad(m_array->is_mutex_owned());

  /* Note that it may be that there is more then one completed
  IO requests. We process them one at a time. We may have a case
  here to improve the performance slightly by dealing with all
  requests in one sweep. */

  srv_set_io_thread_op_info(m_global_segment,
                            "processing completed aio requests");

  ut_ad(slot->io_already_done);

  dberr_t err;

  if (slot->ret == 0) {
    err = AIOHandler::post_io_processing(slot);

  } else {
    errno = -slot->ret;

    /* os_file_handle_error does tell us if we should retry
    this IO. As it stands now, we don't do this retry when
    reaping requests from a different context than
    the dispatcher. This non-retry logic is the same for
    Windows and Linux native AIO.
    We should probably look into this to transparently
    re-submit the IO. */
    os_file_handle_error(slot->name, "Linux aio");

    err = DB_IO_ERROR;
  }

  return (err);
}

/** If no slot was found then the m_array->m_mutex will be released.
@param[out]	n_pending		The number of pending IOs
@return NULL or a slot that has completed IO */
Slot *LinuxAIOHandler::find_completed_slot(ulint *n_pending) {
  ulint offset = m_n_slots * m_segment;

  *n_pending = 0;

  m_array->acquire();

  Slot *slot = m_array->at(offset);

  for (ulint i = 0; i < m_n_slots; ++i, ++slot) {
    if (slot->is_reserved) {
      ++*n_pending;

      if (slot->io_already_done) {
        /* Something for us to work on.
        Note: We don't release the mutex. */
        return (slot);
      }
    }
  }

  m_array->release();

  return (NULL);
}

/** This function is only used in Linux native asynchronous i/o. This is
called from within the io-thread. If there are no completed IO requests
in the slot array, the thread calls this function to collect more
requests from the kernel.
The io-thread waits on io_getevents(), which is a blocking call, with
a timeout value. Unless the system is very heavy loaded, keeping the
io-thread very busy, the io-thread will spend most of its time waiting
in this function.
The io-thread also exits in this function. It checks server status at
each wakeup and that is why we use timed wait in io_getevents(). */
void LinuxAIOHandler::collect() {
  ut_ad(m_n_slots > 0);
  ut_ad(m_array != NULL);
  ut_ad(m_segment < m_array->get_n_segments());

  /* Which io_context we are going to use. */
  io_context *io_ctx = m_array->io_ctx(m_segment);

  /* Starting point of the m_segment we will be working on. */
  ulint start_pos = m_segment * m_n_slots;

  /* End point. */
  ulint end_pos = start_pos + m_n_slots;

  for (;;) {
    struct io_event *events;

    /* Which part of event array we are going to work on. */
    events = m_array->io_events(m_segment * m_n_slots);

    /* Initialize the events. */
    memset(events, 0, sizeof(*events) * m_n_slots);

    /* The timeout value is arbitrary. We probably need
    to experiment with it a little. */
    struct timespec timeout;

    timeout.tv_sec = 0;
    timeout.tv_nsec = OS_AIO_REAP_TIMEOUT;

    int ret;

    ret = io_getevents(io_ctx, 1, m_n_slots, events, &timeout);

    for (int i = 0; i < ret; ++i) {
      struct iocb *iocb;

      iocb = reinterpret_cast<struct iocb *>(events[i].obj);
      ut_a(iocb != NULL);

      Slot *slot = reinterpret_cast<Slot *>(iocb->data);

      /* Some sanity checks. */
      ut_a(slot != NULL);
      ut_a(slot->is_reserved);

      /* We are not scribbling previous segment. */
      ut_a(slot->pos >= start_pos);

      /* We have not overstepped to next segment. */
      ut_a(slot->pos < end_pos);

      /* We never compress/decompress the first page */

      if (slot->offset > 0 && !slot->skip_punch_hole &&
          slot->type.is_compression_enabled() && !slot->type.is_log() &&
          slot->type.is_write() && slot->type.is_compressed() &&
          slot->type.punch_hole()) {
        slot->err = AIOHandler::io_complete(slot);
      } else {
        slot->err = DB_SUCCESS;
      }

      /* Mark this request as completed. The error handling
      will be done in the calling function. */
      m_array->acquire();

      /* events[i].res2 should always be ZERO */
      ut_ad(events[i].res2 == 0);
      slot->io_already_done = true;

      /*Even though events[i].res is an unsigned number in libaio, it is
      used to return a negative value (negated errno value) to indicate
      error and a positive value to indicate number of bytes read or
      written. */

      if (events[i].res > slot->len) {
        /* failure */
        slot->n_bytes = 0;
        slot->ret = events[i].res;
      } else {
        /* success */
        slot->n_bytes = events[i].res;
        slot->ret = 0;
      }
      m_array->release();
    }

    if (srv_shutdown_state.load() == SRV_SHUTDOWN_EXIT_THREADS ||
        !buf_flush_page_cleaner_is_active() || ret > 0) {
      break;
    }

    /* This error handling is for any error in collecting the
    IO requests. The errors, if any, for any particular IO
    request are simply passed on to the calling routine. */

    switch (ret) {
      case -EAGAIN:
        /* Not enough resources! Try again. */

      case -EINTR:
        /* Interrupted! The behaviour in case of an interrupt.
        If we have some completed IOs available then the
        return code will be the number of IOs. We get EINTR
        only if there are no completed IOs and we have been
        interrupted. */

      case 0:
        /* No pending request! Go back and check again. */

        continue;
    }

    /* All other errors should cause a trap for now. */
    ib::fatal(ER_IB_MSG_755)
        << "Unexpected ret_code[" << ret << "] from io_getevents()!";

    break;
  }
}

/** Process a Linux AIO request
@param[out]	m1		the messages passed with the
@param[out]	m2		AIO request; note that in case the
                                AIO operation failed, these output
                                parameters are valid and can be used to
                                restart the operation.
@param[out]	request		IO context
@return DB_SUCCESS or error code */
dberr_t LinuxAIOHandler::poll(fil_node_t **m1, void **m2, IORequest *request) {
  dberr_t err;
  Slot *slot;

  /* Loop until we have found a completed request. */
  for (;;) {
    ulint n_pending;

    slot = find_completed_slot(&n_pending);

    if (slot != NULL) {
      ut_ad(m_array->is_mutex_owned());

      err = check_state(slot);

      /* DB_FAIL is not a hard error, we should retry */
      if (err != DB_FAIL) {
        break;
      }

      /* Partial IO, resubmit request for
      remaining bytes to read/write */
      err = resubmit(slot);

      if (err != DB_SUCCESS) {
        break;
      }

      m_array->release();

    } else if (is_shutdown() && n_pending == 0) {
      /* There is no completed request. If there is
      no pending request at all, and the system is
      being shut down, exit. */

      *m1 = NULL;
      *m2 = NULL;

      return (DB_SUCCESS);

    } else {
      /* Wait for some request. Note that we return
      from wait if we have found a request. */

      srv_set_io_thread_op_info(m_global_segment,
                                "waiting for completed aio requests");

      collect();
    }
  }

  if (err == DB_IO_PARTIAL_FAILED) {
    /* Aborting in case of submit failure */
    ib::fatal(ER_IB_MSG_756) << "Native Linux AIO interface. "
                                "io_submit() call failed when "
                                "resubmitting a partial I/O "
                                "request on the file "
                             << slot->name << ".";
  }

  *m1 = slot->m1;
  *m2 = slot->m2;

  *request = slot->type;

  m_array->release(slot);

  m_array->release();

  return (err);
}

/** This function is only used in Linux native asynchronous i/o.
Waits for an aio operation to complete. This function is used to wait for
the completed requests. The aio array of pending requests is divided
into segments. The thread specifies which segment or slot it wants to wait
for. NOTE: this function will also take care of freeing the aio slot,
therefore no other thread is allowed to do the freeing!

@param[in]	global_segment	segment number in the aio array
                                to wait for; segment 0 is the ibuf
                                i/o thread, segment 1 is log i/o thread,
                                then follow the non-ibuf read threads,
                                and the last are the non-ibuf write
                                threads.
@param[out]	m1		the messages passed with the
@param[out]	m2			AIO request; note that in case the
                                AIO operation failed, these output
                                parameters are valid and can be used to
                                restart the operation.
@param[out]	request		IO context
@return DB_SUCCESS if the IO was successful */
static dberr_t os_aio_linux_handler(ulint global_segment, fil_node_t **m1,
                                    void **m2, IORequest *request) {
  LinuxAIOHandler handler(global_segment);

  dberr_t err = handler.poll(m1, m2, request);

  if (err == DB_IO_NO_PUNCH_HOLE) {
    fil_no_punch_hole(*m1);
    err = DB_SUCCESS;
  }

  return (err);
}
#endif

/** Submit buffered AIO requests on the given segment to the kernel.
(low level function).
@param[in] acquire_mutex specifies whether to lock array mutex */
void AIO::os_aio_dispatch_read_array_submit_low(
    bool acquire_mutex MY_ATTRIBUTE((unused))) {
  if (!srv_use_native_aio) {
    return;
  }
#if defined(LINUX_NATIVE_AIO)
  AIO *array = AIO::s_reads;
  ulint total_submitted = 0;
  if (acquire_mutex) array->acquire();
  /* Submit aio requests buffered on all segments. */
  ut_ad(array->m_pending);
  ut_ad(array->m_count);
  for (ulint i = 0; i < array->m_n_segments; i++) {
    const int count = array->m_count[i];
    int offset = 0;
    while (offset != count) {
      struct iocb **const iocb_array =
          array->m_pending + i * array->m_slots.size() / array->m_n_segments +
          offset;
      const int partial_count = count - offset;
      /* io_submit() returns number of successfully queued
      requests or (-errno).
      It returns 0 only if the number of iocb blocks passed
      is also 0. */
      const int submitted =
          io_submit(array->m_aio_ctx[i], partial_count, iocb_array);

      /* This assertion prevents infinite loop in both
      debug and release modes. */
      ut_a(submitted != 0);

      if (submitted < 0) {
        /* Terminating with fatal error */
        const char *errmsg = strerror(-submitted);
        ib::fatal() << "Trying to sumbit " << count
                    << " aio requests, io_submit() set "
                    << "errno to " << -submitted << ": "
                    << (errmsg ? errmsg : "<unknown>");
      }
      ut_ad(submitted <= partial_count);
      if (submitted < partial_count) {
        ib::warn() << "Trying to sumbit " << count
                   << " aio requests, io_submit() "
                   << "submitted only " << submitted;
      }
      offset += submitted;
    }
    total_submitted += count;
  }
  /* Reset the aio request buffer. */
  memset(array->m_pending, 0x0, sizeof(struct iocb *) * array->m_slots.size());
  memset(array->m_count, 0x0, sizeof(ulint) * array->m_n_segments);
  if (acquire_mutex) array->release();

  srv_stats.n_aio_submitted.add(total_submitted);
#endif
}

/** Submit buffered AIO requests on the given segment to the kernel. */
void os_aio_dispatch_read_array_submit() {
  AIO::os_aio_dispatch_read_array_submit_low(true);
}

#if defined(LINUX_NATIVE_AIO)
/** Dispatch an AIO request to the kernel.
@param[in,out]	slot		an already reserved slot
@param[in]	should_buffer	should buffer the request
rather than submit
@return true on success. */
bool AIO::linux_dispatch(Slot *slot, bool should_buffer) {
  ut_ad(slot);
  ut_a(slot->is_reserved);
  ut_ad(slot->type.validate());

  /* Find out what we are going to work with.
  The iocb struct is directly in the slot.
  The io_context is one per segment. */

  struct iocb *iocb = &slot->control;

  ulint slots_per_segment = m_slots.size() / m_n_segments;
  ulint io_ctx_index = slot->pos / slots_per_segment;

  if (should_buffer) {
    ut_ad(this == s_reads);

    acquire();
    /* There are m_slots.size() elements in m_pending,
    which is divided into m_n_segments area of equal size.
    The iocb of each segment are buffered in its corresponding area
    in the pending array consecutively as they come.
    m_count[i] records the number of buffered aio requests
    in the ith segment.*/
    ut_ad(m_count);
    ulint &count = m_count[io_ctx_index];
    ut_ad(count != slots_per_segment);
    ulint n = io_ctx_index * slots_per_segment + count;
    ut_ad(m_pending);
    m_pending[n] = iocb;
    ++count;
    if (count == slots_per_segment) {
      AIO::os_aio_dispatch_read_array_submit_low(false);
    }
    release();
    return (true);
  }
  /* Submit the given request. */
  int ret = io_submit(m_aio_ctx[io_ctx_index], 1, &iocb);

  /* io_submit() returns number of successfully queued requests
  or -errno. */

  if (ret != 1) {
    errno = -ret;
  }

  return (ret == 1);
}

/** Creates an io_context for native linux AIO.
@param[in]	max_events	number of events
@param[out]	io_ctx		io_ctx to initialize.
@return true on success. */
bool AIO::linux_create_io_ctx(ulint max_events, io_context_t *io_ctx) {
  ssize_t n_retries = 0;

  for (;;) {
    memset(io_ctx, 0x0, sizeof(*io_ctx));

    /* Initialize the io_ctx. Tell it how many pending
    IO requests this context will handle. */

    int ret = io_setup(max_events, io_ctx);

    if (ret == 0) {
      /* Success. Return now. */
      return (true);
    }

    /* If we hit EAGAIN we'll make a few attempts before failing. */

    switch (ret) {
      case -EAGAIN:
        if (n_retries == 0) {
          /* First time around. */
          ib::warn(ER_IB_MSG_757) << "io_setup() failed with EAGAIN."
                                     " Will make "
                                  << OS_AIO_IO_SETUP_RETRY_ATTEMPTS
                                  << " attempts before giving up.";
        }

        if (n_retries < OS_AIO_IO_SETUP_RETRY_ATTEMPTS) {
          ++n_retries;

          ib::warn(ER_IB_MSG_758) << "io_setup() attempt " << n_retries << ".";

          os_thread_sleep(OS_AIO_IO_SETUP_RETRY_SLEEP);

          continue;
        }

        /* Have tried enough. Better call it a day. */
        ib::error(ER_IB_MSG_759)
            << "io_setup() failed with EAGAIN after "
            << OS_AIO_IO_SETUP_RETRY_ATTEMPTS << " attempts.";
        break;

      case -ENOSYS:
        ib::error(ER_IB_MSG_760) << "Linux Native AIO interface"
                                    " is not supported on this platform. Please"
                                    " check your OS documentation and install"
                                    " appropriate binary of InnoDB.";

        break;

      default:
        ib::error(ER_IB_MSG_761) << "Linux Native AIO setup"
                                 << " returned following error[" << ret << "]";
        break;
    }

    ib::info(ER_IB_MSG_762) << "You can disable Linux Native AIO by"
                               " setting innodb_use_native_aio = 0 in my.cnf";

    break;
  }

  return (false);
}

/** Checks if the system supports native linux aio. On some kernel
versions where native aio is supported it won't work on tmpfs. In such
cases we can't use native aio as it is not possible to mix simulated
and native aio.
@return: true if supported, false otherwise. */
bool AIO::is_linux_native_aio_supported() {
  int fd;
  io_context_t io_ctx;
  char name[1000];

  if (!linux_create_io_ctx(1, &io_ctx)) {
    /* The platform does not support native aio. */

    return (false);

  } else if (!srv_read_only_mode) {
    /* Now check if tmpdir supports native aio ops. */
    fd = innobase_mysql_tmpfile(NULL);

    if (fd < 0) {
      ib::warn(ER_IB_MSG_763) << "Unable to create temp file to check"
                                 " native AIO support.";

      return (false);
    }
  } else {
    ulint dirnamelen = strlen(srv_log_group_home_dir);

    ut_a(dirnamelen < (sizeof name) - 10 - sizeof "ib_logfile");

    memcpy(name, srv_log_group_home_dir, dirnamelen);

    /* Add a path separator if needed. */
    if (dirnamelen && name[dirnamelen - 1] != OS_PATH_SEPARATOR) {
      name[dirnamelen++] = OS_PATH_SEPARATOR;
    }

    strcpy(name + dirnamelen, "ib_logfile0");

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:" << name;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    fd = ::open(name, O_RDONLY);
#else
//! to remote_fun :
    fd =
    remote_client->remote_open(name, O_RDONLY);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:" << name << ", fd:" << fd;
#endif // MULTI_MASTER_ZHANG_LOG

    if (fd == -1) {
      ib::warn(ER_IB_MSG_764) << "Unable to open"
                              << " \"" << name << "\" to check native"
                              << " AIO read support.";

      return (false);
    }
  }

  struct io_event io_event;

  memset(&io_event, 0x0, sizeof(io_event));

  byte *buf = static_cast<byte *>(ut_malloc_nokey(UNIV_PAGE_SIZE * 2));
  byte *ptr = static_cast<byte *>(ut_align(buf, UNIV_PAGE_SIZE));

  struct iocb iocb;

  /* Suppress valgrind warning. */
  memset(buf, 0x00, UNIV_PAGE_SIZE * 2);
  memset(&iocb, 0x0, sizeof(iocb));

  struct iocb *p_iocb = &iocb;

  if (!srv_read_only_mode) {
    io_prep_pwrite(p_iocb, fd, ptr, UNIV_PAGE_SIZE, 0);

  } else {
    ut_a(UNIV_PAGE_SIZE >= 512);
    io_prep_pread(p_iocb, fd, ptr, 512, 0);
  }

  int err = io_submit(io_ctx, 1, &p_iocb);

  if (err >= 1) {
    /* Now collect the submitted IO request. */
    err = io_getevents(io_ctx, 1, 1, &io_event, NULL);
  }

  ut_free(buf);
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  close(fd);
#else
//! to remote_fun :
  remote_client->remote_close(fd);
#endif // MULTI_MASTER_ZHANG_REMOTE


  switch (err) {
    case 1:
      return (true);

    case -EINVAL:
    case -ENOSYS:
      ib::error(ER_IB_MSG_765)
          << "Linux Native AIO not supported. You can either"
             " move "
          << (srv_read_only_mode ? name : "tmpdir")
          << " to a file system that supports native"
             " AIO or you can set innodb_use_native_aio to"
             " FALSE to avoid this message.";

      /* fall through. */
    default:
      ib::error(ER_IB_MSG_766) << "Linux Native AIO check on "
                               << (srv_read_only_mode ? name : "tmpdir")
                               << "returned error[" << -err << "]";
  }

  return (false);
}

#endif /* LINUX_NATIVE_AIO */

/** Retrieves the last error number if an error occurs in a file io function.
The number should be retrieved before any other OS calls (because they may
overwrite the error number). If the number is not known to this program,
the OS error number + 100 is returned.
@param[in]	report_all_errors	true if we want an error message
                                        printed of all errors
@param[in]	on_error_silent		true then don't print any diagnostic
                                        to the log
@return error number, or OS error number + 100 */
static ulint os_file_get_last_error_low(bool report_all_errors,
                                        bool on_error_silent) {
  int err = errno;

  if (err == 0) {
    return (0);
  }

  if (report_all_errors ||
      (err != ENOSPC && err != EEXIST && !on_error_silent)) {
    ib::error(ER_IB_MSG_767)
        << "Operating system error number " << err << " in a file operation.";

    if (err == ENOENT) {
      ib::error(ER_IB_MSG_768) << "The error means the system"
                                  " cannot find the path specified.";

#ifndef UNIV_HOTBACKUP
      if (srv_is_being_started) {
        ib::error(ER_IB_MSG_769) << "If you are installing InnoDB,"
                                    " remember that you must create"
                                    " directories yourself, InnoDB"
                                    " does not create them.";
      }
#endif /* !UNIV_HOTBACKUP */
    } else if (err == EACCES) {
      ib::error(ER_IB_MSG_770) << "The error means mysqld does not have"
                                  " the access rights to the directory.";

    } else {
      if (strerror(err) != NULL) {
        ib::error(ER_IB_MSG_771)
            << "Error number " << err << " means '" << strerror(err) << "'";
      }

      ib::info(ER_IB_MSG_772) << OPERATING_SYSTEM_ERROR_MSG;
    }
  }

  switch (err) {
    case ENOSPC:
      return (OS_FILE_DISK_FULL);
    case ENOENT:
      return (OS_FILE_NOT_FOUND);
    case EEXIST:
      return (OS_FILE_ALREADY_EXISTS);
    case EXDEV:
    case ENOTDIR:
    case EISDIR:
      return (OS_FILE_PATH_ERROR);
    case EAGAIN:
      if (srv_use_native_aio) {
        return (OS_FILE_AIO_RESOURCES_RESERVED);
      }
      break;
    case EINTR:
      return (OS_FILE_AIO_INTERRUPTED);
    case EACCES:
      return (OS_FILE_ACCESS_VIOLATION);
    case ENAMETOOLONG:
      return (OS_FILE_NAME_TOO_LONG);
  }
  return (OS_FILE_ERROR_MAX + err);
}

/** Wrapper to fsync(2) that retries the call on some errors.
Returns the value 0 if successful; otherwise the value -1 is returned and
the global variable errno is set to indicate the error.
@param[in]	file		open file handle
@return 0 if success, -1 otherwise */
static int os_file_fsync_posix(os_file_t file) {
  ulint failures = 0;
#ifdef UNIV_HOTBACKUP
  static meb::Mutex meb_mutex;
#endif /* UNIV_HOTBACKUP */

  for (;;) {
#ifdef UNIV_HOTBACKUP
    meb_mutex.lock();
#endif /* UNIV_HOTBACKUP */
    ++os_n_fsyncs;
#ifdef UNIV_HOTBACKUP
    meb_mutex.unlock();
#endif /* UNIV_HOTBACKUP */

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] fsync";
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    int ret = fsync(file);
#else
//! to remote_fun :
    int ret = remote_client->remote_fsync(file);
#endif // MULTI_MASTER_ZHANG_REMOTE

    if (ret == 0) {
      return (ret);
    }

    switch (errno) {
      case ENOLCK:

        ++failures;
        ut_a(failures < 1000);

        if (!(failures % 100)) {
          ib::warn(ER_IB_MSG_773) << "fsync(): "
                                  << "No locks available; retrying";
        }

        /* 0.2 sec */
        os_thread_sleep(200000);
        break;

      case EIO: {
        const auto fd_path = os_file_find_path_for_fd(file);
        if (!fd_path.empty())
          ib::fatal() << "fsync(\"" << fd_path << "\") returned EIO, aborting.";
        else
          ib::fatal() << "fsync() returned EIO, aborting.";
        break;
      }

      case EINTR:

        ++failures;
        ut_a(failures < 2000);
        break;

      default:
        ut_error;
        break;
    }
  }

  ut_error;

  return (-1);
}

/** Check the existence and type of the given file.
@param[in]	path		path name of file
@param[out]	exists		true if the file exists
@param[out]	type		Type of the file, if it exists
@return true if call succeeded */
static bool os_file_status_posix(const char *path, bool *exists,
                                 os_file_type_t *type) {
  struct stat statinfo;

#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = stat(path, &statinfo);
#else
//! to remote_fun :
  int remote_errno;
  int ret = remote_client->remote_stat(path, &statinfo, &remote_errno);
  errno = remote_errno;
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "[lib_function] stat:" << path << ", ret:" << ret <<", call by os_file_get_status_posix().";
#endif // MULTI_MASTER_ZHANG_LOG

  *exists = !ret;

  if (!ret) {
    /* file exists, everything OK */

  } else if (errno == ENOENT || errno == ENOTDIR) {
    if (exists != nullptr) {
      *exists = false;
    }

    /* file does not exist */
    *type = OS_FILE_TYPE_MISSING;
#ifdef MULTI_MASTER_ZHANG_LOG
      EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << path << " not exists";
#endif // MULTI_MASTER_ZHANG_LOG
    return (true);

  } else if (errno == ENAMETOOLONG) {
    *type = OS_FILE_TYPE_NAME_TOO_LONG;
    return (false);
  } else if (errno == EACCES) {
    *type = OS_FILE_PERMISSION_ERROR;
    return (false);
  } else {
    *type = OS_FILE_TYPE_FAILED;

    /* file exists, but stat call failed */
    os_file_handle_error_no_exit(path, "stat", false);
    return (false);
  }

  if (exists != nullptr) {
    *exists = true;
  }

  if (S_ISDIR(statinfo.st_mode)) {
    *type = OS_FILE_TYPE_DIR;

  } else if (S_ISLNK(statinfo.st_mode)) {
    *type = OS_FILE_TYPE_LINK;

  } else if (S_ISREG(statinfo.st_mode)) {
    *type = OS_FILE_TYPE_FILE;

  } else {
    *type = OS_FILE_TYPE_UNKNOWN;
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_flush(), not directly this
function!
Flushes the write buffers of a given file to the disk.
@param[in]	file		handle to a file
@return true if success */
bool os_file_flush_func(os_file_t file) {
  int ret;

  ret = os_file_fsync_posix(file);

  if (ret == 0) {
    return (true);
  }

  /* Since Linux returns EINVAL if the 'file' is actually a raw device,
  we choose to ignore that error if we are using raw disks */

  if (srv_start_raw_disk_in_use && errno == EINVAL) {
    return (true);
  }

  ib::error(ER_IB_MSG_775) << "The OS said file flush did not succeed";

  os_file_handle_error(NULL, "flush");

  /* It is a fatal error if a file flush does not succeed, because then
  the database can get corrupt on disk */
  ut_error;

  return (false);
}

/** NOTE! Use the corresponding macro os_file_create_simple(), not directly
this function!
A simple function to open or create a file.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	access_type	OS_FILE_READ_ONLY or OS_FILE_READ_WRITE
@param[in]	read_only	if true, read only checks are enforced
@param[out]	success		true if succeed, false if error
@return handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
os_file_t os_file_create_simple_func(const char *name, ulint create_mode,
                                     ulint access_type, bool read_only,
                                     bool *success) {
  os_file_t file;

  *success = false;

  int create_flag;

  ut_a(!(create_mode & OS_FILE_ON_ERROR_SILENT));
  ut_a(!(create_mode & OS_FILE_ON_ERROR_NO_EXIT));

  int create_o_sync;
  if (create_mode & OS_FILE_O_SYNC) {
    create_o_sync = O_SYNC;
    create_mode &= ~(static_cast<ulint>(OS_FILE_O_SYNC));
  } else {
    create_o_sync = 0;
  }

  if (create_mode == OS_FILE_OPEN) {
    if (access_type == OS_FILE_READ_ONLY) {
      create_flag = O_RDONLY;

    } else if (read_only) {
      create_flag = O_RDONLY;

    } else {
      create_flag = O_RDWR;
    }

  } else if (read_only) {
    create_flag = O_RDONLY;

  } else if (create_mode == OS_FILE_CREATE) {
    create_flag = O_RDWR | O_CREAT | O_EXCL;

  } else if (create_mode == OS_FILE_CREATE_PATH) {
    /* Create subdirs along the path if needed. */
    dberr_t err;

    err = os_file_create_subdirs_if_needed(name);

    if (err != DB_SUCCESS) {
      *success = false;
      ib::error(ER_IB_MSG_776)
          << "Unable to create subdirectories '" << name << "'";

      return (OS_FILE_CLOSED);
    }

    create_flag = O_RDWR | O_CREAT | O_EXCL;
    create_mode = OS_FILE_CREATE;
  } else {
    ib::error(ER_IB_MSG_777) << "Unknown file create mode (" << create_mode
                             << " for file '" << name << "'";

    return (OS_FILE_CLOSED);
  }

  bool retry;

  do {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create file:" << name;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    file = ::open(name, create_flag | create_o_sync, os_innodb_umask);
#else
//! to remote_fun :
    file =
    remote_client->remote_open((char *)name, create_flag | create_o_sync, os_innodb_umask);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create file:" << name << ", fd:" << file;
#endif // MULTI_MASTER_ZHANG_LOG

    if (file == -1) {
      *success = false;

      retry = os_file_handle_error(
          name, create_mode == OS_FILE_OPEN ? "open" : "create");
    } else {
      *success = true;
      retry = false;
    }

  } while (retry);

#ifdef USE_FILE_LOCK
  if (!read_only && *success && access_type == OS_FILE_READ_WRITE &&
      os_file_lock(file, name)) {
    *success = false;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    close(file);
#else
//! to remote_fun :
    remote_client->remote_close(file);
#endif
    file = -1;
  }
#endif /* USE_FILE_LOCK */

  return (file);
}

/** NOTE! Use the corresponding macro os_file_flush(), not directly this
function!
Truncates a file at the specified position.
@param[in]	file	file to truncate
@param[in]	new_len	new file length
@return true if success */
bool os_file_set_eof_at_func(os_file_t file, ib_uint64_t new_len) {
#ifdef __WIN__
  LARGE_INTEGER li, li2;
  li.QuadPart = new_len;
  return (SetFilePointerEx(file, li, &li2, FILE_BEGIN) && SetEndOfFile(file));
#else
  /* TODO: works only with -D_FILE_OFFSET_BITS=64 ? */
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] ftruncate";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = ftruncate(file, new_len);
#else
//! to remote_fun :
  int ret =
  remote_client->remote_ftruncate(file, new_len);
  EasyLoggerWithTrace("/home/zhangrongrong/LOG_REMOTE_CLIENT", EasyLogger::info).force_flush()
  << " [lib_function] fallocate fd:" << file << ", ret:" << ret;
#endif
  return !ret;
#endif
}

/** This function attempts to create a directory named pathname. The new
directory gets default permissions. On Unix the permissions are
(0770 & ~umask). If the directory exists already, nothing is done and
the call succeeds, unless the fail_if_exists arguments is true.
If another error occurs, such as a permission error, this does not crash,
but reports the error and returns false.
@param[in]	pathname	directory name as null-terminated string
@param[in]	fail_if_exists	if true, pre-existing directory is treated as
                                an error.
@return true if call succeeds, false on error */
bool os_file_create_directory(const char *pathname, bool fail_if_exists) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [create_or_open_path] mkdir : " << pathname;
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] mkdir";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int rcode = mkdir(pathname, 0770);
#else
//! to remote_fun :
  int rcode =
  remote_client->remote_mkdir(pathname, 0770);
#endif

  if (!(rcode == 0 || (errno == EEXIST && !fail_if_exists))) {
    /* failure */
    os_file_handle_error_no_exit(pathname, "mkdir", false);

    return (false);
  }

  return (true);
}

/** This function scans the contents of a directory and invokes the callback
for each entry.
@param[in]	path		directory name as null-terminated string
@param[in]	scan_cbk	use callback to be called for each entry
@param[in]	is_drop		attempt to drop the directory after scan
@return true if call succeeds, false on error */
bool os_file_scan_directory(const char *path, os_dir_cbk_t scan_cbk,
                            bool is_drop) {
  DIR *directory;
  dirent *entry;

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] opendir, by os_file_scan_directory()";
#endif
  directory = opendir(path);

  if (directory == nullptr) {
    os_file_handle_error_no_exit(path, "opendir", false);
    return (false);
  }

  entry = readdir(directory);

  while (entry != nullptr) {
    scan_cbk(path, entry->d_name);
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] readdir, by os_file_scan_directory()";
#endif
    entry = readdir(directory);
  }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] closedir, by os_file_scan_directory()";
#endif
  closedir(directory);

  if (is_drop) {
    int err;

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] rmdir, by os_file_scan_directory()";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    err = rmdir(path);
#else
//! to remote_fun :
    err = remote_client->remote_rmdir(path);
#endif

    if (err != 0) {
      os_file_handle_error_no_exit(path, "rmdir", false);
      return (false);
    }
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_create(), not directly
this function!
Opens an existing file or creates a new.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	purpose		OS_FILE_AIO, if asynchronous, non-buffered I/O
                                is desired, OS_FILE_NORMAL, if any normal file;
                                NOTE that it also depends on type, os_aio_..
                                and srv_.. variables whether we really use async
                                I/O or unbuffered I/O: look in the function
                                source code for the exact rules
@param[in]	type		OS_DATA_FILE or OS_LOG_FILE
@param[in]	read_only	true, if read only checks should be enforcedm
@param[in]	success		true if succeeded
@return handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
pfs_os_file_t os_file_create_func(const char *name, ulint create_mode,
                                  ulint purpose, ulint type, bool read_only,
                                  bool *success) {
  bool on_error_no_exit;
  bool on_error_silent;
  pfs_os_file_t file;

  *success = false;

  DBUG_EXECUTE_IF("ib_create_table_fail_disk_full", *success = false;
                  errno = ENOSPC; file.m_file = OS_FILE_CLOSED; return (file););

  int create_flag;
  const char *mode_str = NULL;

  on_error_no_exit = create_mode & OS_FILE_ON_ERROR_NO_EXIT ? true : false;
  on_error_silent = create_mode & OS_FILE_ON_ERROR_SILENT ? true : false;

  create_mode &= ~OS_FILE_ON_ERROR_NO_EXIT;
  create_mode &= ~OS_FILE_ON_ERROR_SILENT;

  if (create_mode == OS_FILE_OPEN || create_mode == OS_FILE_OPEN_RAW ||
      create_mode == OS_FILE_OPEN_RETRY) {
    mode_str = "OPEN";

    create_flag = read_only ? O_RDONLY : O_RDWR;

  } else if (read_only) {
    mode_str = "OPEN";

    create_flag = O_RDONLY;

  } else if (create_mode == OS_FILE_CREATE) {
    mode_str = "CREATE";
    create_flag = O_RDWR | O_CREAT | O_EXCL;

  } else if (create_mode == OS_FILE_CREATE_PATH) {
    /* Create subdirs along the path if needed. */
    dberr_t err;

    err = os_file_create_subdirs_if_needed(name);

    if (err != DB_SUCCESS) {
      *success = false;
      ib::error(ER_IB_MSG_778)
          << "Unable to create subdirectories '" << name << "'";

      file.m_file = OS_FILE_CLOSED;
      return (file);
    }

    create_flag = O_RDWR | O_CREAT | O_EXCL;
    create_mode = OS_FILE_CREATE;

  } else {
    ib::error(ER_IB_MSG_779)
        << "Unknown file create mode (" << create_mode << ")"
        << " for file '" << name << "'";

    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

  ut_a(type == OS_LOG_FILE || type == OS_DATA_FILE ||
       type == OS_CLONE_DATA_FILE || type == OS_CLONE_LOG_FILE ||
       type == OS_BUFFERED_FILE || type == OS_REDO_LOG_ARCHIVE_FILE);

  ut_a(purpose == OS_FILE_AIO || purpose == OS_FILE_NORMAL);

#ifdef O_SYNC
  /* We let O_SYNC only affect log files; note that we map O_DSYNC to
  O_SYNC because the datasync options seemed to corrupt files in 2001
  in both Linux and Solaris */

  if (!read_only && type == OS_LOG_FILE &&
      srv_unix_file_flush_method == SRV_UNIX_O_DSYNC) {
    create_flag |= O_SYNC;
  }
#endif /* O_SYNC */

  bool retry;

  do {
#ifdef MULTI_MASTER_ZHANG_LOG
  std::string str = (strncmp(mode_str, "CREATE", 6) == 0) ? "create file:" : "open file:";
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << str << name;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    file.m_file = ::open(name, create_flag, os_innodb_umask);
#else
//! to remote_fun :
    file.m_file =
    remote_client->remote_open(name, create_flag, os_innodb_umask);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << str << name << ", fd:" << file.m_file;
#endif // MULTI_MASTER_ZHANG_LOG


    if (file.m_file == -1) {
      const char *operation;

      operation =
          (create_mode == OS_FILE_CREATE && !read_only) ? "create" : "open";

      *success = false;

      if (on_error_no_exit) {
        retry = os_file_handle_error_no_exit(name, operation, on_error_silent);
      } else {
        retry = os_file_handle_error(name, operation);
      }
    } else {
      *success = true;
      retry = false;
    }

  } while (retry);

  /* We disable OS caching (O_DIRECT) only on data files. For clone we
  need to set O_DIRECT even for read_only mode. */

  if ((!read_only || type == OS_CLONE_DATA_FILE) && *success &&
      (type == OS_DATA_FILE || type == OS_CLONE_DATA_FILE) &&
      (srv_unix_file_flush_method == SRV_UNIX_O_DIRECT ||
       srv_unix_file_flush_method == SRV_UNIX_O_DIRECT_NO_FSYNC)) {
    os_file_set_nocache(file.m_file, name, mode_str);
  }

#ifdef USE_FILE_LOCK
  if (!read_only && *success && create_mode != OS_FILE_OPEN_RAW &&
      /* Don't acquire file lock while cloning files. */
      type != OS_CLONE_DATA_FILE && type != OS_CLONE_LOG_FILE &&
      os_file_lock(file.m_file, name)) {
    if (create_mode == OS_FILE_OPEN_RETRY) {
      ib::info(ER_IB_MSG_780) << "Retrying to lock the first data file";

      for (int i = 0; i < 100; i++) {
        os_thread_sleep(1000000);

        if (!os_file_lock(file.m_file, name)) {
          *success = true;
          return (file);
        }
      }

      ib::info(ER_IB_MSG_781) << "Unable to open the first data file";
    }

    *success = false;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    close(file.m_file);
#else
//! to remote_fun :
      remote_client->remote_close(file.m_file);
#endif
    file.m_file = -1;
  }
#endif /* USE_FILE_LOCK */

  return (file);
}

/** NOTE! Use the corresponding macro
os_file_create_simple_no_error_handling(), not directly this function!
A simple function to open or create a file.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	access_type	OS_FILE_READ_ONLY, OS_FILE_READ_WRITE, or
                                OS_FILE_READ_ALLOW_DELETE; the last option
                                is used by a backup program reading the file
@param[in]	read_only	if true read only mode checks are enforced
@param[out]	success		true if succeeded
@return own: handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
pfs_os_file_t os_file_create_simple_no_error_handling_func(const char *name,
                                                           ulint create_mode,
                                                           ulint access_type,
                                                           bool read_only,
                                                           bool *success) {
  pfs_os_file_t file;
  int create_flag;

  ut_a(!(create_mode & OS_FILE_ON_ERROR_SILENT));
  ut_a(!(create_mode & OS_FILE_ON_ERROR_NO_EXIT));

  *success = false;

  if (create_mode == OS_FILE_OPEN) {
    if (access_type == OS_FILE_READ_ONLY) {
      create_flag = O_RDONLY;

    } else if (read_only) {
      create_flag = O_RDONLY;

    } else {
      ut_a(access_type == OS_FILE_READ_WRITE ||
           access_type == OS_FILE_READ_ALLOW_DELETE);

      create_flag = O_RDWR;
    }

  } else if (read_only) {
    create_flag = O_RDONLY;

  } else if (create_mode == OS_FILE_CREATE) {
    create_flag = O_RDWR | O_CREAT | O_EXCL;

  } else {
    ib::error(ER_IB_MSG_782) << "Unknown file create mode " << create_mode
                             << " for file '" << name << "'";
    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:"<< name;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  file.m_file = ::open(name, create_flag, os_innodb_umask);
#else
//! to remote_fun :
  file.m_file =
  remote_client->remote_open(name, create_flag, os_innodb_umask);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "create or open file:"<< name << ", fd:" << file.m_file;
#endif // MULTI_MASTER_ZHANG_LOG

  *success = (file.m_file != -1);

#ifdef USE_FILE_LOCK
  if (!read_only && *success && access_type == OS_FILE_READ_WRITE &&
      os_file_lock(file.m_file, name)) {
    *success = false;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    close(file.m_file);
#else
//! to remote_fun :
    remote_client->remote_close(file.m_file);
#endif
    file.m_file = -1;
  }
#endif /* USE_FILE_LOCK */

  return (file);
}

/** Deletes a file if it exists. The file has to be closed before calling this.
@param[in]	name		file path as a null-terminated string
@param[out]	exist		indicate if file pre-exist
@return true if success */
bool os_file_delete_if_exists_func(const char *name, bool *exist) {
  if (!os_file_can_delete(name)) {
    return (false);
  }

  if (exist != nullptr) {
    *exist = true;
  }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] unlink";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = unlink(name);
#else
//! to remote_fun :
    int ret =
    remote_client->remote_unlink(name);
#endif

  if (ret != 0 && errno == ENOENT) {
    if (exist != nullptr) {
      *exist = false;
    }

  } else if (ret != 0 && errno != ENOENT) {
    os_file_handle_error_no_exit(name, "delete", false);

    return (false);
  }

  return (true);
}

/** Deletes a file. The file has to be closed before calling this.
@param[in]	name		file path as a null-terminated string
@return true if success */
bool os_file_delete_func(const char *name) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] unlink";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = unlink(name);
#else
//! to remote_fun :
    int ret =
    remote_client->remote_unlink(name);
#endif

  if (ret != 0) {
    os_file_handle_error_no_exit(name, "delete", false);

    return (false);
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_rename(), not directly this
function!
Renames a file (can also move it to another directory). It is safest that the
file is closed before calling this function.
@param[in]	oldpath		old file path as a null-terminated string
@param[in]	newpath		new file path
@return true if success */
bool os_file_rename_func(const char *oldpath, const char *newpath) {
#ifdef UNIV_DEBUG
  os_file_type_t type;
  bool exists;

  /* New path must not exist. */
  ut_ad(os_file_status(newpath, &exists, &type));
  ut_ad(!exists);

  /* Old path must exist. */
  ut_ad(os_file_status(oldpath, &exists, &type));
  ut_ad(exists);
#endif /* UNIV_DEBUG */

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] rename " << oldpath << " to " << newpath;
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = rename(oldpath, newpath);
#else
//! to remote_fun :
    int ret =
    remote_client->remote_rename(oldpath, newpath);
#endif

  if (ret != 0) {
    os_file_handle_error_no_exit(oldpath, "rename", false);

    return (false);
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_close(), not directly this
function!
Closes a file handle. In case of error, error number can be retrieved with
os_file_get_last_error.
@param[in]	file		Handle to close
@return true if success */
bool os_file_close_func(os_file_t file) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = close(file);
#else
//! to remote_fun :
  int ret =
  remote_client->remote_close(file);
#endif

  if (ret == -1) {
    os_file_handle_error(NULL, "close");

    return (false);
  }

  return (true);
}

/** Announces an intention to access file data in a specific pattern in the
future.
@param[in, own]	file	handle to a file
@param[in]	offset	file region offset
@param[in]	len	file region length
@param[in]	advice	advice for access pattern
@return true if success */
bool os_file_advise(pfs_os_file_t file, os_offset_t offset, os_offset_t len,
                    ulint advice) {
#ifdef __WIN__
  return (true);
#else
#ifdef UNIV_LINUX
  int native_advice = 0;
  if ((advice & OS_FILE_ADVISE_NORMAL) != 0) native_advice |= POSIX_FADV_NORMAL;
  if ((advice & OS_FILE_ADVISE_RANDOM) != 0) native_advice |= POSIX_FADV_RANDOM;
  if ((advice & OS_FILE_ADVISE_SEQUENTIAL) != 0)
    native_advice |= POSIX_FADV_SEQUENTIAL;
  if ((advice & OS_FILE_ADVISE_WILLNEED) != 0)
    native_advice |= POSIX_FADV_WILLNEED;
  if ((advice & OS_FILE_ADVISE_DONTNEED) != 0)
    native_advice |= POSIX_FADV_DONTNEED;
  if ((advice & OS_FILE_ADVISE_NOREUSE) != 0)
    native_advice |= POSIX_FADV_NOREUSE;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] posix_fadvise";
#endif

  return (posix_fadvise(file.m_file, offset, len, native_advice) == 0);
#else
  return (true);
#endif
#endif /* __WIN__ */
}

/** Gets a file size.
@param[in]	file		handle to an open file
@return file size, or (os_offset_t) -1 on failure */
os_offset_t os_file_get_size(pfs_os_file_t file) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] lseek";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  /* Store current position */
  os_offset_t pos = lseek(file.m_file, 0, SEEK_CUR);
  os_offset_t file_size = lseek(file.m_file, 0, SEEK_END);
  /* Restore current position as the function should not change it */
  lseek(file.m_file, pos, SEEK_SET);
#else
//! to remote_fun :
  /* Store current position */
  os_offset_t pos = remote_client->remote_lseek(file.m_file, 0, SEEK_CUR);
  os_offset_t file_size = remote_client->remote_lseek(file.m_file, 0, SEEK_END);
  /* Restore current position as the function should not change it */
  remote_client->remote_lseek(file.m_file, pos, SEEK_SET);
#endif
  return (file_size);
}

/** Gets a file size.
@param[in]	filename	Full path to the filename to check
@return file size if OK, else set m_total_size to ~0 and m_alloc_size to
        errno */
os_file_size_t os_file_get_size(const char *filename) {
  struct stat s;
  os_file_size_t file_size;

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] stat";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = stat(filename, &s);
#else
//! to remote_fun :
  int remote_errno;
  int ret = remote_client->remote_stat(filename, &s, &remote_errno);
  errno = remote_errno;
#endif

  if (ret == 0) {
    file_size.m_total_size = s.st_size;
    /* st_blocks is in 512 byte sized blocks */
    file_size.m_alloc_size = s.st_blocks * 512;
  } else {
    file_size.m_total_size = ~0;
    file_size.m_alloc_size = (os_offset_t)errno;
  }

  return (file_size);
}

/** Get available free space on disk
@param[in]	path		pathname of a directory or file in disk
@param[out]	free_space	free space available in bytes
@return DB_SUCCESS if all OK */
static dberr_t os_get_free_space_posix(const char *path, uint64_t &free_space) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] stat";
#endif
  struct statvfs stat;
  auto ret = statvfs(path, &stat);

  if (ret && (errno == ENOENT || errno == ENOTDIR)) {
    /* file or directory  does not exist */
    return (DB_NOT_FOUND);

  } else if (ret) {
    /* file exists, but stat call failed */
    os_file_handle_error_no_exit(path, "statvfs", false);
    return (DB_FAIL);
  }

  free_space = stat.f_bsize;
  free_space *= stat.f_bavail;
  return (DB_SUCCESS);
}

/** This function returns information about the specified file
@param[in]	path		pathname of the file
@param[out]	stat_info	information of a file in a directory
@param[in,out]	statinfo	information of a file in a directory
@param[in]	check_rw_perm	for testing whether the file can be opened
                                in RW mode
@param[in]	read_only	if true read only mode checks are enforced
@return DB_SUCCESS if all OK */
static dberr_t os_file_get_status_posix(const char *path,
                                        os_file_stat_t *stat_info,
                                        struct stat *statinfo,
                                        bool check_rw_perm, bool read_only) {
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = stat(path, statinfo);
#else
//! to remote_fun :
  int remote_errno;
  int ret = remote_client->remote_stat(path, statinfo, &remote_errno);
  errno = remote_errno;
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "[lib_function] stat:" << path << ", ret:" << ret << ", call by os_file_get_status_posix().";
#endif // MULTI_MASTER_ZHANG_LOG

  if (ret && (errno == ENOENT || errno == ENOTDIR)) {
    /* file does not exist */

    return (DB_NOT_FOUND);

  } else if (ret) {
    /* file exists, but stat call failed */

    os_file_handle_error_no_exit(path, "stat", false);

    return (DB_FAIL);
  }

  switch (statinfo->st_mode & S_IFMT) {
    case S_IFDIR:
      stat_info->type = OS_FILE_TYPE_DIR;
      break;
    case S_IFLNK:
      stat_info->type = OS_FILE_TYPE_LINK;
      break;
    case S_IFBLK:
      /* Handle block device as regular file. */
    case S_IFCHR:
      /* Handle character device as regular file. */
    case S_IFREG:
      stat_info->type = OS_FILE_TYPE_FILE;
      break;
    default:
      stat_info->type = OS_FILE_TYPE_UNKNOWN;
  }

  stat_info->size = statinfo->st_size;
  stat_info->block_size = statinfo->st_blksize;
  stat_info->alloc_size = statinfo->st_blocks * 512;

  if (check_rw_perm && (stat_info->type == OS_FILE_TYPE_FILE ||
                        stat_info->type == OS_FILE_TYPE_BLOCK)) {
    int access = !read_only ? O_RDWR : O_RDONLY;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "open file:" << path;
#endif // MULTI_MASTER_ZHANG_LOG
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
    int fh = ::open(path, access, os_innodb_umask);
#else
//! to remote_fun :
    int fh =
    remote_client->remote_open(path, access, os_innodb_umask);
#endif // MULTI_MASTER_ZHANG_REMOTE
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << "open file:" << path << ", fd:" << fh;
#endif // MULTI_MASTER_ZHANG_LOG

    if (fh == -1) {
      stat_info->rw_perm = false;
    } else {
      stat_info->rw_perm = true;
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
      close(fh);
#else
//! to remote_fun :
      remote_client->remote_close(fh);
#endif
    }
  }

  return (DB_SUCCESS);
}

/** Truncates a file to a specified size in bytes.
Do nothing if the size to preserve is greater or equal to the current
size of the file.
@param[in]	pathname	file path
@param[in]	file		file to be truncated
@param[in]	size		size to preserve in bytes
@return true if success */
static bool os_file_truncate_posix(const char *pathname, pfs_os_file_t file,
                                   os_offset_t size) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] ftruncate";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int res = ftruncate(file.m_file, size);
#else
//! to remote_fun :
  int res =
  remote_client->remote_ftruncate(file.m_file, size);
  char buf[1024];
  GetPathByFd(file.m_file, buf);
  EasyLoggerWithTrace("/home/zhangrongrong/LOG_REMOTE_CLIENT", EasyLogger::info).force_flush()
  << " [lib_function] fallocate file : " << buf << ", fd : " << file.m_file << ", ret : " << res;
#endif
  if (res == -1) {
    bool retry;

    retry = os_file_handle_error_no_exit(pathname, "truncate", false);

    if (retry) {
      ib::warn(ER_IB_MSG_783) << "Truncate failed for '" << pathname << "'";
    }
  }

  return (res == 0);
}

/** Truncates a file at its current position.
@return true if success */
bool os_file_set_eof(FILE *file) /*!< in: file to be truncated */
{
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] ftruncate";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = ftruncate(fileno(file), ftell(file));
#else
//! to remote_fun :
  int ret = remote_client->remote_ftruncate(fileno(file), ftell(file));
  EasyLoggerWithTrace("/home/zhangrongrong/LOG_REMOTE_CLIENT", EasyLogger::info).force_flush()
  << " [lib_function] fallocate fd:" << fileno(file) << ", ret:" << ret;
#endif
  return !ret;
}

/** Closes a file handle.
@param[in]	file		Handle to a file
@return true if success */
bool os_file_close_no_error_handling_func(os_file_t file) {
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] close";
#endif
#ifndef MULTI_MASTER_ZHANG_REMOTE
//! change :
  int ret = close(file);
#else
//! to remote_fun :
  int ret =
  remote_client->remote_close(file);
#endif
  return (-1 != ret);
}

/** This function can be called if one wants to post a batch of reads and
prefers an i/o-handler thread to handle them all at once later. You must
call os_aio_simulated_wake_handler_threads later to ensure the threads
are not left sleeping! */
void os_aio_simulated_put_read_threads_to_sleep() { /* No op on non Windows */
}

/** Depth first traversal of the directory starting from basedir
@param[in]	basedir		Start scanning from this directory
@param[in]      recursive       True if scan should be recursive
@param[in]	f		Function to call for each entry */
#ifndef MULTI_MASTER_ZHANG_REMOTE
void Dir_Walker::walk_posix(const Path &basedir, bool recursive, Function &&f) {
  using Stack = std::stack<Entry>;

  Stack directories;

  directories.push(Entry(basedir, 0));

  while (!directories.empty()) {
    Entry current = directories.top();

    directories.pop();

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] opendir, by walk_posix().";
#endif
    DIR *parent = opendir(current.m_path.c_str());

    if (parent == nullptr) {
      ib::info(ER_IB_MSG_784) << "Failed to walk directory"
                              << " '" << current.m_path << "'";

      continue;
    }

    if (!is_directory(current.m_path)) {
      f(current.m_path, current.m_depth);
    }

    struct dirent *dirent = nullptr;

    for (;;) {
      dirent = readdir(parent);

      if (dirent == nullptr) {
        break;
      }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] readdir : " << dirent->d_name << ", by walk_posix().";
#endif
      if (strcmp(dirent->d_name, ".") == 0 ||
          strcmp(dirent->d_name, "..") == 0) {
        continue;
      }

      Path path(current.m_path);

      if (path.back() != '/' && path.back() != '\\') {
        path += OS_PATH_SEPARATOR;
      }

      path.append(dirent->d_name);

      if (is_directory(path) && recursive) {
        directories.push(Entry(path, current.m_depth + 1));

      } else {
        f(path, current.m_depth + 1);
      }
    }

#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] closedir : " << current.m_path.c_str() << ", by walk_posix().";
#endif
    closedir(parent);
  }
}
#else
void Dir_Walker::walk_posix(const Path &basedir, bool recursive, Function &&f){
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] opendir, by walk_posix().";
#endif
    std::vector<remote::StructHandle::Entry> entry = remote_client->remote_opendir(basedir, recursive);
    for(auto iter : entry){
#ifdef MULTI_MASTER_ZHANG_LOG
  EasyLoggerWithTrace(log_path, EasyLogger::info).force_flush() << " [lib_function] readdir : " << iter.m_path << ", by walk_posix().";
#endif
        f(iter.m_path, iter.m_depth);
    }
}
#endif

#else /* !_WIN32 */

#include <WinIoCtl.h>

/** Do the read/write
@param[in]	request	The IO context and type
@return the number of bytes read/written or negative value on error */
ssize_t SyncFileIO::execute(const IORequest &request) {
  OVERLAPPED seek;

  memset(&seek, 0x0, sizeof(seek));

  seek.Offset = (DWORD)m_offset & 0xFFFFFFFF;
  seek.OffsetHigh = (DWORD)(m_offset >> 32);

  BOOL ret;
  DWORD n_bytes;

  if (request.is_read()) {
    ret = ReadFile(m_fh, m_buf, static_cast<DWORD>(m_n), &n_bytes, &seek);

  } else {
    ut_ad(request.is_write());
    ret = WriteFile(m_fh, m_buf, static_cast<DWORD>(m_n), &n_bytes, &seek);
  }

  return (ret ? static_cast<ssize_t>(n_bytes) : -1);
}

/** Do the read/write
@param[in,out]	slot	The IO slot, it has the IO context
@return the number of bytes read/written or negative value on error */
ssize_t SyncFileIO::execute(Slot *slot) {
  BOOL ret;

  if (slot->type.is_read()) {
    ret = ReadFile(slot->file.m_file, slot->ptr, slot->len, &slot->n_bytes,
                   &slot->control);
  } else {
    ut_ad(slot->type.is_write());
    ret = WriteFile(slot->file.m_file, slot->ptr, slot->len, &slot->n_bytes,
                    &slot->control);
  }

  return (ret ? static_cast<ssize_t>(slot->n_bytes) : -1);
}

/** Check if the file system supports sparse files.
@param[in]	 name		File name
@return true if the file system supports sparse files */
static bool os_is_sparse_file_supported_win32(const char *filename) {
  char volname[MAX_PATH];
  BOOL result = GetVolumePathName(filename, volname, MAX_PATH);

  if (!result) {
    ib::error(ER_IB_MSG_785)
        << "os_is_sparse_file_supported: "
        << "Failed to get the volume path name for: " << filename
        << "- OS error number " << GetLastError();

    return (false);
  }

  DWORD flags;

  GetVolumeInformation(volname, NULL, MAX_PATH, NULL, NULL, &flags, NULL,
                       MAX_PATH);

  return (flags & FILE_SUPPORTS_SPARSE_FILES) ? true : false;
}

/** Free storage space associated with a section of the file.
@param[in]	fh		Open file handle
@param[in]	page_size	Tablespace page size
@param[in]	block_size	File system block size
@param[in]	off		Starting offset (SEEK_SET)
@param[in]	len		Size of the hole
@return 0 on success or errno */
static dberr_t os_file_punch_hole_win32(os_file_t fh, os_offset_t off,
                                        os_offset_t len) {
  FILE_ZERO_DATA_INFORMATION punch;

  punch.FileOffset.QuadPart = off;
  punch.BeyondFinalZero.QuadPart = off + len;

  /* If lpOverlapped is NULL, lpBytesReturned cannot be NULL,
  therefore we pass a dummy parameter. */
  DWORD temp;

  BOOL result = DeviceIoControl(fh, FSCTL_SET_ZERO_DATA, &punch, sizeof(punch),
                                NULL, 0, &temp, NULL);

  return (!result ? DB_IO_NO_PUNCH_HOLE : DB_SUCCESS);
}

/** Check the existence and type of the given file.
@param[in]	path		path name of file
@param[out]	exists		true if the file exists
@param[out]	type		Type of the file, if it exists
@return true if call succeeded */
static bool os_file_status_win32(const char *path, bool *exists,
                                 os_file_type_t *type) {
  struct _stat64 statinfo;

  int ret = _stat64(path, &statinfo);

  if (ret == 0) {
    /* file exists, everything OK */

  } else if (errno == ENOENT || errno == ENOTDIR) {
    *type = OS_FILE_TYPE_MISSING;

    /* file does not exist */

    if (exists != nullptr) {
      *exists = false;
    }

    return (true);

  } else if (errno == EACCES) {
    *type = OS_FILE_PERMISSION_ERROR;
    return (false);

  } else {
    *type = OS_FILE_TYPE_FAILED;

    /* file exists, but stat call failed */
    os_file_handle_error_no_exit(path, "stat", false);
    return (false);
  }

  if (exists != nullptr) {
    *exists = true;
  }

  if (_S_IFDIR & statinfo.st_mode) {
    *type = OS_FILE_TYPE_DIR;

  } else if (_S_IFREG & statinfo.st_mode) {
    *type = OS_FILE_TYPE_FILE;

  } else {
    *type = OS_FILE_TYPE_UNKNOWN;
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_flush(), not directly this
function!
Flushes the write buffers of a given file to the disk.
@param[in]	file		handle to a file
@return true if success */
bool os_file_flush_func(os_file_t file) {
  ++os_n_fsyncs;

  BOOL ret = FlushFileBuffers(file);

  if (ret) {
    return (true);
  }

  /* Since Windows returns ERROR_INVALID_FUNCTION if the 'file' is
  actually a raw device, we choose to ignore that error if we are using
  raw disks */

  if (srv_start_raw_disk_in_use && GetLastError() == ERROR_INVALID_FUNCTION) {
    return (true);
  }

  os_file_handle_error(NULL, "flush");

  /* It is a fatal error if a file flush does not succeed, because then
  the database can get corrupt on disk */
  ut_error;
}

/** Retrieves the last error number if an error occurs in a file io function.
The number should be retrieved before any other OS calls (because they may
overwrite the error number). If the number is not known to this program,
the OS error number + 100 is returned.
@param[in]	report_all_errors	true if we want an error message printed
                                        of all errors
@param[in]	on_error_silent		true then don't print any diagnostic
                                        to the log
@return error number, or OS error number + 100 */
static ulint os_file_get_last_error_low(bool report_all_errors,
                                        bool on_error_silent) {
  ulint err = (ulint)GetLastError();

  if (err == ERROR_SUCCESS) {
    return (0);
  }

  if (report_all_errors || (!on_error_silent && err != ERROR_DISK_FULL &&
                            err != ERROR_FILE_EXISTS)) {
    ib::error(ER_IB_MSG_786)
        << "Operating system error number " << err << " in a file operation.";

    if (err == ERROR_PATH_NOT_FOUND) {
      ib::error(ER_IB_MSG_787) << "The error means the system cannot find"
                                  " the path specified. It might be too long"
                                  " or it might not exist.";

#ifndef UNIV_HOTBACKUP
      if (srv_is_being_started) {
        ib::error(ER_IB_MSG_788) << "If you are installing InnoDB,"
                                    " remember that you must create"
                                    " directories yourself, InnoDB"
                                    " does not create them.";
      }
#endif /* !UNIV_HOTBACKUP */

    } else if (err == ERROR_ACCESS_DENIED) {
      ib::error(ER_IB_MSG_789) << "The error means mysqld does not have"
                                  " the access rights to"
                                  " the directory. It may also be"
                                  " you have created a subdirectory"
                                  " of the same name as a data file.";

    } else if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
      ib::error(ER_IB_MSG_790) << "The error means that another program"
                                  " is using InnoDB's files."
                                  " This might be a backup or antivirus"
                                  " software or another instance"
                                  " of MySQL."
                                  " Please close it to get rid of this error.";

    } else if (err == ERROR_WORKING_SET_QUOTA ||
               err == ERROR_NO_SYSTEM_RESOURCES) {
      ib::error(ER_IB_MSG_791) << "The error means that there are no"
                                  " sufficient system resources or quota to"
                                  " complete the operation.";

    } else if (err == ERROR_OPERATION_ABORTED) {
      ib::error(ER_IB_MSG_792) << "The error means that the I/O"
                                  " operation has been aborted"
                                  " because of either a thread exit"
                                  " or an application request."
                                  " Retry attempt is made.";
    } else {
      ib::info(ER_IB_MSG_793) << OPERATING_SYSTEM_ERROR_MSG;
    }
  }

  if (err == ERROR_FILE_NOT_FOUND) {
    return (OS_FILE_NOT_FOUND);
  } else if (err == ERROR_PATH_NOT_FOUND) {
    return (OS_FILE_NAME_TOO_LONG);
  } else if (err == ERROR_DISK_FULL) {
    return (OS_FILE_DISK_FULL);
  } else if (err == ERROR_FILE_EXISTS) {
    return (OS_FILE_ALREADY_EXISTS);
  } else if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
    return (OS_FILE_SHARING_VIOLATION);
  } else if (err == ERROR_WORKING_SET_QUOTA ||
             err == ERROR_NO_SYSTEM_RESOURCES) {
    return (OS_FILE_INSUFFICIENT_RESOURCE);
  } else if (err == ERROR_OPERATION_ABORTED) {
    return (OS_FILE_OPERATION_ABORTED);
  } else if (err == ERROR_ACCESS_DENIED) {
    return (OS_FILE_ACCESS_VIOLATION);
  }

  return (OS_FILE_ERROR_MAX + err);
}

/** NOTE! Use the corresponding macro os_file_create_simple(), not directly
this function!
A simple function to open or create a file.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	access_type	OS_FILE_READ_ONLY or OS_FILE_READ_WRITE
@param[in]	read_only	if true read only mode checks are enforced
@param[out]	success		true if succeed, false if error
@return handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
os_file_t os_file_create_simple_func(const char *name, ulint create_mode,
                                     ulint access_type, bool read_only,
                                     bool *success) {
  os_file_t file;

  *success = false;

  DWORD access;
  DWORD create_flag;
  DWORD attributes = 0;
#ifdef UNIV_HOTBACKUP
  DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
#else
  DWORD share_mode = FILE_SHARE_READ;
#endif /* UNIV_HOTBACKUP */

  ut_a(!(create_mode & OS_FILE_ON_ERROR_SILENT));
  ut_a(!(create_mode & OS_FILE_ON_ERROR_NO_EXIT));

  if (create_mode == OS_FILE_OPEN) {
    create_flag = OPEN_EXISTING;

  } else if (read_only) {
    create_flag = OPEN_EXISTING;

  } else if (create_mode == OS_FILE_CREATE) {
    create_flag = CREATE_NEW;

  } else if (create_mode == OS_FILE_CREATE_PATH) {
    /* Create subdirs along the path if needed. */
    dberr_t err;

    err = os_file_create_subdirs_if_needed(name);

    if (err != DB_SUCCESS) {
      *success = false;
      ib::error(ER_IB_MSG_794)
          << "Unable to create subdirectories '" << name << "'";

      return (OS_FILE_CLOSED);
    }

    create_flag = CREATE_NEW;
    create_mode = OS_FILE_CREATE;

  } else {
    ib::error(ER_IB_MSG_795) << "Unknown file create mode (" << create_mode
                             << ") for file '" << name << "'";

    return (OS_FILE_CLOSED);
  }

  if (access_type == OS_FILE_READ_ONLY) {
    access = GENERIC_READ;

  } else if (access_type == OS_FILE_READ_ALLOW_DELETE) {
    ut_ad(read_only);

    access = GENERIC_READ;
    share_mode |= FILE_SHARE_DELETE | FILE_SHARE_WRITE;

  } else if (read_only) {
    ib::info(ER_IB_MSG_796) << "Read only mode set. Unable to"
                               " open file '"
                            << name << "' in RW mode, "
                            << "trying RO mode",
        name;

    access = GENERIC_READ;

  } else if (access_type == OS_FILE_READ_WRITE) {
    access = GENERIC_READ | GENERIC_WRITE;

  } else {
    ib::error(ER_IB_MSG_797) << "Unknown file access type (" << access_type
                             << ") "
                                "for file '"
                             << name << "'";

    return (OS_FILE_CLOSED);
  }

  bool retry;

  do {
    /* Use default security attributes and no template file. */

    file = CreateFile((LPCTSTR)name, access, share_mode, NULL, create_flag,
                      attributes, NULL);

    if (file == INVALID_HANDLE_VALUE) {
      *success = false;

      retry = os_file_handle_error(
          name, create_mode == OS_FILE_OPEN ? "open" : "create");

    } else {
      retry = false;

      *success = true;

      DWORD temp;

      /* This is a best effort use case, if it fails then
      we will find out when we try and punch the hole. */

      DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &temp, NULL);
    }

  } while (retry);

  return (file);
}

/** This function attempts to create a directory named pathname. The new
directory gets default permissions. On Unix the permissions are
(0770 & ~umask). If the directory exists already, nothing is done and
the call succeeds, unless the fail_if_exists arguments is true.
If another error occurs, such as a permission error, this does not crash,
but reports the error and returns false.
@param[in]	pathname	directory name as null-terminated string
@param[in]	fail_if_exists	if true, pre-existing directory is treated
                                as an error.
@return true if call succeeds, false on error */
bool os_file_create_directory(const char *pathname, bool fail_if_exists) {
  BOOL rcode;

  rcode = CreateDirectory((LPCTSTR)pathname, NULL);
  if (!(rcode != 0 ||
        (GetLastError() == ERROR_ALREADY_EXISTS && !fail_if_exists))) {
    os_file_handle_error_no_exit(pathname, "CreateDirectory", false);

    return (false);
  }

  return (true);
}

/** This function scans the contents of a directory and invokes the callback
for each entry.
@param[in]	path		directory name as null-terminated string
@param[in]	scan_cbk	use callback to be called for each entry
@param[in]	is_drop		attempt to drop the directory after scan
@return true if call succeeds, false on error */
bool os_file_scan_directory(const char *path, os_dir_cbk_t scan_cbk,
                            bool is_drop) {
  bool file_found;
  HANDLE find_hdl;
  WIN32_FIND_DATA find_data;
  char wild_card_path[MAX_PATH];

  snprintf(wild_card_path, MAX_PATH, "%s\\*", path);

  find_hdl = FindFirstFile((LPCTSTR)wild_card_path, &find_data);

  if (find_hdl == INVALID_HANDLE_VALUE) {
    os_file_handle_error_no_exit(path, "FindFirstFile", false);
    return (false);
  }

  do {
    scan_cbk(path, find_data.cFileName);
    file_found = FindNextFile(find_hdl, &find_data);

  } while (file_found);

  FindClose(find_hdl);

  if (is_drop) {
    bool ret;

    ret = RemoveDirectory((LPCSTR)path);

    if (!ret) {
      os_file_handle_error_no_exit(path, "RemoveDirectory", false);
      return (false);
    }
  }

  return (true);
}

/** NOTE! Use the corresponding macro os_file_create(), not directly
this function!
Opens an existing file or creates a new.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	purpose		OS_FILE_AIO, if asynchronous, non-buffered I/O
                                is desired, OS_FILE_NORMAL, if any normal file;
                                NOTE that it also depends on type, os_aio_..
                                and srv_.. variables whether we really use async
                                I/O or unbuffered I/O: look in the function
                                source code for the exact rules
@param[in]	type		OS_DATA_FILE or OS_LOG_FILE
@param[in]	success		true if succeeded
@return handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
pfs_os_file_t os_file_create_func(const char *name, ulint create_mode,
                                  ulint purpose, ulint type, bool read_only,
                                  bool *success) {
  pfs_os_file_t file;
  bool retry;
  bool on_error_no_exit;
  bool on_error_silent;

  *success = false;

  DBUG_EXECUTE_IF("ib_create_table_fail_disk_full", *success = false;
                  SetLastError(ERROR_DISK_FULL); file.m_file = OS_FILE_CLOSED;
                  return (file););

  DWORD create_flag;
  DWORD share_mode = FILE_SHARE_READ;

  on_error_no_exit = create_mode & OS_FILE_ON_ERROR_NO_EXIT ? true : false;

  on_error_silent = create_mode & OS_FILE_ON_ERROR_SILENT ? true : false;

  create_mode &= ~OS_FILE_ON_ERROR_NO_EXIT;
  create_mode &= ~OS_FILE_ON_ERROR_SILENT;

  if (create_mode == OS_FILE_OPEN_RAW) {
    ut_a(!read_only);

    create_flag = OPEN_EXISTING;

    /* On Windows Physical devices require admin privileges and
    have to have the write-share mode set. See the remarks
    section for the CreateFile() function documentation in MSDN. */

    share_mode |= FILE_SHARE_WRITE;

  } else if (create_mode == OS_FILE_OPEN || create_mode == OS_FILE_OPEN_RETRY) {
    create_flag = OPEN_EXISTING;

  } else if (read_only) {
    create_flag = OPEN_EXISTING;

  } else if (create_mode == OS_FILE_CREATE) {
    create_flag = CREATE_NEW;

  } else if (create_mode == OS_FILE_CREATE_PATH) {
    /* Create subdirs along the path if needed. */
    dberr_t err;

    err = os_file_create_subdirs_if_needed(name);

    if (err != DB_SUCCESS) {
      *success = false;
      ib::error(ER_IB_MSG_798)
          << "Unable to create subdirectories '" << name << "'";

      file.m_file = OS_FILE_CLOSED;
      return (file);
    }

    create_flag = CREATE_NEW;
    create_mode = OS_FILE_CREATE;

  } else {
    ib::error(ER_IB_MSG_799)
        << "Unknown file create mode (" << create_mode << ") "
        << " for file '" << name << "'";

    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

  DWORD attributes = 0;

#ifdef UNIV_HOTBACKUP
  attributes |= FILE_FLAG_NO_BUFFERING;
#else /* UNIV_HOTBACKUP */
  if (purpose == OS_FILE_AIO) {

#ifdef WIN_ASYNC_IO
    /* If specified, use asynchronous (overlapped) io and no
    buffering of writes in the OS */

    if (srv_use_native_aio) {
      attributes |= FILE_FLAG_OVERLAPPED;
    }
#endif /* WIN_ASYNC_IO */

  } else if (purpose == OS_FILE_NORMAL) {
    /* Use default setting. */

  } else {
    ib::error(ER_IB_MSG_800) << "Unknown purpose flag (" << purpose << ") "
                             << "while opening file '" << name << "'";

    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

#ifdef UNIV_NON_BUFFERED_IO
  // TODO: Create a bug, this looks wrong. The flush log
  // parameter is dynamic.
  if ((type == OS_BUFFERED_FILE) || (type == OS_CLONE_LOG_FILE) ||
      (type == OS_LOG_FILE)) {
    /* Do not use unbuffered i/o for the log files because
    we write really a lot and we have log flusher for fsyncs. */

  } else if (srv_win_file_flush_method == SRV_WIN_IO_UNBUFFERED) {
    attributes |= FILE_FLAG_NO_BUFFERING;
  }
#endif /* UNIV_NON_BUFFERED_IO */

#endif /* UNIV_HOTBACKUP */
  DWORD access = GENERIC_READ;

  if (!read_only) {
    access |= GENERIC_WRITE;
  }

  /* Clone must allow concurrent write to file. */
  if (type == OS_CLONE_LOG_FILE || type == OS_CLONE_DATA_FILE) {
    share_mode |= FILE_SHARE_WRITE;
  }

  do {
    /* Use default security attributes and no template file. */
    file.m_file = CreateFile((LPCTSTR)name, access, share_mode, NULL,
                             create_flag, attributes, NULL);

    if (file.m_file == INVALID_HANDLE_VALUE) {
      const char *operation;

      operation =
          (create_mode == OS_FILE_CREATE && !read_only) ? "create" : "open";

      *success = false;

      if (on_error_no_exit) {
        retry = os_file_handle_error_no_exit(name, operation, on_error_silent);
      } else {
        retry = os_file_handle_error(name, operation);
      }
    } else {
      retry = false;

      *success = true;

      DWORD temp;

      /* This is a best effort use case, if it fails then
      we will find out when we try and punch the hole. */
      DeviceIoControl(file.m_file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &temp,
                      NULL);
    }

  } while (retry);

  return (file);
}

/** NOTE! Use the corresponding macro os_file_create_simple_no_error_handling(),
not directly this function!
A simple function to open or create a file.
@param[in]	name		name of the file or path as a null-terminated
                                string
@param[in]	create_mode	create mode
@param[in]	access_type	OS_FILE_READ_ONLY, OS_FILE_READ_WRITE, or
                                OS_FILE_READ_ALLOW_DELETE; the last option is
                                used by a backup program reading the file
@param[out]	success		true if succeeded
@return own: handle to the file, not defined if error, error number
        can be retrieved with os_file_get_last_error */
pfs_os_file_t os_file_create_simple_no_error_handling_func(const char *name,
                                                           ulint create_mode,
                                                           ulint access_type,
                                                           bool read_only,
                                                           bool *success) {
  pfs_os_file_t file;

  *success = false;

  DWORD access;
  DWORD create_flag;
  DWORD attributes = 0;
  DWORD share_mode = FILE_SHARE_READ;

#ifdef UNIV_HOTBACKUP
  share_mode |= FILE_SHARE_WRITE;
#endif /* UNIV_HOTBACKUP */

  ut_a(name);

  ut_a(!(create_mode & OS_FILE_ON_ERROR_SILENT));
  ut_a(!(create_mode & OS_FILE_ON_ERROR_NO_EXIT));

  if (create_mode == OS_FILE_OPEN) {
    create_flag = OPEN_EXISTING;

  } else if (read_only) {
    create_flag = OPEN_EXISTING;

  } else if (create_mode == OS_FILE_CREATE) {
    create_flag = CREATE_NEW;

  } else {
    ib::error(ER_IB_MSG_801)
        << "Unknown file create mode (" << create_mode << ") "
        << " for file '" << name << "'";

    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

  if (access_type == OS_FILE_READ_ONLY) {
    access = GENERIC_READ;

  } else if (read_only) {
    access = GENERIC_READ;

  } else if (access_type == OS_FILE_READ_WRITE) {
    access = GENERIC_READ | GENERIC_WRITE;

  } else if (access_type == OS_FILE_READ_ALLOW_DELETE) {
    ut_a(!read_only);

    access = GENERIC_READ;

    /* A backup program has to give mysqld the maximum
    freedom to do what it likes with the file */

    share_mode |= FILE_SHARE_DELETE | FILE_SHARE_WRITE;
  } else {
    ib::error(ER_IB_MSG_802)
        << "Unknown file access type (" << access_type << ") "
        << "for file '" << name << "'";

    file.m_file = OS_FILE_CLOSED;
    return (file);
  }

  file.m_file = CreateFile((LPCTSTR)name, access, share_mode,
                           NULL,  // Security attributes
                           create_flag, attributes,
                           NULL);  // No template file

  *success = (file.m_file != INVALID_HANDLE_VALUE);

  return (file);
}

/** Deletes a file if it exists. The file has to be closed before calling this.
@param[in]	name		file path as a null-terminated string
@param[out]	exist		indicate if file pre-exist
@return true if success */
bool os_file_delete_if_exists_func(const char *name, bool *exist) {
  if (!os_file_can_delete(name)) {
    return (false);
  }

  if (exist != nullptr) {
    *exist = true;
  }

  ulint count = 0;

  for (;;) {
    /* In Windows, deleting an .ibd file may fail if mysqlbackup
    is copying it */

    bool ret = DeleteFile((LPCTSTR)name);

    if (ret) {
      return (true);
    }

    DWORD lasterr = GetLastError();

    if (lasterr == ERROR_FILE_NOT_FOUND || lasterr == ERROR_PATH_NOT_FOUND) {
      /* The file does not exist, this not an error */
      if (exist != NULL) {
        *exist = false;
      }

      return (true);
    }

    ++count;

    if (count > 100 && 0 == (count % 10)) {
      /* Print error information */
      os_file_get_last_error(true);

      ib::warn(ER_IB_MSG_803) << "Delete of file '" << name << "' failed.";
    }

    /* Sleep for a second */
    os_thread_sleep(1000000);

    if (count > 2000) {
      return (false);
    }
  }
}

/** Deletes a file. The file has to be closed before calling this.
@param[in]	name		File path as NUL terminated string
@return true if success */
bool os_file_delete_func(const char *name) {
  ulint count = 0;

  for (;;) {
    /* In Windows, deleting an .ibd file may fail if mysqlbackup
    is copying it */

    BOOL ret = DeleteFile((LPCTSTR)name);

    if (ret) {
      return (true);
    }

    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      /* If the file does not exist, we classify this as
      a 'mild' error and return */

      return (false);
    }

    ++count;

    if (count > 100 && 0 == (count % 10)) {
      /* print error information */
      os_file_get_last_error(true);

      ib::warn(ER_IB_MSG_804)
          << "Cannot delete file '" << name << "'. Are you running mysqlbackup"
          << " to back up the file?";
    }

    /* sleep for a second */
    os_thread_sleep(1000000);

    if (count > 2000) {
      return (false);
    }
  }

  ut_error;
  return (false);
}

/** NOTE! Use the corresponding macro os_file_rename(), not directly this
function!
Renames a file (can also move it to another directory). It is safest that the
file is closed before calling this function.
@param[in]	oldpath		old file path as a null-terminated string
@param[in]	newpath		new file path
@return true if success */
bool os_file_rename_func(const char *oldpath, const char *newpath) {
#ifdef UNIV_DEBUG
  os_file_type_t type;
  bool exists;

  /* New path must not exist. */
  ut_ad(os_file_status(newpath, &exists, &type));
  ut_ad(!exists);

  /* Old path must exist. */
  ut_ad(os_file_status(oldpath, &exists, &type));
  ut_ad(exists);
#endif /* UNIV_DEBUG */

  if (MoveFile((LPCTSTR)oldpath, (LPCTSTR)newpath)) {
    return (true);
  }

  os_file_handle_error_no_exit(oldpath, "rename", false);

  return (false);
}

/** NOTE! Use the corresponding macro os_file_close(), not directly
this function!
Closes a file handle. In case of error, error number can be retrieved with
os_file_get_last_error.
@param[in,own]	file		Handle to a file
@return true if success */
bool os_file_close_func(os_file_t file) {
  ut_a(file != INVALID_HANDLE_VALUE);

  if (CloseHandle(file)) {
    return (true);
  }

  os_file_handle_error(NULL, "close");

  return (false);
}

/** Gets a file size.
@param[in]	file		Handle to a file
@return file size, or (os_offset_t) -1 on failure */
os_offset_t os_file_get_size(pfs_os_file_t file) {
  DWORD high;
  DWORD low;

  low = GetFileSize(file.m_file, &high);
  if (low == 0xFFFFFFFF && GetLastError() != NO_ERROR) {
    return ((os_offset_t)-1);
  }

  return (os_offset_t(low | (os_offset_t(high) << 32)));
}

/** Gets a file size.
@param[in]	filename	Full path to the filename to check
@return file size if OK, else set m_total_size to ~0 and m_alloc_size to
        errno */
os_file_size_t os_file_get_size(const char *filename) {
  struct __stat64 s;
  os_file_size_t file_size;

  int ret = _stat64(filename, &s);

  if (ret == 0) {
    file_size.m_total_size = s.st_size;

    DWORD low_size;
    DWORD high_size;

    low_size = GetCompressedFileSize(filename, &high_size);

    if (low_size != INVALID_FILE_SIZE) {
      file_size.m_alloc_size = high_size;
      file_size.m_alloc_size <<= 32;
      file_size.m_alloc_size |= low_size;

    } else {
      ib::error(ER_IB_MSG_805)
          << "GetCompressedFileSize(" << filename << ", ..) failed.";

      file_size.m_alloc_size = (os_offset_t)-1;
    }
  } else {
    file_size.m_total_size = ~0;
    file_size.m_alloc_size = (os_offset_t)ret;
  }

  return (file_size);
}

/** Get available free space on disk
@param[in]	path		pathname of a directory or file in disk
@param[out]	block_size	Block size to use for IO in bytes
@param[out]	free_space	free space available in bytes
@return DB_SUCCESS if all OK */
static dberr_t os_get_free_space_win32(const char *path, uint32_t &block_size,
                                       uint64_t &free_space) {
  char volname[MAX_PATH];
  BOOL result = GetVolumePathName(path, volname, MAX_PATH);

  if (!result) {
    ib::error(ER_IB_MSG_806)
        << "os_file_get_status_win32: "
        << "Failed to get the volume path name for: " << path
        << "- OS error number " << GetLastError();

    return (DB_FAIL);
  }

  DWORD sectorsPerCluster;
  DWORD bytesPerSector;
  DWORD numberOfFreeClusters;
  DWORD totalNumberOfClusters;

  result =
      GetDiskFreeSpace((LPCSTR)volname, &sectorsPerCluster, &bytesPerSector,
                       &numberOfFreeClusters, &totalNumberOfClusters);

  if (!result) {
    ib::error(ER_IB_MSG_807) << "GetDiskFreeSpace(" << volname << ",...) "
                             << "failed "
                             << "- OS error number " << GetLastError();

    return (DB_FAIL);
  }

  block_size = bytesPerSector * sectorsPerCluster;

  free_space = static_cast<uint64_t>(block_size);
  free_space *= numberOfFreeClusters;

  return (DB_SUCCESS);
}

/** This function returns information about the specified file
@param[in]	path		pathname of the file
@param[out]	stat_info	information of a file in a directory
@param[in,out]	statinfo	information of a file in a directory
@param[in]	check_rw_perm	for testing whether the file can be opened
                                in RW mode
@param[in]	read_only	true if the file is opened in read-only mode
@return DB_SUCCESS if all OK */
static dberr_t os_file_get_status_win32(const char *path,
                                        os_file_stat_t *stat_info,
                                        struct _stat64 *statinfo,
                                        bool check_rw_perm, bool read_only) {
  int ret = _stat64(path, statinfo);

  if (ret && (errno == ENOENT || errno == ENOTDIR)) {
    /* file does not exist */

    return (DB_NOT_FOUND);

  } else if (ret) {
    /* file exists, but stat call failed */

    os_file_handle_error_no_exit(path, "stat", false);

    return (DB_FAIL);

  } else if (_S_IFDIR & statinfo->st_mode) {
    stat_info->type = OS_FILE_TYPE_DIR;

  } else if (_S_IFREG & statinfo->st_mode) {
    DWORD access = GENERIC_READ;

    if (!read_only) {
      access |= GENERIC_WRITE;
    }

    stat_info->type = OS_FILE_TYPE_FILE;

    /* Check if we can open it in read-only mode. */

    if (check_rw_perm) {
      HANDLE fh;

      fh = CreateFile((LPCTSTR)path,  // File to open
                      access, FILE_SHARE_READ,
                      NULL,                   // Default security
                      OPEN_EXISTING,          // Existing file only
                      FILE_ATTRIBUTE_NORMAL,  // Normal file
                      NULL);                  // No attr. template

      if (fh == INVALID_HANDLE_VALUE) {
        stat_info->rw_perm = false;
      } else {
        stat_info->rw_perm = true;
        CloseHandle(fh);
      }
    }

    uint64_t free_space;
    auto err = os_get_free_space_win32(path, stat_info->block_size, free_space);

    if (err != DB_SUCCESS) {
      return (err);
    }
    /* On Windows the block size is not used as the allocation
    unit for sparse files. The underlying infra-structure for
    sparse files is based on NTFS compression. The punch hole
    is done on a "compression unit". This compression unit
    is based on the cluster size. You cannot punch a hole if
    the cluster size >= 8K. For smaller sizes the table is
    as follows:

    Cluster Size	Compression Unit
    512 Bytes		 8 KB
      1 KB			16 KB
      2 KB			32 KB
      4 KB			64 KB

    Default NTFS cluster size is 4K, compression unit size of 64K.
    Therefore unless the user has created the file system with
    a smaller cluster size and used larger page sizes there is
    little benefit from compression out of the box. */

    stat_info->block_size = (stat_info->block_size <= 4096)
                                ? stat_info->block_size * 16
                                : UINT32_UNDEFINED;
  } else {
    stat_info->type = OS_FILE_TYPE_UNKNOWN;
  }

  return (DB_SUCCESS);
}

/** Truncates a file to a specified size in bytes.
Do nothing if the size to preserve is greater or equal to the current
size of the file.
@param[in]	pathname	file path
@param[in]	file		file to be truncated
@param[in]	size		size to preserve in bytes
@return true if success */
static bool os_file_truncate_win32(const char *pathname, pfs_os_file_t file,
                                   os_offset_t size) {
  LARGE_INTEGER length;

  length.QuadPart = size;

  BOOL success = SetFilePointerEx(file.m_file, length, NULL, FILE_BEGIN);

  if (!success) {
    os_file_handle_error_no_exit(pathname, "SetFilePointerEx", false);
  } else {
    success = SetEndOfFile(file.m_file);
    if (!success) {
      os_file_handle_error_no_exit(pathname, "SetEndOfFile", false);
    }
  }
  return (success);
}

/** Truncates a file at its current position.
@param[in]	file		Handle to be truncated
@return true if success */
bool os_file_set_eof(FILE *file) {
  HANDLE h = (HANDLE)_get_osfhandle(fileno(file));

  return (SetEndOfFile(h));
}

/** Closes a file handle.
@param[in]	file		Handle to close
@return true if success */
bool os_file_close_no_error_handling_func(os_file_t file) {
  return (CloseHandle(file) ? true : false);
}

/** This function can be called if one wants to post a batch of reads and
prefers an i/o-handler thread to handle them all at once later. You must
call os_aio_simulated_wake_handler_threads later to ensure the threads
are not left sleeping! */
void os_aio_simulated_put_read_threads_to_sleep() {
  AIO::simulated_put_read_threads_to_sleep();
}

/** This function can be called if one wants to post a batch of reads and
prefers an i/o-handler thread to handle them all at once later. You must
call os_aio_simulated_wake_handler_threads later to ensure the threads
are not left sleeping! */
void AIO::simulated_put_read_threads_to_sleep() {
  /* The idea of putting background IO threads to sleep is only for
  Windows when using simulated AIO. Windows XP seems to schedule
  background threads too eagerly to allow for coalescing during
  readahead requests. */

  if (srv_use_native_aio) {
    /* We do not use simulated AIO: do nothing */

    return;
  }

  os_aio_recommend_sleep_for_read_threads = true;

  for (ulint i = 0; i < os_aio_n_segments; i++) {
    AIO *array;

    get_array_and_local_segment(&array, i);

    if (array == s_reads) {
      os_event_reset(os_aio_segment_wait_events[i]);
    }
  }
}

/** Depth first traversal of the directory starting from basedir
@param[in]	basedir		Start scanning from this directory
@param[in]      recursive       true if scan should be recursive
@param[in]	f		Callback for each entry found
@param[in,out]	args		Optional arguments for f */
void Dir_Walker::walk_win32(const Path &basedir, bool recursive, Function &&f) {
  using Stack = std::stack<Entry>;

  HRESULT res;
  size_t length;
  Stack directories;
  TCHAR directory[MAX_PATH];

  res = StringCchLength(basedir.c_str(), MAX_PATH, &length);

  /* Check if the name is too long. */
  if (!SUCCEEDED(res)) {
    ib::warn(ER_IB_MSG_808) << "StringCchLength() call failed!";
    return;

  } else if (length > (MAX_PATH - 3)) {
    ib::warn(ER_IB_MSG_809) << "Directory name too long: '" << basedir << "'";
    return;
  }

  StringCchCopy(directory, MAX_PATH, basedir.c_str());

  if (directory[_tcslen(directory) - 1] != TEXT('\\')) {
    StringCchCat(directory, MAX_PATH, TEXT("\\*"));
  } else {
    StringCchCat(directory, MAX_PATH, TEXT("*"));
  }

  directories.push(Entry(directory, 0));

  using Type = std::codecvt_utf8<wchar_t>;
  using Converter = std::wstring_convert<Type, wchar_t>;

  Converter converter;

  while (!directories.empty()) {
    Entry current = directories.top();

    directories.pop();

    HANDLE h;
    WIN32_FIND_DATA dirent;

    h = FindFirstFile(current.m_path.c_str(), &dirent);

    if (h == INVALID_HANDLE_VALUE) {
      ib::info(ER_IB_MSG_810) << "Directory read failed:"
                              << " '" << current.m_path << "' during scan";

      continue;
    }

    do {
      /* dirent.cFileName is a TCHAR. */
      if (_tcscmp(dirent.cFileName, _T(".")) == 0 ||
          _tcscmp(dirent.cFileName, _T("..")) == 0) {
        continue;
      }

      Path path(current.m_path);

      /* Shorten the path to remove the trailing '*'. */
      ut_ad(path.substr(path.size() - 2).compare("\\*") == 0);

      path.resize(path.size() - 1);
      path.append(dirent.cFileName);

      if ((dirent.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && recursive) {
        path.append("\\*");

        using value_type = Stack::value_type;

        value_type dir(path, current.m_depth + 1);

        directories.push(dir);

      } else {
        f(path, current.m_depth + 1);
      }

    } while (FindNextFile(h, &dirent) != 0);

    if (GetLastError() != ERROR_NO_MORE_FILES) {
      ib::error(ER_IB_MSG_811) << "Scanning '" << directory << "'"
                               << " - FindNextFile(): returned error";
    }

    FindClose(h);
  }
}
#endif /* !_WIN32*/

/** Does a syncronous read or write depending upon the type specified
In case of partial reads/writes the function tries
NUM_RETRIES_ON_PARTIAL_IO times to read/write the complete data.
@param[in]	in_type		IO flags
@param[in]	file		handle to an open file
@param[out]	buf		buffer where to read
@param[in]	offset		file offset from the start where to read
@param[in]	n		number of bytes to read, starting from offset
@param[out]	err		DB_SUCCESS or error code
@return number of bytes read/written, -1 if error */
static MY_ATTRIBUTE((warn_unused_result)) ssize_t
    os_file_io(const IORequest &in_type, os_file_t file, void *buf, ulint n,
               os_offset_t offset, dberr_t *err) {
  Block *block = NULL;
  ulint original_n = n;
  IORequest type = in_type;
  ssize_t bytes_returned = 0;
  byte *encrypt_log_buf = NULL;

  if (type.is_compressed()) {
    /* We don't compress the first page of any file. */
    ut_ad(offset > 0);
    block = os_file_compress_page(type, buf, &n);
  } else {
    block = NULL;
  }

  /* We do encryption after compression, since if we do encryption
  before compression, the encrypted data will cause compression fail
  or low compression rate. */
  if (type.is_encrypted() && type.is_write() &&
      (type.encryption_algorithm().m_type != Encryption::KEYRING ||
       (type.encryption_algorithm().m_key != NULL &&
        Encryption::can_page_be_keyring_encrypted(
            reinterpret_cast<byte *>(buf))))) {
    if (!type.is_log()) {
      /* We don't encrypt the first page of any file. */
      Block *compressed_block = block;
      ut_ad(offset > 0);

      ut_ad(type.encryption_algorithm().m_key != NULL);
      block = os_file_encrypt_page(type, buf, &n);

      if (compressed_block != NULL) {
        os_free_block(compressed_block);
      }
    } else {
      /* Skip encrypt log file header */
      if (offset >= LOG_FILE_HDR_SIZE) {
        block = os_file_encrypt_log(type, buf, encrypt_log_buf, &n);
      }
    }
  }

  SyncFileIO sync_file_io(file, buf, n, offset);

  for (ulint i = 0; i < NUM_RETRIES_ON_PARTIAL_IO; ++i) {
    ssize_t n_bytes = sync_file_io.execute(type);

    /* Check for a hard error. Not much we can do now. */
    if (n_bytes < 0) {
      break;

    } else if ((ulint)n_bytes + bytes_returned == n) {
      bytes_returned += n_bytes;

      if (offset > 0 && (type.is_compressed() || type.is_read())) {
        *err = os_file_io_complete(type, file, reinterpret_cast<byte *>(buf),
                                   NULL, original_n, offset, n);
      } else {
        *err = DB_SUCCESS;
      }

      if (block != NULL) {
        os_free_block(block);
      }

      if (encrypt_log_buf != NULL) {
        ut_free(encrypt_log_buf);
      }

      return (original_n);
    }

    /* Handle partial read/write. */

    ut_ad((ulint)n_bytes + bytes_returned < n);

    bytes_returned += (ulint)n_bytes;

    if (!type.is_partial_io_warning_disabled()) {
      const char *op = type.is_read() ? "read" : "written";

      ib::warn(ER_IB_MSG_812)
          << n << " bytes should have been " << op << ". Only "
          << bytes_returned << " bytes " << op << ". Retrying"
          << " for the remaining bytes.";
    }

    /* Advance the offset and buffer by n_bytes */
    sync_file_io.advance(n_bytes);
  }

  if (block != NULL) {
    os_free_block(block);
  }

  if (encrypt_log_buf != NULL) {
    ut_free(encrypt_log_buf);
  }

  *err = DB_IO_ERROR;

  if (!type.is_partial_io_warning_disabled()) {
    ib::warn(ER_IB_MSG_813)
        << "Retry attempts for " << (type.is_read() ? "reading" : "writing")
        << " partial data failed.";
  }

  return (bytes_returned);
}

/** Does a synchronous write operation in Posix.
@param[in]	type		IO context
@param[in]	file		handle to an open file
@param[out]	buf		buffer from which to write
@param[in]	n		number of bytes to read, starting from offset
@param[in]	offset		file offset from the start where to read
@param[out]	err		DB_SUCCESS or error code
@return number of bytes written, -1 if error */
static MY_ATTRIBUTE((warn_unused_result)) ssize_t
    os_file_pwrite(IORequest &type, os_file_t file, const byte *buf, ulint n,
                   os_offset_t offset, dberr_t *err) {
#ifdef UNIV_HOTBACKUP
  static meb::Mutex meb_mutex;
#endif /* UNIV_HOTBACKUP */

  ut_ad(type.validate());

#ifdef UNIV_HOTBACKUP
  meb_mutex.lock();
#endif /* UNIV_HOTBACKUP */
  ++os_n_fi