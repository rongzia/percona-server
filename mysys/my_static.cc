/* Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   Without limiting anything contained in the foregoing, this file,
   which is part of C Driver for MySQL (Connector/C), is also subject to the
   Universal FOSS Exception, version 1.0, a copy of which can be found at
   http://oss.oracle.com/licenses/universal-foss-exception.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file mysys/my_static.cc
  Static variables for mysys library. All defined here for easy making of
  a shared library.
*/

#include "mysys/my_static.h"

#include "my_config.h"

#include <stdarg.h>
#include <stddef.h>

#include "my_compiler.h"
#include "my_loglevel.h"
#include "mysql/psi/mysql_cond.h"
#include "mysql/psi/mysql_mutex.h"
#include "mysql/psi/psi_base.h"
#include "mysql/psi/psi_memory.h"
#include "mysql/psi/psi_stage.h"
#include "mysys/mysys_priv.h"  // IWYU pragma: keep

/* get memory in hunks */
constexpr uint ONCE_ALLOC_INIT = 4096 - MALLOC_OVERHEAD;

PSI_memory_key key_memory_charset_file;
PSI_memory_key key_memory_charset_loader;
PSI_memory_key key_memory_lf_node;
PSI_memory_key key_memory_lf_dynarray;
PSI_memory_key key_memory_lf_slist;
PSI_memory_key key_memory_LIST;
PSI_memory_key key_memory_IO_CACHE;
PSI_memory_key key_memory_KEY_CACHE;
PSI_memory_key key_memory_SAFE_HASH_ENTRY;
PSI_memory_key key_memory_MY_BITMAP_bitmap;
PSI_memory_key key_memory_my_compress_alloc;
PSI_memory_key key_memory_my_err_head;
PSI_memory_key key_memory_my_file_info;
PSI_memory_key key_memory_max_alloca;
PSI_memory_key key_memory_MY_DIR;
PSI_memory_key key_memory_MY_TMPDIR_full_list;
PSI_memory_key key_memory_DYNAMIC_STRING;
PSI_memory_key key_memory_TREE;

PSI_thread_key key_thread_timer_notifier;

#ifdef _WIN32
PSI_memory_key key_memory_win_SECURITY_ATTRIBUTES;
PSI_memory_key key_memory_win_PACL;
PSI_memory_key key_memory_win_IP_ADAPTER_ADDRESSES;
#endif /* _WIN32 */

/* from my_init */
char *home_dir = 0;
const char *my_progname = 0;
char curr_dir[FN_REFLEN] = {0}, home_dir_buff[FN_REFLEN] = {0};
ulong my_stream_opened = 0, my_file_opened = 0, my_tmp_file_created = 0;
ulong my_file_total_opened = 0;
int my_umask = 0664, my_umask_dir = 0777;

struct st_my_file_info my_file_info_default[MY_NFILE];
uint my_file_limit = MY_NFILE;
struct st_my_file_info *my_file_info = my_file_info_default;

/* from mf_reccache.c */
ulong my_default_record_cache_size = RECORD_CACHE_SIZE;

/* from my_malloc */
USED_MEM *my_once_root_block = 0;     /* pointer to first block */
uint my_once_extra = ONCE_ALLOC_INIT; /* Memory to alloc / block */

/* from errors.c */
void (*error_handler_hook)(uint error, const char *str,
                           myf MyFlags) = my_message_stderr;
void (*fatal_error_handler_hook)(uint error, const char *str,
                                 myf MyFlags) = my_message_stderr;
void (*local_message_hook)(enum loglevel ll, uint ecode,
                           va_list args) = my_message_local_stderr;

static void enter_cond_dummy(void *a MY_ATTRIBUTE((unused)),
                             mysql_cond_t *b MY_ATTRIBUTE((unused)),
                             mysql_mutex_t *c MY_ATTRIBUTE((unused)),
                             const PSI_stage_info *d MY_ATTRIBUTE((unused)),
                             PSI_stage_info *e MY_ATTRIBUTE((unused)),
                             const char *f MY_ATTRIBUTE((unused)),
                             const char *g MY_ATTRIBUTE((unused)),
                             int h MY_ATTRIBUTE((unused))) {}

static void exit_cond_dummy(void *a MY_ATTRIBUTE((unused)),
                            const PSI_stage_info *b MY_ATTRIBUTE((unused)),
                            const char *c MY_ATTRIBUTE((unused)),
                            const char *d MY_ATTRIBUTE((unused)),
                            int e MY_ATTRIBUTE((unused))) {}

static void enter_stage_dummy(void *a MY_ATTRIBUTE((unused)),
                              const PSI_stage_info *b MY_ATTRIBUTE((unused)),
                              PSI_stage_info *c MY_ATTRIBUTE((unused)),
                              const char *d MY_ATTRIBUTE((unused)),
                              const char *e MY_ATTRIBUTE((unused)),
                              int f MY_ATTRIBUTE((unused))) {}

static void set_waiting_for_disk_space_dummy(void *a MY_ATTRIBUTE((unused)),
                                             bool b MY_ATTRIBUTE((unused))) {}

static int is_killed_dummy(const void *a MY_ATTRIBUTE((unused))) { return 0; }

/*
  Initialize these hooks to dummy implementations. The real server
  implementations will be set during server startup by
  init_server_components().
*/
void (*enter_cond_hook)(void *, mysql_cond_t *, mysql_mutex_t *,
                        const PSI_stage_info *, PSI_stage_info *, const char *,
                        const char *, int) = enter_cond_dummy;

void (*exit_cond_hook)(void *, const PSI_stage_info *, const char *,
                       const char *, int) = exit_cond_dummy;

void (*enter_stage_hook)(void *, const PSI_stage_info *, PSI_stage_info *,
                         const char *, const char *, int) = enter_stage_dummy;

void (*set_waiting_for_disk_space_hook)(void *, bool) =
    set_waiting_for_disk_space_dummy;

int (*is_killed_hook)(const void *) = is_killed_dummy;

#if defined(ENABLED_DEBUG_SYNC)
/**
  Global pointer to be set if callback function is defined
  (e.g. in mysqld). See sql/debug_sync.cc.
*/
void (*debug_sync_C_callback_ptr)(const char *, size_t);
#endif /* defined(ENABLED_DEBUG_SYNC) */

/* How to disable options */
bool my_disable_locking = 0;
bool my_enable_symlinks = false;

//! 每个打开的文件都有一个对应，<local fd, remote fd>, 或者后面直接<remote fd, remote fd>
std::map<int, int> map_fd_mysys;
//! 打开的 fd 对应的 path, <remote fd, path> or
std::map<int, std::string> map_path_mysys;
//! 新建的目录
std::set<std::string> set_dir_mysys;
std::string path_log_mysys = std::string("/home/zhangrongrong/LOG");

remote::RemoteClient *remote_client_mysys = 0;

int GetPathByFd(int fd, char *buf) {
    char path[1024];
    memset(path, 0, 1024);
    snprintf(path, 1024, "/proc/%ld/fd/%d", (long) getpid(), fd);
    int ret = readlink(path, buf, 1024);
    return ret;
}
int path_should_be_local_mysys(const char *path){
  if(std::string(path).find(".ibd") != std::string::npos
  || 0 == strncmp(path, "./sys"
          , strlen("./sys"))
  ) {
//      return 0;
      return -1;
  }
  if(0 == strncmp(path, "/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/build/share"
          , strlen("/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/build/share"))
  || 0 == strncmp(path, "/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/share"
          , strlen("/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/share"))
  || 0 == strncmp(path, "/home/zhangrongrong/mysql/local/mysql80"
          , strlen("/home/zhangrongrong/mysql/local/mysql80"))
//  || 0 == strncmp(path, ""
//          , strlen(""))
//  || 0 == strncmp(path, ""
//          , strlen(""))
//  || 0 == strncmp(path, ""
//          , strlen(""))
//  || 0 == strncmp(path, ""
//          , strlen(""))
//  || 0 == strncmp(path, ""
//          , strlen(""))
//  || 0 == strncmp(path, ""
//          , strlen(""))
  ) {
        return 0;
  } else {
      return 0;
//      return -1;
  }
}

int get_remote_fd_mysys(int fd){
  auto iter = map_fd_mysys.find(fd);
  if(iter != map_fd_mysys.end()){
    return iter->second;
  } else {
    return -1;
  }
}

//std::string get_opened_path_mysys(int fd){
//  int remote_fd = get_remote_fd_mysys(fd);
//  auto iter = map_path_mysys.find(remote_fd);
//  if(iter != map_path_mysys.end()){
//    return iter->second;
//  } else {
//    return "null";
//  }
//}

//int close_opened_fd_and_path_mysys(int remote_fd) {
//      remote_client_mysys->remote_close(remote_fd);
//      auto iter = map_path_mysys.find(remote_fd);
//      if(iter != map_path_mysys.end()){
//          map_path_mysys.erase(remote_fd);
//      } else {
//        #ifdef MULTI_MASTER_ZHANG_LOG
//          EasyLoggerWithTrace(path_log_mysys, EasyLogger::info).force_flush() << "[error] no such file, remote fd:" << remote_fd;
//        #endif // MULTI_MASTER_ZHANG_LOG
//      }
//    return 0;
//}