#ifndef MYSYS_MY_STATIC_INCLUDED
#define MYSYS_MY_STATIC_INCLUDED

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

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file mysys/my_static.h
  Static variables for mysys library. All defined here for easy making of
  a shared library.
*/

#include <sys/types.h>

#include "my_alloc.h"
#include "my_inttypes.h"
#include "my_io.h"
#include "my_macros.h"
#include "my_sys.h"

extern char curr_dir[FN_REFLEN], home_dir_buff[FN_REFLEN];

extern USED_MEM *my_once_root_block;
extern uint my_once_extra;

extern struct st_my_file_info my_file_info_default[MY_NFILE];

#include <string.h>
#include <map>
#include <set>
#include "multi_macro.h"
#include "easylogger.h"
#include "remote_client.h"
//! 每个打开的文件都有一个对应，<local fd, remote fd>, 或者后面直接<remote fd, remote fd>
    extern std::map<int, int> map_fd_mysys;
//! 打开的 fd 对应的 path, <remote fd, path> or
extern std::map<int, std::string> map_path_mysys;
//! 新建的目录
extern std::set<std::string> set_dir_mysys;
extern std::string path_log_mysys;
extern remote::RemoteClient *remote_client_mysys;

//extern std::map<int, std::string> local_map;
//extern std::map<int, std::string> remote_map;
//extern std::string dir_bulgarian;
//extern std::string file_Index;

extern int GetPathByFd(int fd, char *buf);
extern int path_should_be_local(const char *path);
extern int get_remote_fd_mysys(int fd);
extern int close_opened_fd_and_path_mysys(int fd);
#endif /* MYSYS_MY_STATIC_INCLUDED */
