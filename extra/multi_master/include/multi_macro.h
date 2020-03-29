//
// Created by rrzhang on 2020/1/13.
//

#ifndef MYSQL_MULTI_MACRO_H
#define MYSQL_MULTI_MACRO_H

#include <string>

#define MULTI_MASTER_ZHANG_LOG
#define MULTI_MASTER_ZHANG_LOG_FUN
#define MULTI_MASTER_ZHANG_REMOTE
namespace multi_master {
    static const std::string path_log_server = "/home/zhangrongrong/LOG_REMOTE_SERVER";
    static const std::string path_log_client = "/home/zhangrongrong/LOG_REMOTE_CLIENT";
    static const std::string path_log_mysys = std::string("/home/zhangrongrong/LOG");
    static const std::string path_log = std::string("/home/zhangrongrong/LOG");
    //! remote_fun server 端运行时需要和 client 端 data 目录保持一致
    static const std::string remote_server_run_path = std::string("/home/zhangrongrong/mysql/data");
    //! 下面几个目录需要放在本地
    static const std::string share_build_dir = std::string("/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/build/share");
    static const std::string share_src_dir = std::string("/home/zhangrongrong/CLionProjects/Percona-Share-Storage/percona-server/share");
    static const std::string install_dir = std::string("/home/zhangrongrong/mysql/local/mysql80");
}
#endif //MYSQL_MULTI_MACRO_H
