#ifndef EASY_LOGGER_HEADER
#define EASY_LOGGER_HEADER

#include<iostream>
#include<ostream>
#include<string>
#include<sstream>

#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"

class EasyLogger
{
    public:

    enum LOG_LEVEL
    {
        debug,
        info,
        warn,
        error,
    };

    virtual ~EasyLogger()
    {
        auto s = m_oss.str();
        if(s.length() <= 0) return;
        switch (m_level)
        {
        case LOG_LEVEL::info:
            async_log->info(s);
            break;
        case LOG_LEVEL::debug:
            async_log->debug(s);
            break;
        case LOG_LEVEL::warn:
            async_log->warn(s);
            break;
        case LOG_LEVEL::error:
            async_log->error(s);
            break;
        default:
            break;
        }
        if(free_flush)
        {
            async_log->flush();
        }
    };

    EasyLogger & force_flush()
    {
        free_flush = true;
        return *this;
    }

    template <typename T>
    EasyLogger &operator<<(const T &rhs) {
        m_oss << rhs;
        return (*this);
    }

    // explicit EasyLogger(std::string log_name,std::string log_path,LOG_LEVEL level)
    // {
    //     async_log = spdlog::get(log_name);
    //     if(async_log == NULL)
    //         async_log = spdlog::basic_logger_mt<spdlog::async_factory>(log_name, log_path);
    //     m_level = level;
    // }

    explicit EasyLogger(std::string file_name,int line_num,std::string log_path,LOG_LEVEL level, bool flush_control = false)
    {
        source_location = "";
        source_location += file_name;
        source_location += " : ";
        source_location += std::to_string(line_num);
        async_log = spdlog::get(source_location);
        if(async_log == NULL)
            async_log = spdlog::basic_logger_mt<spdlog::async_factory>(source_location, log_path);
        m_level = level;
        free_flush = flush_control;
    }

    private:
    LOG_LEVEL m_level;
    std::ostringstream m_oss;
    std::shared_ptr<spdlog::logger> async_log;
    std::string source_location;
    bool free_flush;
};

#define EasyLoggerWithTrace(p,l)             \
        EasyLogger(__FILE__, __LINE__,p,l)

#define EasyLoggerWithTrace_FLUSH(p,l)             \
        EasyLogger(__FILE__, __LINE__,p,l,true)


#endif // !EASY_LOGGER_HEADER