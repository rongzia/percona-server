#include "include/easylogger.h"
#include <iostream>

// void fun1()
// {
//      EasyLogger("fun","./async_log.txt",EasyLogger::warn) << "fun1 : test log message";
//     EasyLoggerWithTrace("./async_log.txt",EasyLogger::warn) << "FUN1 : test log message";
// }

// void fun2()
// {
//      EasyLogger("fun","./async_log.txt",EasyLogger::warn) << "fun2 : test log message";
//     EasyLoggerWithTrace("./async_log.txt",EasyLogger::warn) << "FUN2 : test log message";

// }



int main(void)
{
    //fun1();
    //fun2();
    // EasyLogger("test_log","./async_log.txt",EasyLogger::error) << "test log message";
    //   EasyLogger("test_log","./async_log.txt",EasyLogger::info) << "test log message";
    //    EasyLogger("test_log","./async_log.txt",EasyLogger::debug) << "test log message";
    //EasyLogger("test_log","./async_log.txt",EasyLogger::warn) << "test log message";
    EasyLoggerWithTrace("./async_log.txt",EasyLogger::warn).force_flush() << "test log message";
    //tmp_loggger.force_flush();
    //EasyLoggerWithTrace("./async_log.txt",EasyLogger::error) << "test log message";
    return 0;
}