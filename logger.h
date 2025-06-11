#pragma once

#include <string>
#include <fstream>

// 全局日志文件声明
extern std::ofstream g_logFile;

// 日志记录函数
void LogMessage(const std::string& message);

// 初始化日志系统
bool InitializeLogger(const std::string& logFilePath);

// 关闭日志系统
void ShutdownLogger();
