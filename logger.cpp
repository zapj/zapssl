#include "logger.h"
#include <ctime>
#include <wx/msgdlg.h>

// 全局日志文件
std::ofstream g_logFile;

// 日志记录函数
void LogMessage(const std::string& message) {
    if (g_logFile.is_open()) {
        // 获取当前时间
        time_t now = time(nullptr);
        struct tm timeinfo;
        char timestamp[80];

#ifdef _WIN32
        localtime_s(&timeinfo, &now);
#else
        localtime_r(&now, &timeinfo);
#endif

        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

        // 写入日志
        g_logFile << "[" << timestamp << "] " << message << std::endl;
        g_logFile.flush(); // 确保立即写入文件
    }
}

// 初始化日志系统
bool InitializeLogger(const std::string& logFilePath) {
    // 打开日志文件
    g_logFile.open(logFilePath, std::ios::out | std::ios::app);
    if (!g_logFile.is_open()) {
        wxMessageBox("无法创建日志文件", "错误", wxICON_ERROR);
        return false;
    }

    LogMessage("=== ZapSSL Application Started ===");
    return true;
}

// 关闭日志系统
void ShutdownLogger() {
    if (g_logFile.is_open()) {
        LogMessage("=== ZapSSL Application Shutdown ===");
        g_logFile.close();
    }
}
