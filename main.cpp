#include "main_frame.h"
#include "logger.h"

// Main application class
class SSLCheckerApp : public wxApp {
public:
    virtual bool OnInit() override {
        if (!wxApp::OnInit())
            return false;
#ifdef __ZAPDEBUG__
        // 初始化日志系统
        if (!InitializeLogger("zapssl.log")) {
            // 日志初始化失败，但应用程序可以继续运行
        }
#endif
        MainFrame* frame = new MainFrame("ZapSSL - SSL Certificate Checker");
        frame->Show(true);
        
        return true;
    }
    
    virtual int OnExit() override {
        // 关闭日志系统
#ifdef __ZAPDEBUG__
        ShutdownLogger();
#endif
        return wxApp::OnExit();
    }
};

wxIMPLEMENT_APP(SSLCheckerApp);