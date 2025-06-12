#pragma once

#include <wx/wx.h>
#include <wx/notebook.h>
#include <wx/grid.h>
#include <memory>
#include "ssl_checker.h"
#include <mutex>

// Main frame class
class MainFrame : public wxFrame {
public:
    MainFrame(const wxString& title);
    ~MainFrame();

private:
    // Check results
    CertificateChain m_currentChain;
    bool m_checkSuccess;
    std::mutex m_resultMutex;

    // UI components
    wxTextCtrl* m_hostInput;
    wxTextCtrl* m_portInput;
    wxButton* m_checkButton;
    wxNotebook* m_notebook;
    wxTextCtrl* m_certificateText;
    wxGrid* m_chainGrid;
    wxTextCtrl* m_ocspText;

    // SSL Checker instance
    std::unique_ptr<SSLChecker> m_sslChecker;

    // Event handlers
    void OnCheck(wxCommandEvent& event);
    void OnCheckComplete(wxCommandEvent& event);
    void OnGridCellDoubleClick(wxGridEvent& event);

    // Helper methods
    void DisplayCertificateInfo(const CertificateInfo& certInfo);
    void DisplayCertificateChain(const CertificateChain& chain);
    void DisplayOCSPInfo(const CertificateInfo& certInfo);
    void ClearResults();

    // Thread to perform SSL check
    void PerformCheck(const std::string& host, int port);

    wxDECLARE_EVENT_TABLE();
};

// Custom event for check completion
wxDECLARE_EVENT(CHECK_COMPLETE_EVENT, wxCommandEvent);
