#include "main_frame.h"
#include "logger.h"
#include <wx/statline.h>
#include <thread>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef __WXMSW__
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#pragma comment(lib, "cryptui.lib")
#endif

// Define the custom event
wxDEFINE_EVENT(CHECK_COMPLETE_EVENT, wxCommandEvent);

// Event table
wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_BUTTON(wxID_ANY, MainFrame::OnCheck)
    EVT_TEXT_ENTER(wxID_ANY, MainFrame::OnCheck)
    EVT_COMMAND(wxID_ANY, CHECK_COMPLETE_EVENT, MainFrame::OnCheckComplete)
    // Grid 事件通过 Bind 方法绑定，不在事件表中使用
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600)),
      m_sslChecker(std::make_unique<SSLChecker>()) {

    LogMessage("MainFrame: Constructor called");

    // Create main panel
    wxPanel* panel = new wxPanel(this);

    // Create input controls
    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);

    inputSizer->Add(new wxStaticText(panel, wxID_ANY, "Host:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_hostInput = new wxTextCtrl(panel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    inputSizer->Add(m_hostInput, 1, wxRIGHT, 10);

    inputSizer->Add(new wxStaticText(panel, wxID_ANY, "Port:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_portInput = new wxTextCtrl(panel, wxID_ANY, "443", wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    inputSizer->Add(m_portInput, 0, wxRIGHT, 10);

    m_checkButton = new wxButton(panel, wxID_ANY, "Check Certificate");
    inputSizer->Add(m_checkButton, 0);

    // Create notebook for results
    m_notebook = new wxNotebook(panel, wxID_ANY);

    // Certificate info page
    wxPanel* certPanel = new wxPanel(m_notebook);
    wxBoxSizer* certSizer = new wxBoxSizer(wxVERTICAL);
    m_certificateText = new wxTextCtrl(certPanel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                                     wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    certSizer->Add(m_certificateText, 1, wxEXPAND | wxALL, 5);
    certPanel->SetSizer(certSizer);

    // Certificate chain page
    wxPanel* chainPanel = new wxPanel(m_notebook);
    wxBoxSizer* chainSizer = new wxBoxSizer(wxVERTICAL);
    m_chainGrid = new wxGrid(chainPanel, wxID_ANY);
    m_chainGrid->CreateGrid(0, 4);
    m_chainGrid->SetColLabelValue(0, "Position");
    m_chainGrid->SetColLabelValue(1, "Subject");
    m_chainGrid->SetColLabelValue(2, "Issuer");
    m_chainGrid->SetColLabelValue(3, "Valid Until");
    
    // 设置Grid为只读
    m_chainGrid->EnableEditing(false);
    
    // 绑定双击事件
    m_chainGrid->Bind(wxEVT_GRID_CELL_LEFT_DCLICK, &MainFrame::OnGridCellDoubleClick, this);
    
    m_chainGrid->AutoSizeColumns();
    chainSizer->Add(m_chainGrid, 1, wxEXPAND | wxALL, 5);
    chainPanel->SetSizer(chainSizer);

    // OCSP info page
    wxPanel* ocspPanel = new wxPanel(m_notebook);
    wxBoxSizer* ocspSizer = new wxBoxSizer(wxVERTICAL);
    m_ocspText = new wxTextCtrl(ocspPanel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                               wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    ocspSizer->Add(m_ocspText, 1, wxEXPAND | wxALL, 5);
    ocspPanel->SetSizer(ocspSizer);

    // Add SSL Trace page
    wxPanel* tracePanel = new wxPanel(m_notebook);
    wxBoxSizer* traceSizer = new wxBoxSizer(wxVERTICAL);
    m_traceText = new wxTextCtrl(tracePanel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                                wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    traceSizer->Add(m_traceText, 1, wxEXPAND | wxALL, 5);
    tracePanel->SetSizer(traceSizer);

    // Add About page
    wxPanel* aboutPanel = new wxPanel(m_notebook);
    wxBoxSizer* aboutSizer = new wxBoxSizer(wxVERTICAL);
    m_aboutText = new wxTextCtrl(aboutPanel, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
                                wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    
    // Get OpenSSL version info
    wxString aboutInfo;
    aboutInfo << "ZapSSL - SSL Certificate Checker\n";
    aboutInfo << "Version 1.0.1\n\n";
    aboutInfo << "Website https://zap.dev/projects/zapssl\n\n";
    aboutInfo << "OpenSSL Version Information:\n";
    aboutInfo << "OpenSSL Version: " << wxString::FromUTF8(OpenSSL_version(OPENSSL_VERSION)) << "\n";
    aboutInfo << "OpenSSL Built On: " << wxString::FromUTF8(OpenSSL_version(OPENSSL_BUILT_ON)) << "\n\n";
    aboutInfo << "Copyright 2023 Zap.Dev. All rights reserved.";
    
    m_aboutText->SetValue(aboutInfo);
    aboutSizer->Add(m_aboutText, 1, wxEXPAND | wxALL, 5);
    aboutPanel->SetSizer(aboutSizer);
    
    // Add pages to notebook
    m_notebook->AddPage(certPanel, "Certificate Details");
    m_notebook->AddPage(chainPanel, "Certificate Chain");
    m_notebook->AddPage(ocspPanel, "OCSP Status");
    m_notebook->AddPage(tracePanel, "SSL Trace");
    m_notebook->AddPage(aboutPanel, "About");

    // Main layout
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    mainSizer->Add(inputSizer, 0, wxEXPAND | wxALL, 10);
    mainSizer->Add(new wxStaticLine(panel, wxID_ANY), 0, wxEXPAND | wxLEFT | wxRIGHT, 10);
    mainSizer->Add(m_notebook, 1, wxEXPAND | wxALL, 10);

    panel->SetSizer(mainSizer);

    // Set status bar
    CreateStatusBar();
    SetStatusText("Ready");
}

void MainFrame::OnCheck(wxCommandEvent& event) {
    // Get host and port
    wxString hostStr = m_hostInput->GetValue();
    wxString portStr = m_portInput->GetValue();

    if (hostStr.IsEmpty()) {
        wxMessageBox("Please enter a hostname or IP address", "Input Error", wxICON_ERROR);
        return;
    }

    long port;
    if (!portStr.ToLong(&port) || port <= 0 || port > 65535) {
        wxMessageBox("Please enter a valid port number (1-65535)", "Input Error", wxICON_ERROR);
        return;
    }

    // Clear previous results
    ClearResults();

    // Update status
    SetStatusText("Checking certificate...");
    m_checkButton->Disable();

    // Start check in a separate thread
    PerformCheck(hostStr.ToStdString(), static_cast<int>(port));
}

void MainFrame::PerformCheck(const std::string& host, int port) {
    LogMessage("MainFrame: Starting certificate check for " + host + ":" + std::to_string(port));
    
    auto worker = [this, host, port]() {
        try {
            LogMessage("MainFrame: Worker thread started for " + host + ":" + std::to_string(port));
            
            CertificateChain chain;
            LogMessage("MainFrame: Calling SSLChecker::checkCertificate...");
            bool success = m_sslChecker->checkCertificate(host, port, chain);
            LogMessage("MainFrame: SSLChecker::checkCertificate returned " + std::string(success ? "success" : "failure"));
            
            {
                LogMessage("MainFrame: Updating result data...");
                std::lock_guard<std::mutex> lock(m_resultMutex);
                m_currentChain = chain;
                m_checkSuccess = success;
            }
            
            // Send event to main thread
            LogMessage("MainFrame: Sending CHECK_COMPLETE_EVENT with success status...");
            wxCommandEvent* event = new wxCommandEvent(CHECK_COMPLETE_EVENT);
            event->SetInt(0); // 0 means no error
            wxQueueEvent(this, event);
        }
        catch (const std::exception& e) {
            // Send error event with the error message
            wxCommandEvent* errorEvent = new wxCommandEvent(CHECK_COMPLETE_EVENT);
            errorEvent->SetInt(1); // 1 means error
            errorEvent->SetString(e.what());
            wxQueueEvent(this, errorEvent);
        }
    };
    
    LogMessage("MainFrame: Starting worker thread...");
    std::thread(worker).detach();
    LogMessage("MainFrame: Worker thread started and detached");
}

void MainFrame::OnCheckComplete(wxCommandEvent& event) {
    LogMessage("MainFrame: OnCheckComplete event received");
    
    if (event.GetInt() == 1) {
        // Handle error
        LogMessage("MainFrame: Error flag set in event, error message: " + event.GetString().ToStdString());
        wxMessageBox(event.GetString(), "Error", wxOK | wxICON_ERROR);
        SetStatusText("Certificate check failed");
        m_checkButton->Enable();
        return;
    }

    LogMessage("MainFrame: Acquiring result mutex...");
    std::lock_guard<std::mutex> lock(m_resultMutex);
    LogMessage("MainFrame: Result mutex acquired");
    
    if (m_checkSuccess && !m_currentChain.certificates.empty()) {
        LogMessage("MainFrame: Check successful, certificate chain has " + 
                  std::to_string(m_currentChain.certificates.size()) + " certificates");
        
        // Display certificate information
        LogMessage("MainFrame: Displaying certificate information...");
        DisplayCertificateInfo(m_currentChain.certificates[0]);

        // Display certificate chain
        LogMessage("MainFrame: Displaying certificate chain...");
        DisplayCertificateChain(m_currentChain);

        // Display OCSP information
        LogMessage("MainFrame: Displaying OCSP information...");
        DisplayOCSPInfo(m_currentChain.certificates[0]);

        // Display SSL trace information
        LogMessage("MainFrame: Displaying SSL trace information...");
        DisplayTraceInfo(m_sslChecker->getTraceInfo());

        SetStatusText("Certificate check completed");
    } else {
        LogMessage("MainFrame: Check failed or certificate chain is empty");
        if (!m_checkSuccess) {
            LogMessage("MainFrame: m_checkSuccess is false");
        }
        if (m_currentChain.certificates.empty()) {
            LogMessage("MainFrame: m_currentChain.certificates is empty");
        }
        wxTextAttr attr;
        attr.SetTextColour(*wxRED);  // 设置红色
        const long start = m_certificateText->GetLastPosition();
        m_certificateText->SetValue("Failed to retrieve certificate information");
        const long end = m_certificateText->GetLastPosition();
        m_certificateText->SetStyle(start, end, attr);
        SetStatusText("Certificate check failed");
    }

    m_checkButton->Enable();
    LogMessage("MainFrame: OnCheckComplete finished");
}

void MainFrame::DisplayCertificateInfo(const CertificateInfo& certInfo) {
    wxTextAttr attr;
    wxColour green(11 ,114, 30);
    attr.SetTextColour(green);
    // wxString info;
    m_certificateText->AppendText("Certificate Information:\n\n");
    m_certificateText->AppendText("Subject: " + wxString::FromUTF8(certInfo.subject) + "\n\n");
    m_certificateText->AppendText("Issuer: " + wxString::FromUTF8(certInfo.issuer) + "\n\n");
    m_certificateText->AppendText("Serial Number: " + certInfo.serialNumber + "\n");
    m_certificateText->AppendText("Valid From: " + certInfo.validFrom + "\n");
    m_certificateText->AppendText("Valid To: " + certInfo.validTo + "\n");
    m_certificateText->AppendText("Remaining Validity: ");
    const int rstart = m_certificateText->GetLastPosition();
    m_certificateText->AppendText(wxString::FromUTF8(certInfo.remainingValidity) + "\n");
    const int rend = m_certificateText->GetLastPosition();
    m_certificateText->SetStyle(rstart, rend, attr);
    m_certificateText->AppendText("Signature Algorithm: " + certInfo.signatureAlgorithm + "\n");
    m_certificateText->AppendText("Public Key: " + certInfo.publicKeyType + ", " +  wxString::Format(wxT("%i"), certInfo.publicKeyBits) + " bits\n");
    m_certificateText->AppendText("Thumbprint (SHA-1): " + certInfo.thumbprint + "\n");

    m_certificateText->AppendText("Subject Alternative Names:\n");
    for (const auto& san : certInfo.subjectAltNames) {
        m_certificateText->AppendText("  " + wxString::FromUTF8(san) + "\n");
    }
    m_certificateText->SetInsertionPoint(0);
    // info << "Subject: " << wxString::FromUTF8(certInfo.subject) << "\n\n";
    // info << "Issuer: " << wxString::FromUTF8(certInfo.issuer) << "\n\n";
    // info << "Serial Number: " << certInfo.serialNumber << "\n\n";
    // info << "Valid From: " << certInfo.validFrom << "\n";
    // info << "Valid To: " << certInfo.validTo << "\n";
    // info << "Remaining Validity: " << wxString::FromUTF8(certInfo.remainingValidity) << "\n\n";
    // info << "Signature Algorithm: " << certInfo.signatureAlgorithm << "\n\n";
    // info << "Public Key: " << certInfo.publicKeyType << ", " << certInfo.publicKeyBits << " bits\n\n";
    // info << "Thumbprint (SHA-1): " << certInfo.thumbprint << "\n\n";
    //
    // info << "Subject Alternative Names:\n";
    // for (const auto& san : certInfo.subjectAltNames) {
    //     info << "  " << wxString::FromUTF8(san) << "\n";
    // }
    //
    // m_certificateText->SetValue(info);
}

void MainFrame::DisplayCertificateChain(const CertificateChain& chain) {
    // Clear grid
    if (m_chainGrid->GetNumberRows() > 0) {
        m_chainGrid->DeleteRows(0, m_chainGrid->GetNumberRows());
    }

    // Add rows for each certificate
    m_chainGrid->AppendRows(chain.certificates.size());

    for (size_t i = 0; i < chain.certificates.size(); ++i) {
        const auto& cert = chain.certificates[i];

        m_chainGrid->SetCellValue(i, 0, wxString::Format("%zu", i));
        m_chainGrid->SetCellValue(i, 1, wxString::FromUTF8(cert.subject));
        m_chainGrid->SetCellValue(i, 2, wxString::FromUTF8(cert.issuer));
        m_chainGrid->SetCellValue(i, 3, cert.validTo);
    }

    m_chainGrid->AutoSizeColumns();
}

void MainFrame::DisplayOCSPInfo(const CertificateInfo& certInfo) {
    wxString info;

    info << "OCSP Status: " << (certInfo.ocspEnabled ? "Enabled" : "Disabled") << "\n\n";

    if (certInfo.ocspEnabled) {
        info << "Status: " << certInfo.ocspStatus << "\n";
        info << "Responder URL: " << certInfo.ocspResponderUrl << "\n";
        info << "Response Time: " << certInfo.ocspResponseTime << "\n";
    }

    m_ocspText->SetValue(info);
}

void MainFrame::DisplayTraceInfo(const std::vector<std::string>& traceInfo) {
    wxString info;

    info << "SSL Handshake Trace:\n\n";
    
    for (const auto& trace : traceInfo) {
        info << wxString::FromUTF8(trace) << "\n";
    }

    m_traceText->SetValue(info);
}

void MainFrame::ClearResults() {
    m_certificateText->Clear();
    if (m_chainGrid->GetNumberRows() > 0) {
        m_chainGrid->DeleteRows(0, m_chainGrid->GetNumberRows());
    }
    m_ocspText->Clear();
    m_traceText->Clear();
}

MainFrame::~MainFrame() {
    LogMessage("=== ZapSSL Application Shutting Down ===");
}

void MainFrame::OnGridCellDoubleClick(wxGridEvent& event) {
    // int row = event.GetRow();
    //
    // if (row >= 0 && row < static_cast<int>(m_currentChain.certificates.size())) {
    //     // 显示证书详情
    //     DisplayCertificateInfo(m_currentChain.certificates[row]);
    //
    //     // 切换到证书详情页
    //     m_notebook->SetSelection(0);
    // }
    int row = event.GetRow();
    if (row < 0 || row >= static_cast<int>(m_currentChain.certificates.size())) {
        return;
    }

    // 获取保存的证书
    std::shared_ptr<X509> cert = m_sslChecker->getCertificate(row);
    if (!cert) {
        wxMessageBox("Failed to get certificate", "Error", wxICON_ERROR);
        return;
    }

#ifdef __WXMSW__
    // Windows 平台特定的证书查看器
    // 将证书转换为DER格式
    unsigned char* der = nullptr;
    int der_len = i2d_X509(cert.get(), &der);
    if (der_len < 0) {
        wxMessageBox("Failed to convert certificate to DER format", "Error", wxICON_ERROR);
        return;
    }

    // 创建Windows证书上下文
    PCCERT_CONTEXT certContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der,
        der_len
    );

    OPENSSL_free(der);

    if (!certContext) {
        wxMessageBox("Failed to create certificate context", "Error", wxICON_ERROR);
        return;
    }

    // 显示证书对话框
    CRYPTUI_VIEWCERTIFICATE_STRUCT viewInfo = { 0 };
    viewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
    viewInfo.hwndParent = this->GetHandle();
    viewInfo.pCertContext = certContext;
    viewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE;

    BOOL properties = FALSE;
    CryptUIDlgViewCertificate(&viewInfo, &properties);

    CertFreeCertificateContext(certContext);
#elif defined(__WXGTK__)
    // Linux 平台
    // 显示一个详细的证书信息对话框
    wxString certDetails;
    certDetails << "Certificate Details:\n\n";
    certDetails << "Subject: " << wxString::FromUTF8(m_currentChain.certificates[row].subject) << "\n";
    certDetails << "Issuer: " << wxString::FromUTF8(m_currentChain.certificates[row].issuer) << "\n";
    certDetails << "Valid From: " << m_currentChain.certificates[row].validFrom << "\n";
    certDetails << "Valid To: " << m_currentChain.certificates[row].validTo << "\n";
    certDetails << "Serial Number: " << m_currentChain.certificates[row].serialNumber << "\n";

    wxMessageDialog dialog(this, certDetails, "Certificate Details", wxOK | wxICON_INFORMATION);
    dialog.ShowModal();
#elif defined(__WXMAC__)
    // macOS 平台
    // 显示一个详细的证书信息对话框
    wxString certDetails;
    certDetails << "Certificate Details:\n\n";
    certDetails << "Subject: " << wxString::FromUTF8(m_currentChain.certificates[row].subject) << "\n";
    certDetails << "Issuer: " << wxString::FromUTF8(m_currentChain.certificates[row].issuer) << "\n";
    certDetails << "Valid From: " << m_currentChain.certificates[row].validFrom << "\n";
    certDetails << "Valid To: " << m_currentChain.certificates[row].validTo << "\n";
    certDetails << "Serial Number: " << m_currentChain.certificates[row].serialNumber << "\n";

    wxMessageDialog dialog(this, certDetails, "Certificate Details", wxOK | wxICON_INFORMATION);
    dialog.ShowModal();
#else
    // 其他平台 证书详情显示在首页 Certificate Details

    if (row >= 0 && row < static_cast<int>(m_currentChain.certificates.size())) {
        // 显示证书详情
        DisplayCertificateInfo(m_currentChain.certificates[row]);

        // 切换到证书详情页
        m_notebook->SetSelection(0);
    }
#endif

    event.Skip();
}