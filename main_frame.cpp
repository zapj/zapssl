#include "main_frame.h"
#include "logger.h"
#include <wx/statline.h>
#include <thread>

// Define the custom event
wxDEFINE_EVENT(CHECK_COMPLETE_EVENT, wxCommandEvent);

// Event table
wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_BUTTON(wxID_ANY, MainFrame::OnCheck)
    EVT_COMMAND(wxID_ANY, CHECK_COMPLETE_EVENT, MainFrame::OnCheckComplete)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(800, 600)),
      m_sslChecker(std::make_unique<SSLChecker>()) {
    
    // 初始化日志文件
    if (!g_logFile.is_open()) {
        g_logFile.open("zapssl_debug.log", std::ios::out | std::ios::app);
        if (g_logFile.is_open()) {
            LogMessage("=== ZapSSL Application Started ===");
        }
    }
    
    LogMessage("MainFrame: Constructor called");

    // Create main panel
    wxPanel* panel = new wxPanel(this);

    // Create input controls
    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);

    inputSizer->Add(new wxStaticText(panel, wxID_ANY, "Host:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_hostInput = new wxTextCtrl(panel, wxID_ANY, "");
    inputSizer->Add(m_hostInput, 1, wxRIGHT, 10);

    inputSizer->Add(new wxStaticText(panel, wxID_ANY, "Port:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    m_portInput = new wxTextCtrl(panel, wxID_ANY, "443");
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

    // Add pages to notebook
    m_notebook->AddPage(certPanel, "Certificate Details");
    m_notebook->AddPage(chainPanel, "Certificate Chain");
    m_notebook->AddPage(ocspPanel, "OCSP Status");

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

        SetStatusText("Certificate check completed");
    } else {
        LogMessage("MainFrame: Check failed or certificate chain is empty");
        if (!m_checkSuccess) {
            LogMessage("MainFrame: m_checkSuccess is false");
        }
        if (m_currentChain.certificates.empty()) {
            LogMessage("MainFrame: m_currentChain.certificates is empty");
        }
        m_certificateText->SetValue("Failed to retrieve certificate information");
        SetStatusText("Certificate check failed");
    }

    m_checkButton->Enable();
    LogMessage("MainFrame: OnCheckComplete finished");
}

void MainFrame::DisplayCertificateInfo(const CertificateInfo& certInfo) {
    wxString info;

    info << "Subject: " << certInfo.subject << "\n\n";
    info << "Issuer: " << certInfo.issuer << "\n\n";
    info << "Serial Number: " << certInfo.serialNumber << "\n\n";
    info << "Valid From: " << certInfo.validFrom << "\n";
    info << "Valid To: " << certInfo.validTo << "\n";
    info << "Remaining Validity: " << wxString::FromUTF8(certInfo.remainingValidity) << "\n\n";
    info << "Signature Algorithm: " << certInfo.signatureAlgorithm << "\n\n";
    info << "Public Key: " << certInfo.publicKeyType << ", " << certInfo.publicKeyBits << " bits\n\n";
    info << "Thumbprint (SHA-1): " << certInfo.thumbprint << "\n\n";

    info << "Subject Alternative Names:\n";
    for (const auto& san : certInfo.subjectAltNames) {
        info << "  " << san << "\n";
    }

    m_certificateText->SetValue(info);
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
        m_chainGrid->SetCellValue(i, 1, cert.subject);
        m_chainGrid->SetCellValue(i, 2, cert.issuer);
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

void MainFrame::ClearResults() {
    m_certificateText->Clear();
    if (m_chainGrid->GetNumberRows() > 0) {
        m_chainGrid->DeleteRows(0, m_chainGrid->GetNumberRows());
    }
    m_ocspText->Clear();
}

MainFrame::~MainFrame() {
    LogMessage("=== ZapSSL Application Shutting Down ===");
    if (g_logFile.is_open()) {
        g_logFile.close();
    }
}
