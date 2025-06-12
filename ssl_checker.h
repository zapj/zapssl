#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <string>
#include <vector>
#include <memory>

// SSL Certificate information structure
struct CertificateInfo {
    std::string subject;
    std::string issuer;
    std::string serialNumber;
    std::string validFrom;
    std::string validTo;
    std::string remainingValidity;  // 新增字段：剩余有效期
    std::string signatureAlgorithm;
    std::string publicKeyType;
    int publicKeyBits;
    std::string thumbprint;
    std::vector<std::string> subjectAltNames;
    bool ocspEnabled;
    std::string ocspStatus;
    std::string ocspResponderUrl;
    std::string ocspResponseTime;
};

// Certificate chain structure
struct CertificateChain {
    std::vector<CertificateInfo> certificates;
    bool isComplete;
    bool isTrusted;
};

// Custom deleter for X509 certificates
struct X509Deleter {
    void operator()(X509* cert) {
        if (cert) X509_free(cert);
    }
};

// SSL Checker class to handle SSL connections and certificate validation
class SSLChecker {
public:
    SSLChecker();
    ~SSLChecker();

    // SSL trace callback function
    static void sslInfoCallback(const SSL* ssl, int type, int val);
    
    // Get SSL trace information
    const std::vector<std::string>& getTraceInfo() const { return m_traceInfo; }
    
    // Clear trace information
    void clearTraceInfo() { m_traceInfo.clear(); }

    // Check SSL certificate for a given host and port
    bool checkCertificate(const std::string& host, int port, CertificateChain& chain);

    // Check OCSP status
    bool checkOCSP(X509* cert, X509* issuerCert, std::string& status, std::string& responderUrl, std::string& responseTime);

    // Get certificate at specified index
    std::shared_ptr<X509> getCertificate(size_t index) const {
        if (index < m_certificateChain.size()) {
            return m_certificateChain[index];
        }
        return nullptr;
    }

    // Get number of certificates in the chain
    size_t getCertificateCount() const {
        return m_certificateChain.size();
    }

private:
    // Initialize OpenSSL
    void initOpenSSL();

    // Clean up OpenSSL
    void cleanupOpenSSL();

    // Store the certificate chain
    std::vector<std::shared_ptr<X509>> m_certificateChain;
    
    // Store SSL trace information
    std::vector<std::string> m_traceInfo;

    // Extract certificate information
    CertificateInfo extractCertInfo(X509* cert);

    // Format X509 name
    std::string formatName(X509_NAME* name);

    // Get certificate serial number as string
    std::string getSerialNumber(X509* cert);

    // Format ASN1 time
    std::string formatASN1Time(ASN1_TIME* time);

    // Get signature algorithm
    std::string getSignatureAlgorithm(X509* cert);

    // Get public key information
    void getPublicKeyInfo(X509* cert, std::string& type, int& bits);

    // Get certificate thumbprint (SHA-1 hash)
    std::string getThumbprint(X509* cert);

    // Get Subject Alternative Names
    std::vector<std::string> getSubjectAltNames(X509* cert);

    // Get OCSP responder URL
    std::string getOCSPResponderUrl(X509* cert);
    
    // Calculate remaining validity period
    std::string calculateRemainingValidity(ASN1_TIME* expiry);
};
