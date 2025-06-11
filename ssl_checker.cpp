#include "ssl_checker.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "cacert.h"


// 声明外部日志函数
extern void LogMessage(const std::string& message);

SSLChecker::SSLChecker() {
    initOpenSSL();
}

SSLChecker::~SSLChecker() {
    cleanupOpenSSL();
}

void SSLChecker::initOpenSSL() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

void SSLChecker::cleanupOpenSSL() {
    // In OpenSSL 1.1.0 and later, explicit cleanup is not necessary
    // Resources are automatically cleaned up when the program exits
    // This function is kept for compatibility with older versions
}

bool SSLChecker::checkCertificate(const std::string& host, int port, CertificateChain& chain) {
    BIO* bio = nullptr;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool result = false;

    LogMessage("SSLChecker: Starting certificate check for " + host + ":" + std::to_string(port));

    try {
        // Create SSL context
        LogMessage("SSLChecker: Creating SSL context...");
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            LogMessage("SSLChecker: Failed to create SSL context");
            throw std::runtime_error("Failed to create SSL context");
        }
        // 加载 CA 证书文件用于验证
        if (SSL_CTX_load_verify_locations(ctx,NULL, CACERT.c_str()) != 1) {
            // 加载失败，打印错误信息
            ERR_print_errors_fp(stderr);
            // 根据需要处理错误，例如退出程序
            exit(EXIT_FAILURE);
        }

        // Enable automatic chain building
        LogMessage("SSLChecker: Setting up SSL context options...");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

        // Load system certificates
        LogMessage("SSLChecker: Loading system certificates...");
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            LogMessage("SSLChecker: Failed to load system certificates");
            throw std::runtime_error("Failed to load system certificates");
        }

        // Create BIO chain
        LogMessage("SSLChecker: Creating connection BIO for " + host + ":" + std::to_string(port) + "...");
        std::string connect_str = host + ":" + std::to_string(port);
        bio = BIO_new_connect(connect_str.c_str());
        if (!bio) {
            LogMessage("SSLChecker: Failed to create connection BIO");
            throw std::runtime_error("Failed to create connection BIO");
        }

        // Create SSL object
        LogMessage("SSLChecker: Creating SSL object...");
        ssl = SSL_new(ctx);
        if (!ssl) {
            LogMessage("SSLChecker: Failed to create SSL object");
            throw std::runtime_error("Failed to create SSL object");
        }

        SSL_set_bio(ssl, bio, bio);
        bio = nullptr; // BIO is now owned by SSL

        // Set SNI hostname
        LogMessage("SSLChecker: Setting SNI hostname to " + host + "...");
        SSL_set_tlsext_host_name(ssl, host.c_str());

        // Perform handshake
        LogMessage("SSLChecker: Performing SSL handshake...");
        int connect_result = SSL_connect(ssl);
        if (connect_result != 1) {
            int ssl_error = SSL_get_error(ssl, connect_result);
            LogMessage("SSLChecker: SSL handshake failed with error code: " + std::to_string(ssl_error));
            
            // Get detailed error information
            unsigned long error_code;
            std::string error_details;
            while ((error_code = ERR_get_error()) != 0) {
                char error_buffer[256];
                ERR_error_string_n(error_code, error_buffer, sizeof(error_buffer));
                error_details += std::string(error_buffer) + "; ";
            }
            
            if (!error_details.empty()) {
                LogMessage("SSLChecker: Detailed error: " + error_details);
            }
            
            // Check for specific error conditions
            if (ssl_error == SSL_ERROR_SSL) {
                LogMessage("SSLChecker: Protocol error in SSL library");
            } else if (ssl_error == SSL_ERROR_SYSCALL) {
                LogMessage("SSLChecker: I/O error occurred");
                if (connect_result == 0) {
                    LogMessage("SSLChecker: Connection closed by peer");
                } else if (connect_result == -1) {
                    LogMessage("SSLChecker: System error: " + std::string(strerror(errno)));
                }
            } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                LogMessage("SSLChecker: Connection closed cleanly");
            } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                LogMessage("SSLChecker: Operation did not complete: " + 
                          std::string(ssl_error == SSL_ERROR_WANT_READ ? "want read" : "want write"));
            }
            
            throw std::runtime_error("SSL handshake failed");
        }
        LogMessage("SSLChecker: SSL handshake successful");

        // Get peer certificate chain
        LogMessage("SSLChecker: Getting peer certificate chain...");
        STACK_OF(X509)* cert_chain = SSL_get_peer_cert_chain(ssl);
        if (!cert_chain) {
            LogMessage("SSLChecker: No certificate chain available");
            throw std::runtime_error("No certificate chain available");
        }
        LogMessage("SSLChecker: Found " + std::to_string(sk_X509_num(cert_chain)) + " certificates in the chain");

        // Process certificates
        chain.certificates.clear();
        chain.isComplete = true;
        chain.isTrusted = SSL_get_verify_result(ssl) == X509_V_OK;
        LogMessage("SSLChecker: Certificate chain is " + std::string(chain.isTrusted ? "trusted" : "not trusted"));

        for (int i = 0; i < sk_X509_num(cert_chain); i++) {
            LogMessage("SSLChecker: Processing certificate " + std::to_string(i + 1) + " of " + std::to_string(sk_X509_num(cert_chain)));
            X509* cert = sk_X509_value(cert_chain, i);
            chain.certificates.push_back(extractCertInfo(cert));

            // Check OCSP for the leaf certificate
            if (i == 0) {
                LogMessage("SSLChecker: Checking OCSP for leaf certificate...");
                X509* issuer = (sk_X509_num(cert_chain) > 1) ? sk_X509_value(cert_chain, 1) : nullptr; // Get issuer certificate
                if (!issuer) {
                    LogMessage("SSLChecker: No issuer certificate available for OCSP check");
                } else {
                    std::string status, responderUrl, responseTime;
                    chain.certificates[0].ocspEnabled = checkOCSP(cert, issuer, status, responderUrl, responseTime);
                    if (chain.certificates[0].ocspEnabled) {
                        LogMessage("SSLChecker: OCSP check successful, status: " + status);
                        chain.certificates[0].ocspStatus = status;
                        chain.certificates[0].ocspResponderUrl = responderUrl;
                        chain.certificates[0].ocspResponseTime = responseTime;
                    } else {
                        LogMessage("SSLChecker: OCSP check failed or not available");
                    }
                }
            }
        }

        LogMessage("SSLChecker: Certificate check completed successfully");
        result = true;
    }
    catch (const std::exception& e) {
        LogMessage("SSLChecker: Exception caught: " + std::string(e.what()));
        // Clean up and return false
        if (bio) BIO_free_all(bio);
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        return false;
    }

    // Clean up
    LogMessage("SSLChecker: Cleaning up resources...");
    if (ssl) SSL_free(ssl); // This will also free the BIO
    if (ctx) SSL_CTX_free(ctx);

    return result;
}

bool SSLChecker::checkOCSP(X509* cert, X509* issuerCert, std::string& status, std::string& responderUrl, std::string& responseTime) {
    if (!cert || !issuerCert) {
        return false;
    }

    // Get OCSP URL
    responderUrl = getOCSPResponderUrl(cert);
    if (responderUrl.empty()) {
        return false;
    }

    // Create OCSP request
    OCSP_REQUEST* req = nullptr;
    OCSP_RESPONSE* resp = nullptr;
    bool result = false;

    try {
        OCSP_CERTID* certId = OCSP_cert_to_id(nullptr, cert, issuerCert);
        if (!certId) {
            throw std::runtime_error("Failed to create OCSP cert ID");
        }

        req = OCSP_REQUEST_new();
        if (!req) {
            OCSP_CERTID_free(certId);
            throw std::runtime_error("Failed to create OCSP request");
        }

        if (!OCSP_request_add0_id(req, certId)) {
            throw std::runtime_error("Failed to add ID to OCSP request");
        }

        // Send OCSP request
        auto start = std::chrono::steady_clock::now();

        BIO* bio = BIO_new_connect(responderUrl.c_str());
        if (!bio) {
            throw std::runtime_error("Failed to create OCSP connection BIO");
        }

        if (BIO_do_connect(bio) <= 0) {
            BIO_free_all(bio);
            throw std::runtime_error("Failed to connect to OCSP responder");
        }

        resp = OCSP_sendreq_bio(bio, const_cast<char*>(responderUrl.c_str()), req);
        BIO_free_all(bio);

        if (!resp) {
            throw std::runtime_error("Failed to get OCSP response");
        }

        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        responseTime = std::to_string(duration.count()) + "ms";

        // Process OCSP response
        int response_status = OCSP_response_status(resp);
        if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            throw std::runtime_error("OCSP response not successful");
        }

        OCSP_BASICRESP* basic = OCSP_response_get1_basic(resp);
        if (!basic) {
            throw std::runtime_error("Failed to get basic OCSP response");
        }

        int cert_status, reason;
        ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;

        if (!OCSP_resp_find_status(basic, certId, &cert_status, &reason, &revtime, &thisupd, &nextupd)) {
            OCSP_BASICRESP_free(basic);
            throw std::runtime_error("Failed to find OCSP status");
        }

        // Convert status to string
        switch (cert_status) {
            case V_OCSP_CERTSTATUS_GOOD:
                status = "Good";
                break;
            case V_OCSP_CERTSTATUS_REVOKED:
                status = "Revoked";
                break;
            case V_OCSP_CERTSTATUS_UNKNOWN:
                status = "Unknown";
                break;
            default:
                status = "Invalid";
                break;
        }

        OCSP_BASICRESP_free(basic);
        result = true;
    }
    catch (const std::exception&) {
        status = "Error";
        result = false;
    }

    if (req) OCSP_REQUEST_free(req);
    if (resp) OCSP_RESPONSE_free(resp);

    return result;
}

CertificateInfo SSLChecker::extractCertInfo(X509* cert) {
    CertificateInfo info;
    
    // Get subject and issuer
    info.subject = formatName(X509_get_subject_name(cert));
    info.issuer = formatName(X509_get_issuer_name(cert));
    
    // Get serial number
    info.serialNumber = getSerialNumber(cert);
    
    // Get validity period
    info.validFrom = formatASN1Time(X509_get_notBefore(cert));
    info.validTo = formatASN1Time(X509_get_notAfter(cert));
    
    // Calculate remaining validity
    info.remainingValidity = calculateRemainingValidity(X509_get_notAfter(cert));
    
    // Get signature algorithm
    info.signatureAlgorithm = getSignatureAlgorithm(cert);
    
    // Get public key information
    getPublicKeyInfo(cert, info.publicKeyType, info.publicKeyBits);
    
    // Get thumbprint
    info.thumbprint = getThumbprint(cert);
    
    // Get subject alternative names
    info.subjectAltNames = getSubjectAltNames(cert);
    
    return info;
}

std::string SSLChecker::formatName(X509_NAME* name) {
    if (!name) return "";
    
    // 首先获取原始的DER编码数据
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    
    // 解码十六进制转义序列
    std::string decoded;
    size_t i = 0;
    
    while (i < result.length()) {
        if (result[i] == '\\' && i + 2 < result.length() && 
            isxdigit(result[i+1]) && isxdigit(result[i+2])) {
            // 收集所有连续的转义序列
            std::vector<unsigned char> bytes;
            while (i < result.length() && 
                   result[i] == '\\' && i + 2 < result.length() && 
                   isxdigit(result[i+1]) && isxdigit(result[i+2])) {
                std::string hex = result.substr(i+1, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(hex, nullptr, 16));
                bytes.push_back(byte);
                i += 3; // 跳过 '\' 和两个十六进制字符
            }
            // 将收集到的字节作为UTF-8字符串添加到结果中
            decoded.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        } else {
            decoded.push_back(result[i]);
            ++i;
        }
    }
    
    return decoded;
}

std::string SSLChecker::getSerialNumber(X509* cert) {
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* decimal = BN_bn2hex(bn);
    
    std::string result(decimal);
    OPENSSL_free(decimal);
    BN_free(bn);
    
    return result;
}

std::string SSLChecker::formatASN1Time(ASN1_TIME* time) {
    if (!time) return "Invalid time";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "Memory allocation error";
    
    // Convert ASN1_TIME to more usable format
    ASN1_GENERALIZEDTIME* gtime = ASN1_TIME_to_generalizedtime(time, NULL);
    if (!gtime) {
        BIO_free(bio);
        return "Time conversion error";
    }
    
    // Get the raw string data
    const unsigned char* str = ASN1_STRING_get0_data(gtime);
    int len = ASN1_STRING_length(gtime);
    
    // Format: YYYYMMDDHHMMSSZ
    if (len < 14) {
        ASN1_GENERALIZEDTIME_free(gtime);
        BIO_free(bio);
        return "Invalid time format";
    }
    
    // Parse components
    int year = (str[0] - '0') * 1000 + (str[1] - '0') * 100 + (str[2] - '0') * 10 + (str[3] - '0');
    int month = (str[4] - '0') * 10 + (str[5] - '0');
    int day = (str[6] - '0') * 10 + (str[7] - '0');
    int hour = (str[8] - '0') * 10 + (str[9] - '0');
    int min = (str[10] - '0') * 10 + (str[11] - '0');
    int sec = (str[12] - '0') * 10 + (str[13] - '0');
    
    // Format as YYYY-MM-DD HH:MM:SS
    std::stringstream ss;
    ss << std::setfill('0') 
       << std::setw(4) << year << "-" 
       << std::setw(2) << month << "-" 
       << std::setw(2) << day << " " 
       << std::setw(2) << hour << ":" 
       << std::setw(2) << min << ":" 
       << std::setw(2) << sec;
    
    ASN1_GENERALIZEDTIME_free(gtime);
    BIO_free(bio);
    
    return ss.str();
}

std::string SSLChecker::calculateRemainingValidity(ASN1_TIME* expiry) {
    if (!expiry) return "Unknown";

    // Convert ASN1_TIME to time_t
    int pday = 0, psec = 0;
    int ret = ASN1_TIME_diff(&pday, &psec, NULL, expiry);
    if (ret != 1) {
        return "Time calculation error";
    }

    // If both days and seconds are negative or zero, the certificate has expired
    if (pday < 0 || (pday == 0 && psec <= 0)) {
        return "已过期";
    }

    // Convert total seconds to days (add the seconds component to days)
    int total_days = pday;
    if (psec > 0) {
        total_days += (psec + 86399) / 86400; // Round up partial days
    }

    // Format the remaining validity
    if (total_days > 365) {
        int years = total_days / 365;
        int remaining_days = total_days % 365;
        if (remaining_days > 30) {
            int months = remaining_days / 30;
            remaining_days = remaining_days % 30;
            return std::to_string(years) + "年" + std::to_string(months) + "个月" + std::to_string(remaining_days) + "天";
        } else {
            return std::to_string(years) + "年" + std::to_string(remaining_days) + "天";
        }
    } else {
        return std::to_string(total_days) + "天";
    }
}

std::string SSLChecker::getSignatureAlgorithm(X509* cert) {
    int nid = X509_get_signature_nid(cert);
    return OBJ_nid2ln(nid);
}

void SSLChecker::getPublicKeyInfo(X509* cert, std::string& type, int& bits) {
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        type = "Unknown";
        bits = 0;
        return;
    }
    
    bits = EVP_PKEY_bits(pkey);
    
    int keyType = EVP_PKEY_base_id(pkey);
    switch (keyType) {
        case EVP_PKEY_RSA:
            type = "RSA";
            break;
        case EVP_PKEY_DSA:
            type = "DSA";
            break;
        case EVP_PKEY_EC:
            type = "EC";
            break;
        default:
            type = "Unknown";
            break;
    }
    
    EVP_PKEY_free(pkey);
}

std::string SSLChecker::getThumbprint(X509* cert) {
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned int n;
    X509_digest(cert, EVP_sha1(), md, &n);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < n; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
    }
    
    return ss.str();
}

std::vector<std::string> SSLChecker::getSubjectAltNames(X509* cert) {
    std::vector<std::string> result;
    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    
    if (names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(names, i);
            
            if (gen->type == GEN_DNS || gen->type == GEN_URI) {
                ASN1_STRING* str = (gen->type == GEN_DNS) ? gen->d.dNSName : gen->d.uniformResourceIdentifier;
                
                // 使用BIO来正确处理可能的UTF-8编码
                BIO* bio = BIO_new(BIO_s_mem());
                ASN1_STRING_print_ex(bio, str, ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_QUOTE);
                
                char* data = nullptr;
                long len = BIO_get_mem_data(bio, &data);
                if (data && len > 0) {
                    // 去除引号（如果存在）
                    std::string value(data, len);
                    if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
                        value = value.substr(1, value.length() - 2);
                    }
                    result.push_back(value);
                }
                
                BIO_free(bio);
            }
        }
        
        GENERAL_NAMES_free(names);
    }
    
    return result;
}

std::string SSLChecker::getOCSPResponderUrl(X509* cert) {
    AUTHORITY_INFO_ACCESS* aia = static_cast<AUTHORITY_INFO_ACCESS*>(X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr));
    std::string url;
    
    if (aia) {
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
            ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
            
            if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
                if (ad->location->type == GEN_URI) {
                    const unsigned char* uri_data = ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
                    url = std::string(reinterpret_cast<const char*>(uri_data));
                    break;
                }
            }
        }
        
        AUTHORITY_INFO_ACCESS_free(aia);
    }
    LogMessage("OCSP responder URL: " + url);
    return url;
}
