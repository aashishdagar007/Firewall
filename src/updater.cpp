#include "updater.hpp"
#include "logger.hpp"
#include "platform.hpp"
#include <cstdlib>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <winhttp.h>
#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#endif
#endif

namespace fw {

Updater::Updater(Logger* logger,
                 const std::string& update_host,
                 uint16_t port,
                 const std::string& pinned_sha256)
    : logger_(logger), update_host_(update_host), port_(port), pinned_sha256_(pinned_sha256) {}

std::string Updater::get_secure_credential(const std::string& env_var_name,
                                           const std::vector<uint8_t>& dpapi_blob) {
    // 1. Check environment variables
    if (const char* env_val = std::getenv(env_var_name.c_str())) {
        if (env_val[0] != '\0') {
            return std::string(env_val);
        }
    }

#ifdef _WIN32
    // 2. Check DPAPI encrypted blob
    if (!dpapi_blob.empty()) {
        DATA_BLOB in_blob;
        in_blob.cbData = static_cast<DWORD>(dpapi_blob.size());
        in_blob.pbData = const_cast<BYTE*>(dpapi_blob.data());

        DATA_BLOB out_blob{};
        LPWSTR descr = nullptr;
        if (CryptUnprotectData(&in_blob, &descr, nullptr, nullptr, nullptr, 0, &out_blob)) {
            std::string decrypted(reinterpret_cast<char*>(out_blob.pbData), out_blob.cbData);
            LocalFree(out_blob.pbData);
            if (descr) LocalFree(descr);
            return decrypted;
        }
    }
#else
    (void)dpapi_blob;
#endif

    // Security: Never fall back to a hardcoded string
    return "";
}

UpdateCheckResult Updater::check_for_updates(const std::string& current_version) {
    UpdateCheckResult res;

    // Retrieve credential securely
    std::string api_key = get_secure_credential("AEGIS_UPDATE_KEY");

#ifdef _WIN32
    return check_winhttp(current_version, api_key);
#else
    (void)current_version;
    (void)api_key;
    res.error_message = "Platform update client not implemented for non-Windows host";
    return res;
#endif
}

#ifdef _WIN32
UpdateCheckResult Updater::check_winhttp(const std::string& current_version, const std::string& api_key) {
    UpdateCheckResult result;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, update_host_.c_str(), -1, nullptr, 0);
    std::wstring whost(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, update_host_.c_str(), -1, &whost[0], wlen);

    HINTERNET hSession = WinHttpOpen(
        L"AegixFirewall-Updater/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        result.error_message = "WinHttpOpen failed: " + std::to_string(GetLastError());
        return result;
    }

    // Enforce TLS 1.2 and TLS 1.3 only
    DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    secureProtocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols));

    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port_, 0);
    if (!hConnect) {
        result.error_message = "WinHttpConnect failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hSession);
        return result;
    }

    std::wstring path = L"/api/v1/update/check?current=";
    int vlen = MultiByteToWideChar(CP_UTF8, 0, current_version.c_str(), -1, nullptr, 0);
    std::wstring wversion(vlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, current_version.c_str(), -1, &wversion[0], vlen);
    path += wversion;

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE); // Enforces HTTPS

    if (!hRequest) {
        result.error_message = "WinHttpOpenRequest failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // ── Enforce Strict TLS Certificate & Hostname Verification ──────────
    // Clear all security ignore flags. Do NOT set:
    //   SECURITY_FLAG_IGNORE_UNKNOWN_CA
    //   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    //   SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    //   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
    // We explicitly clear them to ensure Windows trust validation will fail closed on any invalid cert.
    DWORD secFlags = 0;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    // Add authentication header if credential exists
    std::wstring headers;
    if (!api_key.empty()) {
        headers = L"Authorization: Bearer ";
        int klen = MultiByteToWideChar(CP_UTF8, 0, api_key.c_str(), -1, nullptr, 0);
        std::wstring wkey(klen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, api_key.c_str(), -1, &wkey[0], klen);
        headers += wkey + L"\r\n";
    }

    BOOL sent = WinHttpSendRequest(
        hRequest,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        static_cast<DWORD>(headers.length()),
        WINHTTP_NO_REQUEST_DATA,
        0, 0, 0);

    if (!sent) {
        DWORD err = GetLastError();
        result.error_message = "WinHttpSendRequest failed (TLS handshake / verification error): " + std::to_string(err);
        if (logger_) {
            logger_->log(LogLevel::LOG_ERROR, "[Updater] TLS Verification Failed: error " + std::to_string(err));
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    BOOL received = WinHttpReceiveResponse(hRequest, nullptr);
    if (!received) {
        result.error_message = "WinHttpReceiveResponse failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode,
                        &statusSize,
                        WINHTTP_NO_HEADER_INDEX);

    if (statusCode == 200) {
        result.success = true;
        std::string responseBody;
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;

            std::vector<char> tempBuf(dwSize + 1, 0);
            DWORD dwDownloaded = 0;
            if (WinHttpReadData(hRequest, tempBuf.data(), dwSize, &dwDownloaded)) {
                responseBody.append(tempBuf.data(), dwDownloaded);
            }
        } while (dwSize > 0);

        if (responseBody.find("\"update_available\":true") != std::string::npos) {
            result.update_available = true;
        }
    } else {
        result.error_message = "HTTP " + std::to_string(statusCode);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}
#endif

} // namespace fw
