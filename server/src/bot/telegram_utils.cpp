/*
 * RT-SRT Telegram Utilities
 * Low-level Telegram API utilities and HTTP client
 */

#include "telegram_utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <curl/curl.h>
#endif

namespace rt_srt {
namespace bot {

// HTTP Response structure
struct HttpResponse {
    std::string data;
    long response_code;
    
    HttpResponse() : response_code(0) {}
};

// Callback for writing HTTP response data
#ifdef _WIN32
// Windows implementation using WinINet
class WinHttpClient {
private:
    HINTERNET hInternet;
    HINTERNET hConnect;
    
public:
    WinHttpClient() : hInternet(nullptr), hConnect(nullptr) {
        hInternet = InternetOpenA("RT-SRT/1.0", 
                                  INTERNET_OPEN_TYPE_PRECONFIG, 
                                  nullptr, nullptr, 0);
    }
    
    ~WinHttpClient() {
        if (hConnect) InternetCloseHandle(hConnect);
        if (hInternet) InternetCloseHandle(hInternet);
    }
    
    HttpResponse post(const std::string& url, const std::string& data) {
        HttpResponse response;
        
        if (!hInternet) {
            return response;
        }
        
        // Parse URL
        std::string host = "api.telegram.org";
        std::string path = url.substr(url.find("/bot"));
        
        hConnect = InternetConnectA(hInternet, host.c_str(), 
                                   INTERNET_DEFAULT_HTTPS_PORT,
                                   nullptr, nullptr, 
                                   INTERNET_SERVICE_HTTP, 
                                   INTERNET_FLAG_SECURE, 0);
        
        if (!hConnect) {
            return response;
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(),
                                             nullptr, nullptr, nullptr,
                                             INTERNET_FLAG_SECURE, 0);
        
        if (!hRequest) {
            return response;
        }
        
        std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";
        
        if (HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                            (LPVOID)data.c_str(), data.length())) {
            
            char buffer[1024];
            DWORD bytesRead;
            
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                response.data.append(buffer, bytesRead);
            }
            
            response.response_code = 200; // Simplified
        }
        
        InternetCloseHandle(hRequest);
        return response;
    }
};

#else
// Linux/macOS implementation using libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HttpResponse* response) {
    size_t totalSize = size * nmemb;
    response->data.append((char*)contents, totalSize);
    return totalSize;
}

class CurlHttpClient {
private:
    CURL* curl;
    
public:
    CurlHttpClient() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
    }
    
    ~CurlHttpClient() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }
    
    HttpResponse post(const std::string& url, const std::string& data) {
        HttpResponse response;
        
        if (!curl) {
            return response;
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "RT-SRT/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        }
        
        return response;
    }
};
#endif

TelegramUtils::TelegramUtils(const std::string& bot_token) 
    : bot_token_(bot_token), base_url_("https://api.telegram.org/bot" + bot_token) {
    
#ifdef _WIN32
    http_client_ = std::make_unique<WinHttpClient>();
#else
    http_client_ = std::make_unique<CurlHttpClient>();
#endif
}

TelegramUtils::~TelegramUtils() = default;

std::string TelegramUtils::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

std::string TelegramUtils::escape_markdown(const std::string& text) {
    std::string escaped = text;
    
    // Characters that need escaping in Telegram MarkdownV2
    std::vector<char> special_chars = {'_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'};
    
    for (char ch : special_chars) {
        size_t pos = 0;
        std::string search(1, ch);
        std::string replace = "\\" + search;
        
        while ((pos = escaped.find(search, pos)) != std::string::npos) {
            escaped.replace(pos, search.length(), replace);
            pos += replace.length();
        }
    }
    
    return escaped;
}

bool TelegramUtils::send_message(const std::string& chat_id, 
                                const std::string& text, 
                                bool markdown) {
    try {
        std::string url = base_url_ + "/sendMessage";
        
        std::ostringstream data;
        data << "chat_id=" << url_encode(chat_id)
             << "&text=" << url_encode(text);
        
        if (markdown) {
            data << "&parse_mode=Markdown";
        }
        
#ifdef _WIN32
        auto* client = static_cast<WinHttpClient*>(http_client_.get());
#else
        auto* client = static_cast<CurlHttpClient*>(http_client_.get());
#endif
        
        HttpResponse response = client->post(url, data.str());
        
        if (response.response_code == 200) {
            // Parse JSON response to check for errors
            return response.data.find("\"ok\":true") != std::string::npos;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        std::cerr << "Error sending message: " << e.what() << std::endl;
        return false;
    }
}

bool TelegramUtils::send_document(const std::string& chat_id,
                                 const std::string& file_path,
                                 const std::string& caption) {
    // Document sending requires multipart/form-data which is more complex
    // For now, we'll send a message indicating file is ready
    std::string message = "=Î Document ready: " + file_path;
    if (!caption.empty()) {
        message += "\nCaption: " + caption;
    }
    
    return send_message(chat_id, message);
}

bool TelegramUtils::send_photo(const std::string& chat_id,
                              const std::string& photo_path,
                              const std::string& caption) {
    // Photo sending requires multipart/form-data
    // For now, we'll send a message indicating photo is ready
    std::string message = "=¼ Photo ready: " + photo_path;
    if (!caption.empty()) {
        message += "\nCaption: " + caption;
    }
    
    return send_message(chat_id, message);
}

std::string TelegramUtils::get_updates(int offset, int limit, int timeout) {
    try {
        std::string url = base_url_ + "/getUpdates";
        
        std::ostringstream data;
        data << "offset=" << offset
             << "&limit=" << limit
             << "&timeout=" << timeout;
        
#ifdef _WIN32
        auto* client = static_cast<WinHttpClient*>(http_client_.get());
#else
        auto* client = static_cast<CurlHttpClient*>(http_client_.get());
#endif
        
        HttpResponse response = client->post(url, data.str());
        
        if (response.response_code == 200) {
            return response.data;
        }
        
        return "";
        
    } catch (const std::exception& e) {
        std::cerr << "Error getting updates: " << e.what() << std::endl;
        return "";
    }
}

bool TelegramUtils::set_webhook(const std::string& webhook_url) {
    try {
        std::string url = base_url_ + "/setWebhook";
        
        std::ostringstream data;
        data << "url=" << url_encode(webhook_url);
        
#ifdef _WIN32
        auto* client = static_cast<WinHttpClient*>(http_client_.get());
#else
        auto* client = static_cast<CurlHttpClient*>(http_client_.get());
#endif
        
        HttpResponse response = client->post(url, data.str());
        
        if (response.response_code == 200) {
            return response.data.find("\"ok\":true") != std::string::npos;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        std::cerr << "Error setting webhook: " << e.what() << std::endl;
        return false;
    }
}

bool TelegramUtils::delete_webhook() {
    return set_webhook("");
}

std::string TelegramUtils::get_bot_info() {
    try {
        std::string url = base_url_ + "/getMe";
        
#ifdef _WIN32
        auto* client = static_cast<WinHttpClient*>(http_client_.get());
#else
        auto* client = static_cast<CurlHttpClient*>(http_client_.get());
#endif
        
        HttpResponse response = client->post(url, "");
        
        if (response.response_code == 200) {
            return response.data;
        }
        
        return "";
        
    } catch (const std::exception& e) {
        std::cerr << "Error getting bot info: " << e.what() << std::endl;
        return "";
    }
}

// Utility functions for message formatting
std::string TelegramUtils::format_code_block(const std::string& code, const std::string& language) {
    return "```" + language + "\n" + code + "\n```";
}

std::string TelegramUtils::format_inline_code(const std::string& code) {
    return "`" + code + "`";
}

std::string TelegramUtils::format_bold(const std::string& text) {
    return "*" + text + "*";
}

std::string TelegramUtils::format_italic(const std::string& text) {
    return "_" + text + "_";
}

std::string TelegramUtils::format_link(const std::string& text, const std::string& url) {
    return "[" + text + "](" + url + ")";
}

// Rate limiting utilities
bool TelegramUtils::is_rate_limited() {
    auto now = std::chrono::steady_clock::now();
    
    // Clean old timestamps (older than 1 minute)
    auto cutoff = now - std::chrono::minutes(1);
    message_timestamps_.erase(
        std::remove_if(message_timestamps_.begin(), message_timestamps_.end(),
                      [cutoff](const auto& timestamp) { return timestamp < cutoff; }),
        message_timestamps_.end()
    );
    
    // Check if we're within rate limits (30 messages per minute)
    if (message_timestamps_.size() >= 30) {
        return true;
    }
    
    message_timestamps_.push_back(now);
    return false;
}

void TelegramUtils::wait_for_rate_limit() {
    if (is_rate_limited()) {
        // Wait for 2 seconds if rate limited
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

// Error handling utilities
std::string TelegramUtils::get_error_description(int error_code) {
    static std::map<int, std::string> error_descriptions = {
        {400, "Bad Request: The request was invalid"},
        {401, "Unauthorized: Invalid bot token"},
        {403, "Forbidden: Bot doesn't have permission"},
        {404, "Not Found: Method or chat not found"},
        {429, "Too Many Requests: Rate limited"},
        {500, "Internal Server Error: Telegram server error"}
    };
    
    auto it = error_descriptions.find(error_code);
    if (it != error_descriptions.end()) {
        return it->second;
    }
    
    return "Unknown error code: " + std::to_string(error_code);
}

} // namespace bot
} // namespace rt_srt