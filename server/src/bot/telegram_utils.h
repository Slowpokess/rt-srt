/*
 * RT-SRT Telegram Utilities Header
 * Low-level Telegram API utilities and HTTP client
 */

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <chrono>
#include <thread>

namespace rt_srt {
namespace bot {

// Forward declarations for platform-specific HTTP clients
#ifdef _WIN32
class WinHttpClient;
#else
class CurlHttpClient;
#endif

/**
 * Telegram API utility class
 * Provides low-level interface to Telegram Bot API
 */
class TelegramUtils {
private:
    std::string bot_token_;
    std::string base_url_;
    
#ifdef _WIN32
    std::unique_ptr<WinHttpClient> http_client_;
#else
    std::unique_ptr<CurlHttpClient> http_client_;
#endif
    
    // Rate limiting
    std::vector<std::chrono::steady_clock::time_point> message_timestamps_;
    
public:
    /**
     * Constructor
     * @param bot_token Telegram bot token
     */
    explicit TelegramUtils(const std::string& bot_token);
    
    /**
     * Destructor
     */
    ~TelegramUtils();
    
    // Disable copy constructor and assignment
    TelegramUtils(const TelegramUtils&) = delete;
    TelegramUtils& operator=(const TelegramUtils&) = delete;
    
    /**
     * Send a text message
     * @param chat_id Target chat ID
     * @param text Message text
     * @param markdown Whether to use Markdown formatting
     * @return true if successful
     */
    bool send_message(const std::string& chat_id, 
                     const std::string& text, 
                     bool markdown = false);
    
    /**
     * Send a document
     * @param chat_id Target chat ID
     * @param file_path Path to file
     * @param caption Optional caption
     * @return true if successful
     */
    bool send_document(const std::string& chat_id,
                      const std::string& file_path,
                      const std::string& caption = "");
    
    /**
     * Send a photo
     * @param chat_id Target chat ID
     * @param photo_path Path to photo
     * @param caption Optional caption
     * @return true if successful
     */
    bool send_photo(const std::string& chat_id,
                   const std::string& photo_path,
                   const std::string& caption = "");
    
    /**
     * Get updates from Telegram
     * @param offset Update offset
     * @param limit Number of updates to fetch
     * @param timeout Timeout in seconds
     * @return JSON response string
     */
    std::string get_updates(int offset = 0, int limit = 100, int timeout = 0);
    
    /**
     * Set webhook URL
     * @param webhook_url Webhook URL
     * @return true if successful
     */
    bool set_webhook(const std::string& webhook_url);
    
    /**
     * Delete webhook
     * @return true if successful
     */
    bool delete_webhook();
    
    /**
     * Get bot information
     * @return JSON response string
     */
    std::string get_bot_info();
    
    // Utility functions for message formatting
    
    /**
     * URL encode a string
     * @param value String to encode
     * @return Encoded string
     */
    static std::string url_encode(const std::string& value);
    
    /**
     * Escape markdown characters
     * @param text Text to escape
     * @return Escaped text
     */
    static std::string escape_markdown(const std::string& text);
    
    /**
     * Format code block
     * @param code Code content
     * @param language Programming language
     * @return Formatted code block
     */
    static std::string format_code_block(const std::string& code, 
                                        const std::string& language = "");
    
    /**
     * Format inline code
     * @param code Code content
     * @return Formatted inline code
     */
    static std::string format_inline_code(const std::string& code);
    
    /**
     * Format bold text
     * @param text Text to format
     * @return Formatted text
     */
    static std::string format_bold(const std::string& text);
    
    /**
     * Format italic text
     * @param text Text to format
     * @return Formatted text
     */
    static std::string format_italic(const std::string& text);
    
    /**
     * Format link
     * @param text Link text
     * @param url Link URL
     * @return Formatted link
     */
    static std::string format_link(const std::string& text, const std::string& url);
    
    // Rate limiting utilities
    
    /**
     * Check if rate limited
     * @return true if rate limited
     */
    bool is_rate_limited();
    
    /**
     * Wait for rate limit to clear
     */
    void wait_for_rate_limit();
    
    // Error handling utilities
    
    /**
     * Get error description for HTTP status code
     * @param error_code HTTP status code
     * @return Error description
     */
    static std::string get_error_description(int error_code);
};

// C-style interface for integration with agent code
extern "C" {
    /**
     * Initialize Telegram bot
     * @param token Bot token
     * @param chat_id Default chat ID
     * @return true if successful
     */
    bool telegram_bot_init(const char* token, const char* chat_id);
    
    /**
     * Cleanup Telegram bot
     */
    void telegram_bot_cleanup();
    
    /**
     * Send a message
     * @param text Message text
     * @return true if successful
     */
    bool telegram_send_message(const char* text);
    
    /**
     * Send log notification
     * @param agent_id Agent ID
     * @param log_type Log type
     * @param item_count Number of items
     * @param timestamp Timestamp string
     * @return true if successful
     */
    bool telegram_send_log_notification(const char* agent_id,
                                       const char* log_type,
                                       size_t item_count,
                                       const char* timestamp);
    
    /**
     * Send agent online notification
     * @param agent_id Agent ID
     * @param hostname Hostname
     * @param ip_address IP address
     * @return true if successful
     */
    bool telegram_send_agent_online(const char* agent_id,
                                   const char* hostname,
                                   const char* ip_address);
    
    /**
     * Send alert message
     * @param message Alert message
     * @param level Alert level (info, warning, error)
     * @return true if successful
     */
    bool telegram_send_alert(const char* message, const char* level);
    
    /**
     * Send file notification
     * @param file_path File path
     * @param caption Optional caption
     * @return true if successful
     */
    bool telegram_send_file(const char* file_path, const char* caption);
}

} // namespace bot
} // namespace rt_srt