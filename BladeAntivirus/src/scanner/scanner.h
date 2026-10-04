#pragma once

#include <string>

struct ScanResult
{
    std::string file;
    std::string sha256;

    bool hashMatch = false;
    bool isPE = false;

    std::string verdict;
};

class HashDetector;

class Scanner
{
public:
    Scanner();
    ~Scanner();

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    bool initialize(
        const std::string& databasePath
    );

    ScanResult scan(
        const std::string& filePath
    );

private:
    std::string calculateSHA256(
        const std::string& filePath
    );

    bool checkPE(
        const std::string& filePath
    );

    HashDetector* detector = nullptr;
};