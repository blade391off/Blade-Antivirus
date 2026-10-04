#pragma once

#include <string>
#include <vector>

struct SignMatch
{
    std::string name;
    int score;
    std::string description;
};

struct SignsResult
{
    int score = 0;
    std::vector<SignMatch> matches;
    std::string verdict;
};

class SignsEngine
{
public:
    SignsResult analyze(const std::string& filePath);

private:
    bool isPE(const std::string& filePath);

    void addSign(
        SignsResult& result,
        const std::string& name,
        int score,
        const std::string& description
    );

    void analyzePE(
        const std::string& filePath,
        SignsResult& result
    );

    void analyzeStrings(
        const std::string& filePath,
        SignsResult& result
    );
};