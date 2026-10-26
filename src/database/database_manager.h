#pragma once
#include <string>

class DatabaseManager
{
public:
	bool load(const std::string& path);
	bool isUpToDate() const;
	std::string version() const;
private:
	std::string ver;
};
