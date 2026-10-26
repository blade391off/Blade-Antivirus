#include "database_manager.h"
#include <fstream>

bool DatabaseManager::load(const std::string& path)
{
	std::ifstream in(path);
	if (!in)
		return false;
	std::getline(in, ver);
	return true;
}

bool DatabaseManager::isUpToDate() const
{
	return !ver.empty();
}

std::string DatabaseManager::version() const
{
	return ver;
}
