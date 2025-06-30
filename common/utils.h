#pragma once
#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include "logger.h"

namespace Xianwei {
std::string uuid();

bool ReadFile(const std::string& filename, std::string& body);

bool WriteFile(const std::string& filename, const std::string& data);
}  // namespace Xianwei
