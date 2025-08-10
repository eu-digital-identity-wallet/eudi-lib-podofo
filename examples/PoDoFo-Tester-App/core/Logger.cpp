#include "Logger.h"
#include <iostream>
#include <string>
#include <sstream>

void Logger::info(const std::string& message) {
    printMessage("INFO", message);
}

void Logger::debug(const std::string& message) {
    if (Config::isDebugMode()) {
        printMessage("DEBUG", message);
    }
}

void Logger::debug(const std::string& label, const std::string& value) {
    if (Config::isDebugMode()) {
        std::string message = label + ": " + value;
        printMessage("DEBUG", message);
    }
}

void Logger::debug(const std::string& label, const char* value) {
    if (Config::isDebugMode()) {
        debug(label, std::string(value));
    }
}

void Logger::error(const std::string& message) {
    printMessage("ERROR", message);
}

void Logger::printMessage(const std::string& level, const std::string& message) {
    std::cout << "[" << level << "] " << message << std::endl;
}
