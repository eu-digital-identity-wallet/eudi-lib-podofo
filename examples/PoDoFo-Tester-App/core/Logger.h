#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <string>
#include <sstream>
#include "Config.h"

/**
 * @brief Simple logging class for PoDoFo-Tester-App
 *
 * Provides INFO and DEBUG logging levels with configurable output.
 * DEBUG mode shows full values, INFO mode shows only essential information.
 *
 * ============================================================================
 * USAGE INSTRUCTIONS
 * ============================================================================
 *
 * 1. TO SWITCH BETWEEN MODES:
 *    - Open core/PoDoFo-App.cpp
 *    - Find the "LOGGING CONFIGURATION" section in main()
 *    - Change: Config::setDebugMode(true)  for DEBUG mode
 *    - Change: Config::setDebugMode(false) for INFO mode
 *
 * 2. LOGGING EXAMPLES:
 *    Logger::info("Starting process");                    // Always shown
 *    Logger::debug("Full value", someVariable);          // Only in DEBUG mode
 *    Logger::error("Error occurred");                     // Always shown
 *
 * 3. DEBUG MODE: Shows all values in full detail (no truncation)
 * 4. INFO MODE:  Shows only essential information for normal operation
 *
 * ============================================================================
 */
class Logger {
public:
    /**
     * @brief Log an INFO message
     * @param message The message to log
     */
    static void info(const std::string& message);

    /**
     * @brief Log a DEBUG message (only shown in debug mode)
     * @param message The message to log
     */
    static void debug(const std::string& message);

    /**
     * @brief Log a DEBUG message with a value (only shown in debug mode)
     * @param label The label for the value
     * @param value The value to log (full value, not truncated)
     */
    static void debug(const std::string& label, const std::string& value);

    /**
     * @brief Log a DEBUG message with a value (only shown in debug mode)
     * @param label The label for the value
     * @param value The value to log (full value, not truncated)
     */
    static void debug(const std::string& label, const char* value);

    /**
     * @brief Log an ERROR message (always shown)
     * @param message The error message to log
     */
    static void error(const std::string& message);

    /**
     * @brief Log a DEBUG message with a value (only shown in debug mode)
     * @param label The label for the value
     * @param value The value to log
     */
    template<typename T>
    static void debug(const std::string& label, const T& value) {
        if (Config::isDebugMode()) {
            std::ostringstream oss;
            oss << value;
            debug(label, oss.str());
        }
    }

private:
    static void printMessage(const std::string& level, const std::string& message);
};

#endif // LOGGER_H
