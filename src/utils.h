/*!
 *  Copyright (c) 2020-22 by Contributors
 */

#include <fstream>
#include <iostream>
#include <map>
#include <math.h>
#include <numeric>
#include <string>
#include <type_traits>
#include <vector>

#include "crypto.h"

// Print out a map<string, vector<float>>
void print_map(std::map<std::string, std::vector<double>> dict) {
    for (const auto &pair : dict) {
        std::cout << pair.first << ": ";
        for (float x : pair.second) {
            std::cout << x << ", ";
        }
        std::cout << std::endl;
    }
}

void print_map(std::map<std::string, std::string> dict) {
    for (const auto &pair : dict) {
        std::cout << pair.first << ": ";
        std::cout << std::boolalpha << pair.second << std::endl;
        std::cout << std::endl;
    }
}

void print_map_keys(std::map<std::string, std::vector<double>> dict) {
    for (const auto &pair : dict) {
        if (pair.first.length() > 20)
            continue;
        std::cout << pair.first << std::endl;
    }
}

// Print integers instead of bytes for encryption debugging.
int print_bytes(uint8_t *data, size_t len) {
    for (int i = 0; i < len; i++) {
        std::cout << (int)data[i] << " ";
    }
    std::cout << std::endl;
}

// Delete a double pointer.
void delete_double_ptr(unsigned char **src, size_t num) {
    for (int i = 0; i < num; i++) {
        delete src[i];
    }
    delete src;
}

// Split a string by delimiter
std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (std::getline(ss, item, delim)) {
        result.push_back(item);
    }

    return result;
}

void load_key(char *k_fname, char key[CIPHER_KEY_SIZE]) {
    std::ifstream keyfile;
    keyfile.open(k_fname);
    keyfile.read(key, CIPHER_KEY_SIZE);
    keyfile.close();
}

// Convert a date to its integer representation
int date_to_int(std::string &&date) {
    struct tm tm = {0};
    std::istringstream iss(date);
    iss >> std::get_time(&tm, "%Y-%m-%d");
    // mktime returns seconds since the epoch, but opaque expects days since
    // the epoch
    auto days_since_epoch = mktime(&tm) / (24 * 3600);
    return days_since_epoch;
}

// Convert an integer to its date representation
std::string int_to_date(int days_since_epoch) {
    // `time_t` is represented as seconds since the epoch
    time_t secs_since_epoch = days_since_epoch * 24 * 3600;
    struct tm *tm = gmtime(&secs_since_epoch);
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d");
    return oss.str();
}

// This function ensures that decrypted floating point values have their types
// correctly inferred in Spark. By default, if a floating point value is
// equivalent to an integer, C++ will display it without a decimal + trailing
// zero. However, this is incorrect behaivor in Spark.
template <typename F> std::string fmt_floating(F value) {
    static_assert(
        std::is_floating_point<F>::value,
        "Attempted to call fmt_decimal on value which isn't a floating point");
    // Extract the integer part of the value. This is necessary since a simple
    // cast can fail if the value is too large.
    double int_part;
    modf(value, &int_part);

    std::ostringstream oss;
    if (value == int_part) {
        oss << value << ".0";
    } else {
        oss << value;
    }
    return oss.str();
}
