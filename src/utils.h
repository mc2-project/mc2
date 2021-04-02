#include <vector>
#include <numeric>
#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include "crypto.h"

// Print out a map<string, vector<float>>
void print_map(std::map<std::string, std::vector<double>> dict) {
    for (const auto& pair : dict) {
        std::cout << pair.first << ": ";
        for (float x : pair.second) {
            std::cout << x << ", ";
        }
        std::cout << std::endl;
    }
}

void print_map(std::map<std::string, std::string> dict) {
    for (const auto& pair : dict) {
        std::cout << pair.first << ": ";
        std::cout << std::boolalpha << pair.second << std::endl;
        std::cout << std::endl;
    }
}

void print_map_keys(std::map<std::string, std::vector<double>> dict) {
  for (const auto& pair : dict) {
    if (pair.first.length() > 20) continue;
    std::cout << pair.first << std::endl;
  }
}


// Print integers instead of bytes for encryption debugging. 
int print_bytes(uint8_t* data, size_t len) {
    for (int i = 0; i < len; i++) {
        std::cout << (int) data[i] << " ";
    }
    std::cout << std::endl;
}

// Delete a double pointer.
void delete_double_ptr(unsigned char** src, size_t num) {
    for (int i = 0; i < num; i++) {
        delete src[i];
    }
    delete src;
}

// Split a string by delimiter
std::vector<std::string> split (const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while (std::getline(ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}

void load_key(char* k_fname, char key[CIPHER_KEY_SIZE]) {
    std::ifstream keyfile;
    keyfile.open(k_fname);
    keyfile.read(key, CIPHER_KEY_SIZE);
    keyfile.close();
}
