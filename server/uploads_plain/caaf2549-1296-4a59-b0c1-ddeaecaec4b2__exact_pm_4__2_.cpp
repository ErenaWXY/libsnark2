// MIT License
//
// Copyright (c) 2021 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include "algorithm/circuit_loader.h"
#include "base/gate_factory.h"
#include "base/two_party_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/logger.h"
#include "utility/bit_vector.h"
// #include "protocols/beavy/beavy_provider.cpp"
#include "wire/new_wire.h"
#include "utility/helpers.h"

#include "protocols/gmw/wire.h"
#include "protocols/gmw/gate.h"
#include "protocols/gmw/gmw_provider.h"
#include "utility/bit_vector.h"
#include "fss/aes.h"
// #include "protocols/gmw/gmw_provider.cpp"

namespace po = boost::program_options;
using namespace MOTION::proto::gmw;
using NewWire = MOTION::NewWire;
using WireVector = std::vector<std::shared_ptr<NewWire>>;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_repetitions;
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t pattern_size;
  std::uint64_t text_size;
  // std::uint64_t ring_size;
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  bool no_run = false;
  
  // New fields for secret sharing
  std::string pattern;
  std::string text;
  std::string role;
};

std::optional<Options> parse_program_options(int argc, char* argv[]) {
  Options options;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false),"produce help message")
    ("config-file", po::value<std::string>(), "config file containing options")
    ("my-id", po::value<std::size_t>()->required(), "my party id")
    ("party", po::value<std::vector<std::string>>()->multitoken(),
     "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
    ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false), "output data in JSON format")
    ("pattern", po::value<std::string>(), "pattern string for pattern holder")
    ("text", po::value<std::string>(), "text string for text holder")
    ("pattern-size", po::value<std::uint64_t>(), "expected pattern size for text holder")
    ("text-size", po::value<std::uint64_t>(), "expected text size for pattern holder")
    ("role", po::value<std::string>()->required(), "role: pattern_holder or text_holder")
    ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
    ("num-simd", po::value<std::size_t>()->default_value(1), "number of SIMD values")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
     "run a synchronization protocol before the online phase starts")
    ("no-run", po::bool_switch()->default_value(false), "just build the circuit, but not execute it")
    ;
  // clang-format on

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  bool help = vm["help"].as<bool>();
  if (help) {
    std::cerr << desc << "\n";
    return std::nullopt;
  }
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::store(po::parse_config_file(ifs, desc), vm);
  }
  try {
    po::notify(vm);
  } catch (std::exception& e) {
    std::cerr << "error:" << e.what() << "\n\n";
    std::cerr << desc << "\n";
    return std::nullopt;
  }

  options.my_id = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();

  options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
  options.boolean_protocol = MOTION::MPCProtocol::BooleanGMW;
  
  // Parse role and input strings
  options.role = vm["role"].as<std::string>();
  
  if (options.role == "pattern_holder") {
    if (!vm.count("pattern")) {
      std::cerr << "pattern_holder must provide --pattern\n";
      return std::nullopt;
    }
    options.pattern = vm["pattern"].as<std::string>();
    options.pattern_size = options.pattern.length();
    
    if (!vm.count("text-size")) {
      std::cerr << "pattern_holder must provide expected text size via --text-size\n";
      return std::nullopt;
    }
    options.text_size = vm["text-size"].as<std::uint64_t>();
  } else if (options.role == "text_holder") {
    if (!vm.count("text")) {
      std::cerr << "text_holder must provide --text\n";
      return std::nullopt;
    }
    options.text = vm["text"].as<std::string>();
    options.text_size = options.text.length();
    
    if (!vm.count("pattern-size")) {
      std::cerr << "text_holder must provide expected pattern size via --pattern-size\n";
      return std::nullopt;
    }
    options.pattern_size = vm["pattern-size"].as<std::uint64_t>();
  } else {
    std::cerr << "role must be either 'pattern_holder' or 'text_holder'\n";
    return std::nullopt;
  }
  
  if (options.pattern_size >= options.text_size) {
    std::cerr << "pattern size must be smaller than text size\n";
    return std::nullopt;
  }

  const auto parse_party_argument =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, {host, port}};
  };

  const std::vector<std::string> party_infos = vm["party"].as<std::vector<std::string>>();
  if (party_infos.size() != 2) {
    std::cerr << "expecting two --party options\n";
    return std::nullopt;
  }

  options.tcp_config.resize(2);
  std::size_t other_id = 2;

  const auto [id0, conn_info0] = parse_party_argument(party_infos[0]);
  const auto [id1, conn_info1] = parse_party_argument(party_infos[1]);
  if (id0 == id1) {
    std::cerr << "need party arguments for party 0 and 1\n";
    return std::nullopt;
  }
  options.tcp_config[id0] = conn_info0;
  options.tcp_config[id1] = conn_info1;

  return options;
}




std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
    const Options& options) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id, options.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
                                                                     helper.setup_connections());
}

std::vector<uint64_t> convert_to_binary(uint64_t x) {
    std::vector<uint64_t> res;
    for (uint64_t i = 0; i < 64; ++i) {
        if (x%2 == 1) res.push_back(1);
        else res.push_back(0);
        x /= 2;
    }
    return res;
}


// String processing namespace for pattern matching functionality
namespace StringProcessing {
    
  // Convert string to vector of uint8_t values (ASCII)
  std::vector<uint8_t> string_to_integers(const std::string& str) {
    std::vector<uint8_t> result;
    for (char c : str) {
      result.push_back(static_cast<uint8_t>(c));
    }
    return result;
  }
  
  // Break pattern into individual characters
  // Example: "HEL" -> ["H", "E", "L"]
  std::vector<std::string> break_pattern_into_chars(const std::string& pattern) {
    std::vector<std::string> result;
    for (char c : pattern) {
      result.push_back(std::string(1, c));
    }
    return result;
  }
  
  // Create sliding window substrings from text
  // Example: text="HELLO", pattern_size=3 -> [["H","E","L"], ["E","L","L"], ["L","L","O"]]
  std::vector<std::vector<std::string>> create_sliding_windows(const std::string& text, size_t pattern_size) {
    std::vector<std::vector<std::string>> windows;
    
    if (text.length() < pattern_size) {
      return windows; // Return empty if text is shorter than pattern
    }
    
    for (size_t i = 0; i <= text.length() - pattern_size; ++i) {
      std::vector<std::string> window;
      for (size_t j = 0; j < pattern_size; ++j) {
        window.push_back(std::string(1, text[i + j]));
      }
      windows.push_back(window);
    }
    
    return windows;
  }
  
  // Convert pattern characters to uint8_t values for secret sharing
  std::vector<uint8_t> pattern_chars_to_integers(const std::vector<std::string>& pattern_chars) {
    std::vector<uint8_t> result;
    for (const auto& char_str : pattern_chars) {
      if (!char_str.empty()) {
        result.push_back(static_cast<uint8_t>(char_str[0]));
      }
    }
    return result;
  }
  
  // Convert sliding window substrings to uint8_t values for secret sharing
  std::vector<std::vector<uint8_t>> sliding_windows_to_integers(const std::vector<std::vector<std::string>>& windows) {
    std::vector<std::vector<uint8_t>> result;
    result.reserve(windows.size());

    for (const auto& window : windows) {
      result.push_back(pattern_chars_to_integers(window)); 
    }

    return result;
  }

  // Print pattern breakdown for debugging
  template <typename T>
  void print_vector(const std::vector<T>& input_vector) {
    std::cout << "[";
    for (size_t i = 0; i < input_vector.size(); ++i) {
      std::cout << "\"" << input_vector[i] << "\"";
      if (i < input_vector.size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
  }
  
  // Print sliding windows for debugging
  template <typename T>
  void print_nested_vector(const std::vector<std::vector<T>>& windows) {
    std::cout << "[";
    for (size_t i = 0; i < windows.size(); ++i) {
        std::cout << "[";
        for (size_t j = 0; j < windows[i].size(); ++j) {
            std::cout << "\"" << windows[i][j] << "\"";
            if (j < windows[i].size() - 1) std::cout << ", ";
        }
        std::cout << "]";
        // if (i < windows.size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
  }

  // Concat a vector of type T into string
  template <typename T>
  std::string concat_vector(const std::vector<T>& target_vector) {
    std::string final_result {};

    for (T el : target_vector) {
      final_result += std::to_string(el);
    }

    return final_result;
  }

  std::vector<uint8_t> hash_difference_vector(const std::vector<uint8_t>& differences) {
    const size_t hash_size = 32;  // 256 bits output
    const size_t required_input_size = 16;  // AES requires exactly 16 bytes input
    
    // Create 16-byte input buffer (pad with zeros)
    uint8_t input_buffer[required_input_size] = {0};  // Initialize all to 0
    
    // Copy your differences (copy min of available vs required)
    size_t copy_size = std::min(differences.size(), required_input_size);
    std::copy(differences.begin(), differences.begin() + copy_size, input_buffer);
    
    // If differences is larger than 16 bytes, XOR the excess into the buffer
    for (size_t i = required_input_size; i < differences.size(); ++i) {
        input_buffer[i % required_input_size] ^= differences[i];
    }
    
    uint8_t hash_output[hash_size];
    
    // Now input is exactly 16 bytes!
    G_tiny(input_buffer, hash_output, required_input_size, hash_size);
    
    return std::vector<uint8_t>(hash_output, hash_output + hash_size);
  }

  // String processing for pattern holder
  auto pattern_holder(const std::string& pattern) {
    std::cout << "Pattern: \"" << pattern << "\"" << std::endl;

    std::vector<std::string> pattern_vector = break_pattern_into_chars(pattern);
    std:: cout << "Broken down to Char: \n";
    print_vector(pattern_vector);

    std::vector<uint8_t> pattern_ascii_vector = pattern_chars_to_integers(pattern_vector);
     std:: cout << "Broken down to ASCII: \n";
    print_vector(pattern_ascii_vector);

    return pattern_ascii_vector;
  }

  // String processing for text holder
  auto text_holder(const std::string& text, size_t pattern_size) {
    std::cout << "Original text: \"" << text << "\", pattern_size: " << pattern_size << std::endl;

    std::vector<std::vector<std::string>> text_vector = create_sliding_windows(text, pattern_size);
    std:: cout << "Broken down to Char: \n";
    print_nested_vector(text_vector);

    std::vector<std::vector<uint8_t>> text_ascii_vector = sliding_windows_to_integers(text_vector);
    std:: cout << "Broken down to ASCII: \n";
    print_nested_vector(text_ascii_vector);

    return text_ascii_vector;
  }
}



// Structure to hold individual character wires and promises for secret sharing
struct SecretSharedData {
    // PATTERN DATA: Individual secret sharing for each pattern character
    // - Each pattern character gets its own wire and promise
    // - For pattern "HEL": 3 wires (one for 'H', 'E', 'L')
    
    std::vector<MOTION::WireVector> pattern_char_wires;
    // ↳ Wire containers that hold secret shares after circuit execution
    // ↳ pattern_char_wires[0] = wire holding share of 1st character ('H')
    // ↳ Each wire stores one uint8_t share value (e.g., 165)
    // ↳ MOTION::WireVector = std::vector<std::shared_ptr<NewWire>> (size 1 for single values)
    
    std::vector<ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint8_t>>> pattern_char_promises;
    // ↳ Input mechanisms where actual ASCII values are provided
    // ↳ pattern_char_promises[0].set_value({72}) feeds 'H' into secret sharing
    // ↳ Promise fulfillment triggers generation of secret shares
    // ↳ MOTION::IntegerValues<uint8_t> = std::vector<uint8_t> (size 1 for single values)
    
    // TEXT DATA: Individual secret sharing for each character in each sliding window
    // - For text "HELLO" with pattern_size=3: 3 windows, each with 3 characters
    // - Window 1: ['H','E','L'], Window 2: ['E','L','L'], Window 3: ['L','L','O']
    
    std::vector<std::vector<MOTION::WireVector>> text_window_wires; 
    // ↳ 2D structure: text_window_wires[window][position]
    // ↳ text_window_wires[0][0] = wire for 1st character of 1st window ('H')
    // ↳ text_window_wires[1][2] = wire for 3rd character of 2nd window ('L')
    
    std::vector<std::vector<ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint8_t>>>> text_window_promises;
    // ↳ 2D structure: text_window_promises[window][position]
    // ↳ text_window_promises[0][0].set_value({72}) feeds 'H' from window 1
    // ↳ Each promise provides one ASCII character to the secret sharing process
};

// Create input wires with individual character secret sharing
// This function sets up the MPC input gates for both parties based on their roles
auto create_circuit_inputs(const Options& options, MOTION::TwoPartyBackend& backend) {
  auto& gate_factory = backend.get_gate_factory(options.arithmetic_protocol);
  
  SecretSharedData shared_data;
  size_t num_windows = options.text_size - options.pattern_size + 1;  // Number of sliding windows
  
  if (options.role == "pattern_holder") {
    // PATTERN HOLDER: Creates input gates for their own pattern, receives gates for other's text
    
    // Create individual input gates for each pattern character (OWN DATA)
    // Each gate produces a [promise, wire] pair for one character
    shared_data.pattern_char_wires.resize(options.pattern_size);
    shared_data.pattern_char_promises.resize(options.pattern_size);
    
    for (size_t i = 0; i < options.pattern_size; ++i) {
      // make_arithmetic_8_input_gate_my() creates an input gate for data WE own
      // Returns: std::pair<Promise, WireVector>
      // - Promise (first): Input mechanism to provide our secret ASCII value
      // - WireVector (second): Output wire that will contain our share of the value
      auto pattern_pair = gate_factory.make_arithmetic_8_input_gate_my(options.my_id, 1);
      shared_data.pattern_char_promises[i] = std::move(pattern_pair.first);   // Input side
      shared_data.pattern_char_wires[i] = std::move(pattern_pair.second);     // Output side
    }
    
    // Create receiver gates for text character shares from the other party (OTHER'S DATA)
    shared_data.text_window_wires.resize(num_windows);
    for (size_t window = 0; window < num_windows; ++window) {
      shared_data.text_window_wires[window].resize(options.pattern_size);
      for (size_t pos = 0; pos < options.pattern_size; ++pos) {
        // make_arithmetic_8_input_gate_other() creates a receiver gate for data THEY own
        // Returns: WireVector (no promise since we don't provide the input)
        // This wire will receive the share of the other party's character
        shared_data.text_window_wires[window][pos] = 
            gate_factory.make_arithmetic_8_input_gate_other(1 - options.my_id, 1);
      }
    }
    
  } else if (options.role == "text_holder") {
    // TEXT HOLDER: Receives gates for other's pattern, creates input gates for their own text
    
    // Create receiver gates for pattern character shares from the other party (OTHER'S DATA)
    shared_data.pattern_char_wires.resize(options.pattern_size);
    for (size_t i = 0; i < options.pattern_size; ++i) {
      // Receive shares of pattern holder's characters
      shared_data.pattern_char_wires[i] = 
          gate_factory.make_arithmetic_8_input_gate_other(1 - options.my_id, 1);
    }
    
    // Create individual input gates for each text character in each window (OWN DATA)
    shared_data.text_window_wires.resize(num_windows);
    shared_data.text_window_promises.resize(num_windows);
    
    for (size_t window = 0; window < num_windows; ++window) {
      shared_data.text_window_wires[window].resize(options.pattern_size);
      shared_data.text_window_promises[window].resize(options.pattern_size);
      
      for (size_t pos = 0; pos < options.pattern_size; ++pos) {
        // Create input gate for our text character at this window position
        auto text_pair = gate_factory.make_arithmetic_8_input_gate_my(options.my_id, 1);
        shared_data.text_window_promises[window][pos] = std::move(text_pair.first);  // Input side
        shared_data.text_window_wires[window][pos] = std::move(text_pair.second);    // Output side
      }
    }
  }
  
  return shared_data;
}

// Function to extract and display share values with both kept and sent shares
// This function demonstrates how to access the actual cryptographic shares after circuit execution
void print_share_details(const Options& options, const SecretSharedData& shared_data, 
                        const std::vector<uint8_t>* pattern_values = nullptr,
                        const std::vector<std::vector<uint8_t>>* text_values = nullptr) {
  
  size_t num_windows = options.text_size - options.pattern_size + 1;
  std::cout << "\n\n\n" << std::endl;
  if (options.role == "pattern_holder") {
    std::cout << "=== MY PATTERN SHARES (Owned) ===" << std::endl;
    // SHARE EXTRACTION: Access the actual secret shares from owned pattern wires
    for (size_t i = 0; i < options.pattern_size; ++i) {
      // WIRE ACCESS: Cast generic NewWire to specific ArithmeticGMWWire to access share data
      // shared_data.pattern_char_wires[i][0] gets the first (and only) wire in the vector
      auto gmw_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.pattern_char_wires[i][0]);
      
      // SHARE EXTRACTION: Get the actual share vector and extract the single value [0]
      // share_values[0] contains the uint8_t share this party holds
      auto share_values = gmw_wire->get_share();
      
      char original_char = static_cast<char>((*pattern_values)[i]);
      uint8_t original_value = (*pattern_values)[i];
      uint8_t my_share = share_values[0];  // The cryptographic share we keep
      
      // SENT SHARE CALCULATION: In GMW, sent_share + my_share = original_value (mod 2^8)
      // This shows what we sent to the other party to complete the secret sharing
      uint8_t sent_share = original_value - my_share;  // What we sent to the other party
      
      std::cout << "P[" << i << "] = '" << original_char << "' (" << (int)original_value 
                << "): My share = " << (int)my_share << ", Sent share = " << (int)sent_share << std::endl;
    }
    
    std::cout << "\n=== RECEIVED TEXT SHARES ===" << std::endl;
    // RECEIVED SHARES: Display shares we received from the text holder
    for (size_t window = 0; window < num_windows; ++window) {
      std::cout << "Window T" << (window + 1) << ":" << std::endl;
      for (size_t pos = 0; pos < options.pattern_size; ++pos) {
        // WIRE ACCESS: Get the wire that received the other party's text character share
        auto gmw_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.text_window_wires[window][pos][0]);
        auto share_values = gmw_wire->get_share();
        
        // RECEIVED SHARE: This is the share the text holder sent us
        // We cannot reconstruct the original value since we only have one share
        std::cout << "  T" << (window + 1) << "[" << pos << "]: Received share = " 
                  << (int)share_values[0] << std::endl;
      }
    }
    
  } else if (options.role == "text_holder") {
    std::cout << "=== RECEIVED PATTERN SHARES ===" << std::endl;
    // RECEIVED SHARES: Display shares we received from the pattern holder
    for (size_t i = 0; i < options.pattern_size; ++i) {
      // WIRE ACCESS: Get the wire that received the other party's pattern character share
      auto gmw_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.pattern_char_wires[i][0]);
      auto share_values = gmw_wire->get_share();
      
      // RECEIVED SHARE: This is the share the pattern holder sent us
      // We cannot reconstruct the original character since we only have one share
      std::cout << "P[" << i << "]: Received share = " << (int)share_values[0] << std::endl;
    }
    
    std::cout << "\n=== MY TEXT SHARES (Owned) ===" << std::endl;
    // SHARE EXTRACTION: Access the actual secret shares from owned text wires  
    for (size_t window = 0; window < num_windows; ++window) {
      std::cout << "Window T" << (window + 1) << ":" << std::endl;
      for (size_t pos = 0; pos < options.pattern_size; ++pos) {
        // WIRE ACCESS: Cast and access the share data for this window position
        auto gmw_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.text_window_wires[window][pos][0]);
        auto share_values = gmw_wire->get_share();
        
        char original_char = static_cast<char>((*text_values)[window][pos]);
        uint8_t original_value = (*text_values)[window][pos];
        uint8_t my_share = share_values[0];  // The cryptographic share we keep
        
        // SENT SHARE CALCULATION: Show what we sent to complete the secret sharing
        uint8_t sent_share = original_value - my_share;  // What we sent to the other party
        
        std::cout << "  T" << (window + 1) << "[" << pos << "] = '" << original_char 
                  << "' (" << (int)original_value << "): My share = " << (int)my_share 
                  << ", Sent share = " << (int)sent_share << std::endl;
      }
    }
  }
}







std::vector<std::vector<uint8_t>> compute_difference_concat_hash(const Options& options, const SecretSharedData& shared_data) {

  std::cout << "\n\n=== Computing differences ===" << std::endl;
  size_t num_windows = options.text_size - options.pattern_size + 1;
  std::vector<std::vector<uint8_t>> window_hashes(num_windows);

   for (size_t window = 0; window < num_windows; ++window) {
    std::vector<uint8_t> curr_window_share_difference(options.pattern_size);
    std::cout << "Window T" << (window + 1) << ":" << std::endl;

    for (size_t pos = 0; pos < options.pattern_size; ++pos) {

      // Retrieve self kept pattern shares
      auto gmw_pattern_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.pattern_char_wires[pos][0]);
      uint8_t pattern_char_share = gmw_pattern_wire->get_share()[0];

      // Retrieve other party's text character share
      auto gmw_text_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_data.text_window_wires[window][pos][0]);
      uint8_t text_char_share = gmw_text_wire->get_share()[0];
      
      std::cout << "  T" << (window + 1) << "[" << pos << "] - P[" << pos << "]: " << (int)text_char_share << " - " << (int)pattern_char_share << "\n";
      uint8_t share_difference = text_char_share - pattern_char_share;
      std::cout << "  Difference: " << (int)share_difference << '\n';

      if (options.role == "pattern_holder") {
        uint8_t negated = -share_difference;
        std::cout << "  Negated: " << (int)negated << "\n";
        curr_window_share_difference[pos] = negated;
        
      } else {
        curr_window_share_difference[pos] = share_difference;
      }
      std::cout << '\n';
    }


    // NEW: Hash the difference vector
    std::vector<uint8_t> hash_result = StringProcessing::hash_difference_vector(curr_window_share_difference);
    window_hashes[window] = hash_result;  // Store for potential future secret sharing
    
    // Display results
    std::string concatenated_shares = StringProcessing::concat_vector(curr_window_share_difference);
    std::string hash_string = StringProcessing::concat_vector(hash_result);

    std::cout << "\n  Concatenated: " << concatenated_shares << std::endl;
    std::cout << "  Hash (256-bit): " << hash_string << std::endl;
    std::cout << "  Full hash size: " << hash_result.size() << " bytes\n\n\n";
  }

  return window_hashes;
}





std::vector<std::vector<uint8_t>> run_pattern_text_circuit(const Options& options, MOTION::TwoPartyBackend& backend, const SecretSharedData& shared_data,
                                                          const std::vector<uint8_t>* pattern_values = nullptr,
                                                          const std::vector<std::vector<uint8_t>>* text_values = nullptr) {
  
  std::vector<std::vector<uint8_t>> hashes {};
  if (options.no_run) {
    return hashes;
  }

  // Execute the circuit to complete the secret sharing process
  backend.run();
  
  if (!options.json) {
    std::cout << "\n=== Circuit Execution Summary ===" << std::endl;
    std::cout << "Individual character secret sharing circuit executed successfully!" << std::endl;
    
    size_t num_windows = options.text_size - options.pattern_size + 1;
    size_t total_pattern_chars = options.pattern_size;
    size_t total_text_chars = num_windows * options.pattern_size;
    
    std::cout << "Pattern: " << total_pattern_chars << " individual character secrets shared" << std::endl;
    std::cout << "Text: " << total_text_chars << " individual character secrets shared across " 
              << num_windows << " windows" << std::endl;
    std::cout << "Total individual secret sharings: " << (total_pattern_chars + total_text_chars) << std::endl;
    
    // Display actual share values after circuit execution
    print_share_details(options, shared_data, pattern_values, text_values);
    hashes = compute_difference_concat_hash(options, shared_data);


    std::cout << "\n\n\n=== All Hashes ===" << std::endl;
    for (size_t window = 0; window < hashes.size(); ++window) {
      std::cout << "  Hash " << window << ": " << StringProcessing::concat_vector(hashes[window]) << std::endl;
    } 
  }

  return hashes;
}




void print_stats(const Options& options,
                 const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
                 const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
  if (options.json) {
    auto obj = MOTION::Statistics::to_json("exact_pm", run_time_stats, comm_stats);
    obj.emplace("party_id", options.my_id);
    obj.emplace("threads", options.threads);
    obj.emplace("sync_between_setup_and_online", options.sync_between_setup_and_online);
    std::cout << obj << "\n";
  } else {
    std::cout << MOTION::Statistics::print_stats("Exact Pattern Matching", run_time_stats,
                                                 comm_stats);
  }
}



struct SecretShareHash {
    // Each window gets one hash to secret share
    std::vector<std::vector<MOTION::WireVector>> my_hash_wires;  
    std::vector<std::vector<ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<uint8_t>>>> my_hash_promises;
    
    // For receiving other party's hash shares
    std::vector<std::vector<MOTION::WireVector>> other_hash_wires;
};

struct HAMDPFCircuit {
    // HAM output wires (Hamming distances for each byte of each hash pair)
    std::vector<std::vector<MOTION::WireVector>> ham_outputs;  // [hash_pair][byte_pos]
    
    // DPF output wires (equality check results for each byte of each hash pair)  
    std::vector<std::vector<MOTION::WireVector>> dpf_outputs;  // [hash_pair][byte_pos]
    
    // Final results: one wire per hash pair indicating if hashes are equal
    std::vector<MOTION::WireVector> final_results;  // [hash_pair]
};


auto create_hash_ss_circuit_inputs(const Options& options, MOTION::TwoPartyBackend& backend, std::vector<std::vector<uint8_t>>& hashes) {
  auto& gate_factory = backend.get_gate_factory(options.arithmetic_protocol);
  
  SecretShareHash shared_hash;
  size_t number_of_hashes = hashes.size();
  
  shared_hash.my_hash_wires.resize(number_of_hashes);
  shared_hash.my_hash_promises.resize(number_of_hashes);
  shared_hash.other_hash_wires.resize(number_of_hashes);

  for (size_t hash_no = 0; hash_no < number_of_hashes; ++hash_no) {
    size_t hash_size = hashes[hash_no].size();
    shared_hash.my_hash_wires[hash_no].resize(hash_size);
    shared_hash.my_hash_promises[hash_no].resize(hash_size);
    shared_hash.other_hash_wires[hash_no].resize(hash_size);
    
    for (size_t j = 0; j < hash_size; ++j) {
      // COMPLEMENTARY GATE ORDER based on party ID
      if (options.my_id == 0) {
        // Party 0: Create send gate first, then receive gate
        auto pair = gate_factory.make_arithmetic_8_input_gate_my(options.my_id, 1);
        shared_hash.my_hash_promises[hash_no][j] = std::move(pair.first);
        shared_hash.my_hash_wires[hash_no][j] = std::move(pair.second);
        
        shared_hash.other_hash_wires[hash_no][j] = gate_factory.make_arithmetic_8_input_gate_other(1 - options.my_id, 1);
      } else {
        // Party 1: Create receive gate first, then send gate  
        shared_hash.other_hash_wires[hash_no][j] = gate_factory.make_arithmetic_8_input_gate_other(1 - options.my_id, 1);
        
        auto pair = gate_factory.make_arithmetic_8_input_gate_my(options.my_id, 1);
        shared_hash.my_hash_promises[hash_no][j] = std::move(pair.first);
        shared_hash.my_hash_wires[hash_no][j] = std::move(pair.second);
      }
    }
  }

  return shared_hash;
}


void print_secret_shared_hash_details(const Options& options, const SecretShareHash& shared_hash, const std::vector<std::vector<uint8_t>>& original_hashes) {
  std::cout << "\n=== HASH SECRET SHARING DETAILS ===" << std::endl;
  size_t number_of_hashes = original_hashes.size();

  for (size_t hash_no = 0; hash_no < number_of_hashes; ++hash_no) {
    std::cout << "Hash " << hash_no << ":" << std::endl;
    size_t hash_size = original_hashes[hash_no].size();

    for (size_t byte_pos = 0; byte_pos < hash_size; ++byte_pos) {
      auto gmw_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_hash.my_hash_wires[hash_no][byte_pos][0]);
      auto share_values = gmw_wire->get_share();

      auto gmw_other_wire = std::static_pointer_cast<ArithmeticGMWWire<uint8_t>>(shared_hash.other_hash_wires[hash_no][byte_pos][0]);
      auto received_values = gmw_other_wire->get_share();

      uint8_t original_byte = original_hashes[hash_no][byte_pos];
      uint8_t my_share = share_values[0];
      uint8_t sent_share = original_byte - my_share;
      uint8_t received_share = received_values[0];
      
      
      std::cout << "  Byte[" << byte_pos << "] = " << (int)original_byte << ": \n";
      std::cout << "\tMy share = " << (int)my_share << '\n'
                << "\tSent share = " << (int)sent_share << '\n'
                << "\tReceived share = " << (int)received_share << std::endl;
    }
  }
}


void run_secret_share_hashes_circuit(const Options& options, MOTION::TwoPartyBackend& backend, const SecretShareHash& shared_hash, const std::vector<std::vector<uint8_t>>& original_hashes) {

  if (options.no_run) {
    return;
  }

  // Execute the circuit to complete the secret sharing process
  backend.run();

  if (!options.json) {
    print_secret_shared_hash_details(options, shared_hash, original_hashes);
  }
}

HAMDPFCircuit create_ham_dpf_circuit(const Options& options, MOTION::TwoPartyBackend& backend, const SecretShareHash& shared_hash) {
  auto& gate_factory = backend.get_gate_factory(options.arithmetic_protocol);
  
  HAMDPFCircuit ham_dpf_circuit;
  size_t num_hashes = shared_hash.my_hash_wires.size();
  size_t hash_size = 32;  // 256-bit hash = 32 bytes
  
  std::cout << "\n=== Creating HAM+DPF Circuit for " << num_hashes << " hash pairs ===" << std::endl;
  
  // Initialize circuit structures
  ham_dpf_circuit.ham_outputs.resize(num_hashes);
  ham_dpf_circuit.dpf_outputs.resize(num_hashes);
  ham_dpf_circuit.final_results.resize(num_hashes);
  
  // Process each hash pair (pairwise comparison: h0==h0', h1==h1', etc.)
  for (size_t hash_no = 0; hash_no < num_hashes; ++hash_no) {
    std::cout << "Processing hash pair " << hash_no << ":" << std::endl;
    
    ham_dpf_circuit.ham_outputs[hash_no].resize(hash_size);
    ham_dpf_circuit.dpf_outputs[hash_no].resize(hash_size);
    
    // For each byte in the hash
    for (size_t byte_pos = 0; byte_pos < hash_size; ++byte_pos) {
      
      // Step 2: Calculate difference SS(h0) - SS(h1) using NEG + ADD gates
      // NEG gate: -SS(h1) 
      auto neg_other_hash = gate_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::NEG, 
                                                         shared_hash.other_hash_wires[hash_no][byte_pos]);
      
      // ADD gate: SS(h0) + (-SS(h1)) = SS(h0 - h1)
      auto hash_difference = gate_factory.make_binary_gate(ENCRYPTO::PrimitiveOperationType::ADD,
                                                          shared_hash.my_hash_wires[hash_no][byte_pos],
                                                          neg_other_hash);
      
      // Steps 3-5: HAM gate (generates random mask, publishes a+r, computes Hamming distance)
      auto hamming_distance = gate_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, 
                                                          hash_difference);
      ham_dpf_circuit.ham_outputs[hash_no][byte_pos] = hamming_distance;
      
      // Step 6: DPF gate (equality check: HD==0?)
      auto is_equal = gate_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::DPF,
                                                  hamming_distance);
      ham_dpf_circuit.dpf_outputs[hash_no][byte_pos] = is_equal;
      
      // std::cout << "  Byte " << byte_pos << ": NEG -> ADD -> HAM -> DPF" << std::endl;
    }
    
    // Combine all byte equality results for this hash pair using AND gates
    // All bytes must be equal for the hashes to be equal
    auto combined_result = ham_dpf_circuit.dpf_outputs[hash_no][0];  // Start with first byte
    
    for (size_t byte_pos = 1; byte_pos < hash_size; ++byte_pos) {
      combined_result = gate_factory.make_binary_gate(ENCRYPTO::PrimitiveOperationType::AND,
                                                     combined_result,
                                                     ham_dpf_circuit.dpf_outputs[hash_no][byte_pos]);
    }
    
    ham_dpf_circuit.final_results[hash_no] = combined_result;
    std::cout << "  Final result: AND of all " << hash_size << " byte equality checks" << std::endl;
  }
  
  std::cout << "HAM+DPF circuit creation complete!" << std::endl;
  return ham_dpf_circuit;
}

void run_ham_dpf_circuit(const Options& options, MOTION::TwoPartyBackend& backend, const HAMDPFCircuit& ham_dpf_circuit) {
  if (options.no_run) {
    return;
  }

  std::cout << "\n=== Executing HAM+DPF Circuit ===" << std::endl;
  
  // Execute the HAM+DPF circuit
  backend.run();
  
  if (!options.json) {
    std::cout << "\n=== HAM+DPF Results ===" << std::endl;
    
    // Display results for each hash pair
    for (size_t hash_no = 0; hash_no < ham_dpf_circuit.final_results.size(); ++hash_no) {
      // Extract the final equality result
      auto result_wire = std::static_pointer_cast<BooleanGMWWire>(ham_dpf_circuit.final_results[hash_no][0]);
      auto result_bits = result_wire->get_share();
      
      bool is_equal = result_bits.Get(0);  // Get the boolean result
      
      std::cout << "Hash pair " << hash_no << ": " 
                << (is_equal ? "EQUAL ✓" : "NOT EQUAL ✗") << std::endl;
    }
    
    // Overall pattern matching result
    bool pattern_found = false;
    for (size_t hash_no = 0; hash_no < ham_dpf_circuit.final_results.size(); ++hash_no) {
      auto result_wire = std::static_pointer_cast<BooleanGMWWire>(ham_dpf_circuit.final_results[hash_no][0]);
      auto result_bits = result_wire->get_share();
      
      if (result_bits.Get(0)) {
        pattern_found = true;
        break;
      }
    }
    
    std::cout << "\n🎯 FINAL PATTERN MATCHING RESULT: " 
              << (pattern_found ? "PATTERN FOUND! 🎉" : "PATTERN NOT FOUND 😞") << std::endl;
  }
}


auto make_dpf_in_wire(const Options& options) {
  
  auto num_simd = (options.text_size - options.pattern_size + 1);
  auto num_wires = options.pattern_size;

  auto wire = std::make_shared<ArithmeticGMWWire<uint8_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;
  std::vector<uint8_t> x(num_simd, 2*num_wires);

  wire->get_share() = x;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}

auto make_ham_in_wire(const Options& options) {
  
  auto num_simd = (options.text_size - options.pattern_size + 1);

  auto wire = std::make_shared<ArithmeticGMWWire<uint32_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;
  std::vector<uint32_t> x(num_simd, 1);

  wire->get_share() = x;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}


void run_circuit(const Options& options, MOTION::TwoPartyBackend& backend, WireVector in1, WireVector in2) {

  if (options.no_run) {
    return;
  }

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;
  auto& gate_factory_arith = backend.get_gate_factory(arithmetic_protocol);
  auto& gate_factory_bool = backend.get_gate_factory(boolean_protocol);

  auto output1 = gate_factory_bool.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, in1);
  auto output = gate_factory_arith.make_unary_gate(
    ENCRYPTO::PrimitiveOperationType::DPF, in2);
  
  backend.run();

}


void print_ham_dpf_results(const Options& options, const HAMDPFCircuit& ham_dpf_circuit) {
  if (options.no_run || options.json) {
    return;
  }

  std::cout << "\n=== HAM+DPF Results ===" << std::endl;

  // Display results for each hash pair
  for (size_t hash_no = 0; hash_no < ham_dpf_circuit.final_results.size(); ++hash_no) {
    auto result_wire = std::static_pointer_cast<BooleanGMWWire>(ham_dpf_circuit.final_results[hash_no][0]);
    auto result_bits = result_wire->get_share();

    bool is_equal = result_bits.Get(0);

    std::cout << "Hash pair " << hash_no << ": "
              << (is_equal ? "EQUAL(666)" : "NOT EQUAL(die)") << std::endl;
  }

  bool pattern_found = false;
  for (size_t hash_no = 0; hash_no < ham_dpf_circuit.final_results.size(); ++hash_no) {
    auto result_wire = std::static_pointer_cast<BooleanGMWWire>(ham_dpf_circuit.final_results[hash_no][0]);
    auto result_bits = result_wire->get_share();
    if (result_bits.Get(0)) {
      pattern_found = true;
      break;
    }
  }

  std::cout << "\n🎯 FINAL PATTERN MATCHING RESULT: "
            << (pattern_found ? "PATTERN FOUND! 🎉" : "PATTERN NOT FOUND 😞") << std::endl;
}


int main(int argc, char* argv[]) {
  auto options = parse_program_options(argc, argv);
  std::vector<std::vector<uint8_t>> hashes;
  
  if (!options.has_value()) {
    return EXIT_FAILURE;
  }
  
  // ========== PHASE 1: CHARACTER SECRET SHARING ==========
  try {
    auto comm_layer = setup_communication(*options);
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
    
    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      MOTION::TwoPartyBackend backend(*comm_layer, options->threads,
                                      options->sync_between_setup_and_online, logger);

      // Character sharing logic (unchanged)
      auto shared_data = create_circuit_inputs(*options, backend);
      
      // Provide actual input values based on role using individual character sharing
      std::vector<uint8_t> pattern_values;
      std::vector<std::vector<uint8_t>> text_values;
      
      
      if (options->role == "pattern_holder") {
        // PATTERN HOLDER: Process and provide pattern characters for secret sharing
        pattern_values = StringProcessing::pattern_holder(options->pattern);
        
        // PROMISE FULFILLMENT: Feed actual ASCII values into the secret sharing mechanism
        // Each promise.set_value() triggers the generation of secret shares
        for (size_t i = 0; i < pattern_values.size(); ++i) {
          // Wrap single ASCII value in vector (SIMD size 1)
          std::vector<uint8_t> single_char = {pattern_values[i]};
          
          // CRITICAL: This triggers secret sharing for character i
          // The framework will:
          // 1. Generate a random share for this party
          // 2. Calculate and send complementary share to other party
          // 3. Store this party's share in the corresponding wire
          shared_data.pattern_char_promises[i].set_value(single_char);
          
          // Example: For 'H' (ASCII 72):
          // - Framework generates random value: 123
          // - Calculates sent share: 72 - 123 = 205 (mod 2^8)  
          // - Stores 123 in pattern_char_wires[i]
          // - Sends 205 to text holder
        }
        
        // Run the circuit with pattern values
        hashes = run_pattern_text_circuit(*options, backend, shared_data, &pattern_values, nullptr);
        
      } else if (options->role == "text_holder") {
        // TEXT HOLDER: Process and provide text characters for secret sharing
        text_values = StringProcessing::text_holder(options->text, options->pattern_size);
        
        // PROMISE FULFILLMENT: Feed actual ASCII values for each character in each window
        for (size_t window = 0; window < text_values.size(); ++window) {
          for (size_t pos = 0; pos < text_values[window].size(); ++pos) {
            // Wrap single ASCII value in vector (SIMD size 1)
            std::vector<uint8_t> single_char = {text_values[window][pos]};
            
            // CRITICAL: This triggers secret sharing for this window position
            // Same process as pattern holder but for text characters
            shared_data.text_window_promises[window][pos].set_value(single_char);
            
            // Example: For 'E' (ASCII 69) in window 1, position 1:
            // - Framework generates random value: 87
            // - Calculates sent share: 69 - 87 = 238 (mod 2^8)
            // - Stores 87 in text_window_wires[1][1]  
            // - Sends 238 to pattern holder
          }
        }
        
        // Run the circuit with text values
        hashes = run_pattern_text_circuit(*options, backend, shared_data, nullptr, &text_values);
      }
      
      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }
    
    // CRITICAL: Proper cleanup of Phase 1
    comm_layer->sync();                    // Final synchronization
    comm_layer->shutdown();                // Shutdown connections
    comm_layer.reset();                    // Release communication layer
    
    std::cout << "\n=== Phase 1 Complete - Character sharing finished ===\n" << std::endl;
    print_stats(*options, run_time_stats, comm_stats);
    
  } catch (std::runtime_error& e) {
    std::cerr << "ERROR in Phase 1: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

    // ========== PHASE TRANSITION ==========
  std::cout << "\n=== Starting Phase 2 & 3 (shared backend) ===\n" << std::endl;
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  try {
    auto comm_layer = setup_communication(*options);
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;

    for (std::size_t rep = 0; rep < options->num_repetitions; ++rep) {
      // Dùng CHUNG backend cho Phase 2 + Phase 3
      MOTION::TwoPartyBackend backend(*comm_layer, options->threads,
                                      options->sync_between_setup_and_online, logger);

      // ---------- PHASE 2: HASH SECRET SHARING (build circuit & set input) ----------
      std::cout << "\n=== Phase 2 - Hash secret sharing (build only) ===\n" << std::endl;

      SecretShareHash shared_hashes = create_hash_ss_circuit_inputs(*options, backend, hashes);

      // Set input for promises (hash bytes)
      for (size_t h = 0; h < hashes.size(); ++h) {
        for (size_t b = 0; b < hashes[h].size(); ++b) {
          shared_hashes.my_hash_promises[h][b].set_value({hashes[h][b]});
        }
      }

      // ---------- PHASE 3: HAM+DPF PATTERN MATCHING (build circuit) ----------
      std::cout << "\n=== Phase 3 - HAM+DPF Pattern Matching (build only) ===\n" << std::endl;

      HAMDPFCircuit ham_dpf_circuit = create_ham_dpf_circuit(*options, backend, shared_hashes);

      // ---------- Run 2 PHASE (run backend one time) ----------
      if (!options->no_run) {
        backend.run();
      }

      // ---------- AFTER RUN: PRINT RESULTS / DEBUG ----------
      if (!options->json && !options->no_run) {
        // Phase 2: hash shares
        print_secret_shared_hash_details(*options, shared_hashes, hashes);

        // Phase 3: Print HAM+DPF
        print_ham_dpf_results(*options, ham_dpf_circuit);
      }

      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }

    comm_layer->shutdown();
    print_stats(*options, run_time_stats, comm_stats);

    std::cout << "\n🎉 EXACT PATTERN MATCHING COMPLETE! 🎉" << std::endl;

  } catch (std::runtime_error& e) {
    std::cerr << "ERROR in Phase 2/3: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
