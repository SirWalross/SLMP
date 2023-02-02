#include <iostream>

#include "slmp.h"

int main(void) {
    SLMP slmp("192.168.3.39", 5007, SLMP::NetworkNumber::A, SLMP::StationNumber::A, SLMP::DestinationModule::CPU,
              SLMP::DestinationStation::A);
    slmp.connect();
    std::array<uint16_t, 4> data{};
    slmp.read_request(SLMP::Device::M, SLMP::Subcommand::Bit, 100, data);
    slmp.read_request(SLMP::Device::M, SLMP::Subcommand::Bit, 100, data);
    // std::array<uint8_t, 4> write_data{0, 1, 0, 1};
    // slmp.write_request<decltype(write_data)::value_type, SLMP::Subcommand::Bit>(SLMP::Device::M, 100, write_data);

    // std::array<std::string, 2> label_names{"LabelW1", "LabelW2"};
    // std::array<uint32_t, 2> label_data{9, 8};
    //  slmp.label_write_request(label_names, label_data);
    // slmp.label_read_request(label_names);
}