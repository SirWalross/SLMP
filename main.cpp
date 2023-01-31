#include <iostream>

#include "slmp.h"

int main(void) {
    SLMP slmp("192.168.3.39", 5007);
     slmp.read_request(SLMP::Device::D, SLMP::Subcommand::Word, 1000, 8);
     std::array<float, 2> write_data{1.0, 3.0};
     slmp.write_request<decltype(write_data)::value_type, SLMP::Subcommand::Word>(SLMP::Device::D, 100, write_data);

    std::array<std::string, 3> label_names{"LabelB", "LabelW", "Sw.led"};
    std::array<uint32_t, 3> label_data{1, 0x31, 1};
    slmp.label_write_request(label_names, label_data);
}