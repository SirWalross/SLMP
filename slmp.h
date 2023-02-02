#pragma once
#include <winsock2.h>
#include <ws2def.h>
#include <ws2tcpip.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "fmt/format.h"

#pragma comment(lib, "Ws2_32.lib")

class Socket {
   public:
    Socket(const char* addr, int port) : addr{addr}, port{port} {}

    std::optional<int> connect(int timeout_ms = 0) {
        auto iresult = WSAStartup(MAKEWORD(2, 2), &wsadata);
        if (iresult != 0) {
            return {};
        }

        if (iresult != 0) {
            return {};
        }

        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (socket == INVALID_SOCKET) {
            return {};
        }

        iresult = ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                               sizeof(timeout_ms));

        if (iresult == SOCKET_ERROR) {
            return {};
        }

        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        InetPton(AF_INET, addr, &dest_addr.sin_addr.s_addr);
        dest_addr.sin_port = htons(port);

        iresult = ::connect(socket, reinterpret_cast<SOCKADDR*>(&dest_addr), sizeof(dest_addr));

        if (iresult == SOCKET_ERROR) {
            return {};
        }

        return 1;
    }

    ~Socket() {
        ::closesocket(socket);
        WSACleanup();
    }

    std::optional<int> send(const void* sendData, const ::size_t& size) {
        const auto numbytes = ::send(socket, static_cast<const char*>(sendData), size, 0);
        if (numbytes == SOCKET_ERROR) {
            return {};
        }
        return numbytes;
    }

    std::optional<SSIZE_T> recv(void* recvData, const ::size_t& size) {
        const auto numbytes = ::recv(socket, static_cast<char*>(recvData), size - 1, 0);
        if (numbytes == SOCKET_ERROR) {
            return {};
        }
        static_cast<char*>(recvData)[numbytes] = 0;
        return numbytes;
    }

    const char* addr;
    int port;

   private:
    SOCKET socket;
    WSADATA wsadata;
};

#define SLMP_SHIFT_UINT8_T(a) static_cast<uint8_t>(a)
#define SLMP_SHIFT_UINT16_T(a) static_cast<uint8_t>(a), (static_cast<uint32_t>(a) >> 8) & 0xff
#define SLMP_SHIFT_UINT24_T(a) \
    static_cast<uint8_t>(a), (static_cast<uint32_t>(a) >> 8) & 0xff, (static_cast<uint32_t>(a) >> 16) & 0xff
#define SLMP_SHIFT_UINT32_T(a)                                                                                \
    static_cast<uint8_t>(a), (static_cast<uint32_t>(a) >> 8) & 0xff, (static_cast<uint32_t>(a) >> 16) & 0xff, \
        (static_cast<uint32_t>(a) >> 24) & 0xff

class SLMP {
   private:
    std::map<uint8_t, uint8_t> datatype_size_map = {{0x00, 0}, {0x01, 2}, {0x02, 2}, {0x03, 4},
                                                    {0x04, 2}, {0x05, 4}, {0x06, 4}, {0x07, 8}};

   public:
    enum class Request_Command : uint16_t {
        Read = 0x0401,
        Write = 0x1401,
        LabelRead = 0x041A,
        LabelWrite = 0x141A,
        RandomLabelRead = 0x041c,
        RandomLabelWrite = 0x141b
    };

    enum class Response_Command : uint8_t { Read = 0x01, LabelRead = 0x02, RandomLabelRead = 0x03 };

    enum class Subcommand : uint8_t {
        Bit = 0x01,
        Word = 0x00,
    };

    enum class Datatype : uint8_t {
        Bit = 0x01,
        uWord = 0x02,
        uDoubleWord = 0x03,
        Word = 0x04,
        doubleWord = 0x05,
        Float = 0x06,
        Double = 0x07,
    };

    enum class Device : uint8_t {
        SM = 0x91,
        SD = 0xA9,
        X = 0x9C,
        Y = 0x9D,
        M = 0x90,
        L = 0x92,
        F = 0x93,
        V = 0x94,
        B = 0xA0,
        D = 0xA8,
        W = 0xB4,
        TS = 0xC1,
        TC = 0xC0,
        TN = 0xC2,
        SB = 0xA1,
        SW = 0xB5,
        DX = 0xA2,
        DY = 0xA3,
        Z = 0xCC,
        R = 0xAF,
        ZR = 0xB0,
    };

    enum class Serialnumber : uint16_t {
        None = 0x0050,
    };

    enum class Networknumber : uint8_t { A = 0x00 };

    enum class Stationnumber : uint8_t { A = 0xFF };

    enum class DestinationModule : uint16_t {
        CPU = 0x03FF,
        CPU_Multi_1 = 0x03E0,
        CPU_Multi_2 = 0x03E1,
        CPU_Multi_3 = 0x03E2,
        CPU_Multi_4 = 0x03E3,
    };

    enum class DestinationStation : uint8_t { A = 0x00 };

    enum class MonitoringTimer : uint16_t {
        None = 0x0000,
    };

    enum class Endcode : uint16_t {
        Success = 0x0000,
        InvalidEndCode = 0x0001,
        UnableToWrite = 0x0055,
        WrongCommand = 0xC059,
        WrongFormat = 0xC05C,
        WrongLength = 0xC061,
        Busy = 0xCEE0,
        ExceedReqLength = 0xCEE1,
        ExceedRespLength = 0xCEE2,
        ServerNotFound = 0xCF10,
        WrongConfigItem = 0xCF20,
        PrmIDNotFound = 0xCF30,
        NotStartExclusiveWrite = 0xCF31,
        RelayFailure = 0xCF70,
        TimeoutError = 0xCF71,
        CANAppNotPermittedRead = 0xCCC7,
        CANAppWriteOnly = 0xCCC8,
        CANAppReadOnly = 0xCCC9,
        CANAppUndefinedObjectAccess = 0xCCCA,
        CANAppNotPermittedPDOMapping = 0xCCCB,
        CANAppExceedPDOMapping = 0xCCCC,
        CANAppNotExistSubIndex = 0xCCD3,
        CANAppWrongParameter = 0xCCD4,
        CANAppMoreOverParameterRange = 0xCCD5,
        CANAppLessOverParameterRange = 0xCCD6,
        CANAppTransOrStoreError = 0xCCDA,
        CANAppOtherError = 0xCCFF,
        OtherNetworkError = 0xCF00,
        DataFragmentShortage = 0xCF40,
        DataFragmentDup = 0xCF41,
        DataFragmentLost = 0xCF43,
        DataFragmentNotSupport = 0xCF44,
        InvalidGlobalLabel = 0x40C0
    };

    SLMP(const char* addr, int port) : socket(addr, port), buffer(buffer_size, 0) {
        header_size = request_data.size() + 4;  // command and subcommand are counted as part of header
        request_data.resize(request_data_size);
        if (!socket.connect(2000).has_value()) {
            fmt::print("SLMP connection to {}:{} failed with error {}\n", addr, port, WSAGetLastError());
            throw std::exception();
        }
    }

    ~SLMP() {}

    std::optional<uint8_t*> read_request(Device device, Subcommand subcommand, uint32_t head_no, uint16_t number) {
        request_data[header_size] = head_no & 0xff;
        request_data[header_size + 1] = (head_no >> 8) & 0xff;
        request_data[header_size + 2] = (head_no >> 16) & 0xff;
        request_data[header_size + 3] = static_cast<uint8_t>(device);
        request_data[header_size + 4] = number & 0xff;
        request_data[header_size + 5] = (number >> 8) & 0xff;
        return request(Request_Command::Read, subcommand, header_size + 6);
    }

    template <class T, Subcommand subcommand, size_t size,
              typename = std::enable_if<subcommand == Subcommand::Word || std::is_same<T, uint8_t>::value>::type>
    std::optional<uint8_t*> write_request(Device device, uint32_t head_no, std::array<T, size> data) {
        constexpr auto write_data_size = [&]() {
            if constexpr (subcommand == Subcommand::Bit) {
                return (size * sizeof(T) + 1) / 2;  // to round up
            } else {
                return size * sizeof(T);
            }
        }();
        constexpr auto device_count = [&]() {
            if constexpr (subcommand == Subcommand::Word) {
                return (size * sizeof(T) + 1) / 2;  // to round up
            } else {
                return size * sizeof(T);
            }
        }();
        ;
        // fmt::print("write_data_size: {}, device_count: {}\n", write_data_size, device_count);
        assert((write_data_size + header_size + 6) <= request_data_size && "Write request too big");
        if constexpr (subcommand == Subcommand::Bit) {
            for (int i = 0; i < write_data_size; i++) {
                request_data[header_size + 6 + i] = (data[i * 2] << 4) + data[i * 2 + 1];
            }
        } else {
            std::memcpy(request_data.data() + 6 + header_size, data.data(), write_data_size);
        }
        request_data[header_size] = head_no & 0xff;
        request_data[header_size + 1] = (head_no >> 8) & 0xff;
        request_data[header_size + 2] = (head_no >> 16) & 0xff;
        request_data[header_size + 3] = static_cast<uint8_t>(device);
        request_data[header_size + 4] = device_count & 0xff;
        request_data[header_size + 5] = (device_count >> 8) & 0xff;
        return request(Request_Command::Write, subcommand, header_size + 6 + write_data_size);
    }

    template <size_t size>
    std::optional<uint8_t*> label_read_request(std::array<std::string, size> label_names) {
        constexpr auto sizes =
            label_names | std::views::transform([](const auto& string) { return 2 * string.size() + 2; });
        const std::size_t read_data_size = 4 + std::accumulate(sizes.begin(), sizes.end(), 0);
        assert((read_data_size + header_size) <= request_data_size && "Read request too big");

        std::size_t last_index = header_size + 4;
        for (std::size_t i = 0; i < label_names.size(); i++) {
            request_data[last_index] = label_names[i].size() & 0xff;
            request_data[last_index + 1] = (label_names[i].size() >> 8) & 0xff;
            for (std::size_t j = 0; j < label_names[i].size(); j++) {
                request_data[last_index + 2 + j * 2] = label_names[i][j];
                request_data[last_index + 2 + j * 2 + 1] = 0;
            }
            last_index += 2 + label_names[i].size() * 2;
        }

        request_data[header_size] = label_names.size() & 0xff;
        request_data[header_size + 1] = (label_names.size() >> 8) & 0xff;
        request_data[header_size + 2] = 0;
        request_data[header_size + 3] = 0;
        return request(Request_Command::RandomLabelRead, Subcommand::Word, read_data_size + header_size);
    }

    template <class T, size_t size>
    std::optional<uint8_t*> label_write_request(std::array<std::string, size> label_names,
                                                std::array<T, size> label_data) {
        constexpr auto write_data_length = 2 * ((sizeof(T) + 1) / 2);  // to round uint8_t up to 2
        constexpr auto sizes = label_names | std::views::transform([](const auto& string) -> std::size_t {
                                   return 2 * string.size() + 4 + write_data_length;
                               });
        const std::size_t write_data_size = 4 + std::accumulate(sizes.begin(), sizes.end(), 0);
        assert((write_data_size + header_size) <= request_data_size && "Write request too big");

        std::size_t last_index = header_size + 4;
        for (std::size_t i = 0; i < label_names.size(); i++) {
            request_data[last_index] = label_names[i].size() & 0xff;
            request_data[last_index + 1] = (label_names[i].size() >> 8) & 0xff;
            for (std::size_t j = 0; j < label_names[i].size(); j++) {
                request_data[last_index + 2 + j * 2] = label_names[i][j];
                request_data[last_index + 2 + j * 2 + 1] = 0;
            }
            request_data[last_index + 2 + label_names[i].size() * 2] = write_data_length & 0xff;
            request_data[last_index + 3 + label_names[i].size() * 2] = (write_data_length >> 8) & 0xff;
            std::memcpy(request_data.data() + last_index + label_names[i].size() * 2 + 4, label_data.data() + i,
                        sizeof(T));
            last_index += 4 + label_names[i].size() * 2 + write_data_length;
        }

        request_data[header_size] = label_names.size() & 0xff;
        request_data[header_size + 1] = (label_names.size() >> 8) & 0xff;
        request_data[header_size + 2] = 0;
        request_data[header_size + 3] = 0;
        return request(Request_Command::RandomLabelWrite, Subcommand::Word, write_data_size + header_size);
    }

   private:
    void response(Request_Command command, Subcommand subcommand, ::size_t response_length) {
        fmt::print("Serial no. {:04x}\n", buffer[0] + (static_cast<uint32_t>(buffer[1]) << 8));
        fmt::print("Request destination network no. {:02x}\n", buffer[2]);
        fmt::print("Request destination station no. {:02x}\n", buffer[3]);
        fmt::print("Request destination module I/O no. {:04x}\n", buffer[4] + (static_cast<uint32_t>(buffer[5]) << 8));
        fmt::print("Request destination multidrop station no. {:02x}\n", buffer[6]);
        fmt::print("Response data length {}\n", buffer[7] + (static_cast<uint32_t>(buffer[8]) << 8));
        const auto end_code = buffer[9] + (static_cast<uint32_t>(buffer[10]) << 8);
        fmt::print("Response end code {:04x}\n", end_code);

        if (end_code != 0) {
            return;
        }

        if (command == Request_Command::Read) {
            if (subcommand == Subcommand::Word) {
                for (std::size_t i = 0; i < (response_length - 10) / 2; i++) {
                    fmt::print("[{}]: {:x}\n", i,
                               buffer[11 + 2 * i] * (static_cast<uint32_t>(buffer[12 + 2 * i]) << 8));
                }
            } else {
                for (std::size_t i = 0; i < (response_length - 11) * 2; i++) {
                    fmt::print("[{}]: {:x}\n", i, (buffer[11 + i / 2] >> ((i % 2) ? 0 : 4)) & 0x0f);
                }
            }
        } else if (command == Request_Command::RandomLabelRead) {
            assert(buffer[11] + (static_cast<uint32_t>(buffer[12]) << 8) ==
                       static_cast<uint32_t>(Request_Command::RandomLabelWrite) &&
                   "Invalid response command!");
            const std::size_t label_count = buffer[15] + (static_cast<uint32_t>(buffer[16]) << 8);
            std::size_t start_index = 19;
            for (std::size_t i = 0; i < label_count; i++) {
                const std::size_t label_size =
                    2 * (buffer[start_index] + (static_cast<uint32_t>(buffer[start_index + 1]) << 8));
                const std::size_t data_size = buffer[start_index + label_size + 2] +
                                              (static_cast<uint32_t>(buffer[start_index + label_size + 3]) << 8);
                fmt::print("[{}]: {:x}\n", i,
                           fmt::join(buffer.begin() + start_index + label_size + 4,
                                     buffer.begin() + start_index + label_size + 4 + data_size, ", "));
                start_index += start_index + label_size + 4 + data_size;
            }
        }
    }

    Socket socket;
    std::size_t buffer_size = 400;
    std::vector<uint8_t> buffer;
    std::size_t request_data_size = 1296;
    std::size_t header_size;
    std::vector<uint8_t> request_data{
        SLMP_SHIFT_UINT16_T(Serialnumber::None),   SLMP_SHIFT_UINT8_T(Networknumber::A),
        SLMP_SHIFT_UINT8_T(Stationnumber::A),      SLMP_SHIFT_UINT16_T(DestinationModule::CPU),
        SLMP_SHIFT_UINT8_T(DestinationStation::A), SLMP_SHIFT_UINT16_T(0),
        SLMP_SHIFT_UINT16_T(MonitoringTimer::None)};

    std::optional<uint8_t*> request(Request_Command command, Subcommand subcommand, std::size_t request_size) {
        auto request_data_length = request_size - header_size + 6;  // include monitoring timer, command and subcommand
        request_data[7] = request_data_length & 0xff;
        request_data[8] = (request_data_length >> 8) & 0xff;
        request_data[11] = static_cast<uint16_t>(command) & 0xff;
        request_data[12] = (static_cast<uint16_t>(command) >> 8) & 0xff;
        request_data[13] = static_cast<uint16_t>(subcommand) & 0xff;
        request_data[14] = (static_cast<uint16_t>(subcommand) >> 8) & 0xff;

        fmt::print("{:02x}\n", fmt::join(request_data.begin(), request_data.begin() + request_size, ","));
        const auto send_result = socket.send(request_data.data(), request_size);
        if (!send_result.has_value()) {
            return {};
        }
        const auto recv_result = socket.recv(buffer.data(), buffer.size());
        if (!recv_result.has_value()) {
            fmt::print("Didnt get answer: {}!\n", WSAGetLastError());
            return {};
        }
        fmt::print("{:02x}\n", fmt::join(buffer.begin(), buffer.begin() + recv_result.value(), ","));
        response(command, subcommand, recv_result.value());
        return buffer.data();
    }
};