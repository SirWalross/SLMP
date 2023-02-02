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

    std::optional<int> recv(void* recvData, const ::size_t& size) {
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
    enum class RequestCommand : uint16_t {
        Read = 0x0401,
        Write = 0x1401,
        LabelRead = 0x041A,
        LabelWrite = 0x141A,
        RandomLabelRead = 0x041c,
        RandomLabelWrite = 0x141b
    };

    enum class ResponseCommand : uint8_t { Read = 0x01, LabelRead = 0x02, RandomLabelRead = 0x03 };

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

    enum class NetworkNumber : uint8_t { A = 0x00 };

    enum class StationNumber : uint8_t { A = 0xFF };

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

    SLMP(const char *addr, int port, NetworkNumber network_no, StationNumber station_no, DestinationModule module_io,
         DestinationStation multidrop_station_no)
        : socket(addr, port), buffer(buffer_size), request_data{SLMP_SHIFT_UINT16_T(Serialnumber::None),
                                                                SLMP_SHIFT_UINT8_T(network_no),
                                                                SLMP_SHIFT_UINT8_T(station_no),
                                                                SLMP_SHIFT_UINT16_T(module_io),
                                                                SLMP_SHIFT_UINT8_T(multidrop_station_no),
                                                                SLMP_SHIFT_UINT16_T(0),
                       SLMP_SHIFT_UINT16_T(MonitoringTimer::None)},
          connected{false} {
        header_size = request_data.size() + 4;  // command and subcommand are counted as part of header
        request_data.reserve(request_data_size);
    }

    void disconnect() {
        connected = false;
    }

    std::optional<int> connect() {
        if (!socket.connect(100).has_value()) {
            fmt::print("SLMP connection to {}:{} failed with error {}\n", socket.addr, socket.port, WSAGetLastError());
            throw std::exception();
        }
        connected = true;
    }

    ~SLMP() {}

    std::optional<int32_t> read_request(Device device, Subcommand subcommand, uint32_t head_no,
                                        std::span<uint16_t> data) {
        request_data.push_back(head_no & 0xff);
        request_data.push_back((head_no >> 8) & 0xff);
        request_data.push_back((head_no >> 16) & 0xff);
        request_data.push_back(static_cast<uint8_t>(device));
        request_data.push_back(data.size() & 0xff);
        request_data.push_back((data.size() >> 8) & 0xff);

        const auto retval = request(RequestCommand::Read, subcommand);

        if (retval.has_value()) {
            return response(RequestCommand::Read, subcommand, data, retval.value());
        }
        return retval;
    }

    template <class T>
    std::optional<int32_t> write_request(Device device, Subcommand subcommand, uint32_t head_no, std::span<T> data) {
        const auto write_data_size = [&]() {
            if (subcommand == Subcommand::Bit) {
                return (data.size() * sizeof(T) + 1) / 2;  // to round up
            } else {
                return data.size() * sizeof(T);
            }
        }();
        const auto device_count = [&]() {
            if (subcommand == Subcommand::Word) {
                return (data.size() * sizeof(T) + 1) / 2;  // to round up
            } else {
                return data.size() * sizeof(T);
            }
        }();

        assert((write_data_size + header_size + 6) <= request_data_size && "Write request too big");
        request_data.push_back(head_no & 0xff);
        request_data.push_back((head_no >> 8) & 0xff);
        request_data.push_back((head_no >> 16) & 0xff);
        request_data.push_back(static_cast<uint8_t>(device));
        request_data.push_back(device_count.size() & 0xff);
        request_data.push_back((device_count.size() >> 8) & 0xff);
        if (subcommand == Subcommand::Bit) {
            for (int i = 0; i < write_data_size; i++) {
                request_data.push_back((data[i * 2] << 4) + data[i * 2 + 1]);
            }
        } else {
            request_data.resize(request_data.size() + write_data_size);
            std::memcpy(request_data.data() + 6 + header_size, data.data(), write_data_size);
        }
        return request(RequestCommand::Write, subcommand);
    }

    template <class T>
    std::optional<int32_t> label_read_request(std::span<std::string> label_names, std::span<T> label_data) {
        auto sizes = label_names | std::views::transform([](const auto& string) { return 2 * string.size() + 2; });
        const std::size_t read_data_size = 4 + std::accumulate(sizes.begin(), sizes.end(), 0);
        assert((read_data_size + header_size) <= request_data_size && "Read request too big");

        request_data.push_back(label_names.size() & 0xff);
        request_data.push_back((label_names.size() >> 8) & 0xff);
        request_data.push_back(0);
        request_data.push_back(0);

        for (std::size_t i = 0; i < label_names.size(); i++) {
            request_data.push_back(label_names[i].size() & 0xff);
            request_data.push_back((label_names[i].size() >> 8) & 0xff);
            for (std::size_t j = 0; j < label_names[i].size(); j++) {
                request_data.push_back(label_names[i][j]);
                request_data.push_back(0);
            }
        }
        const auto retval = request(RequestCommand::RandomLabelRead, Subcommand::Word);

        if (retval.has_value()) {
            return response(RequestCommand::RandomLabelRead, Subcommand::Word, label_data, retval.value());
        }
        return retval;
    }

    template <class T>
    std::optional<int32_t> label_write_request(std::span<std::string> label_names, std::span<T> label_data) {
        auto write_data_length = 2 * ((sizeof(T) + 1) / 2);  // to round uint8_t up to 2
        auto sizes = label_names | std::views::transform([&](const auto& string) -> std::size_t {
                         return 2 * string.size() + 4 + write_data_length;
                     });
        const std::size_t write_data_size = 4 + std::accumulate(sizes.begin(), sizes.end(), 0);
        assert((write_data_size + header_size) <= request_data_size && "Write request too big");

        request_data.push_back(label_names.size() & 0xff);
        request_data.push_back((label_names.size() >> 8) & 0xff);
        request_data.push_back(0);
        request_data.push_back(0);

        for (std::size_t i = 0; i < label_names.size(); i++) {
            request_data.push_back(label_names[i].size() & 0xff);
            request_data.push_back((label_names[i].size() >> 8) & 0xff);
            for (std::size_t j = 0; j < label_names[i].size(); j++) {
                request_data.push_back(label_names[i][j]);
                request_data.push_back(0);
            }
            request_data.push_back(write_data_length & 0xff);
            request_data.push_back((write_data_length >> 8) & 0xff);
            request_data.resize(request_data.size() + sizeof(T));
            std::memcpy(&request_data.back() - sizeof(T), label_data.data() + i, sizeof(T));
        }
        return request(RequestCommand::RandomLabelWrite, Subcommand::Word);
    }

    volatile bool connected;

   private:
    template <class T>
    std::optional<int> response(RequestCommand command, Subcommand subcommand, std::span<T> read_data,
                                std::size_t response_length) {
        const auto end_code = buffer[9] + (static_cast<uint32_t>(buffer[10]) << 8);

        if (end_code != 0) {
            return {};
        }

        std::size_t i = 0;
        if (command == RequestCommand::Read) {
            if (subcommand == Subcommand::Word) {
                for (i = 0; i < (response_length - 10) / 2; i++) {
                    read_data[i] = buffer[11 + 2 * i] * (static_cast<uint32_t>(buffer[12 + 2 * i]) << 8);
                }
            } else {
                for (i = 0; i < (response_length - 11) * 2; i++) {
                    read_data[i] = (buffer[11 + i / 2] >> ((i % 2) ? 0 : 4)) & 0x0f;
                }
            }
        } else if (command == RequestCommand::RandomLabelRead) {
            assert(buffer[11] + (static_cast<uint32_t>(buffer[12]) << 8) ==
                       static_cast<uint32_t>(RequestCommand::RandomLabelWrite) &&
                   "Invalid response command!");
            const std::size_t label_count = buffer[15] + (static_cast<uint32_t>(buffer[16]) << 8);
            std::size_t start_index = 19;
            for (i = 0; i < label_count; i++) {
                const std::size_t label_size =
                    2 * (buffer[start_index] + (static_cast<uint32_t>(buffer[start_index + 1]) << 8));
                const std::size_t data_size = buffer[start_index + label_size + 2] +
                                              (static_cast<uint32_t>(buffer[start_index + label_size + 3]) << 8);
                std::memcpy(&read_data[i], &buffer.front() + start_index + label_size + 4, data_size);
                start_index += start_index + label_size + 4 + data_size;
            }
        }
        return static_cast<int>(i);
    }

    Socket socket;
    std::size_t buffer_size = 400;
    std::vector<uint8_t> buffer;
    std::size_t request_data_size = 1296;
    std::size_t header_size;
    std::vector<uint8_t> request_data;

    std::optional<int> request(RequestCommand command, Subcommand subcommand) {
        request_data[7] = (request_data.size() - header_size) & 0xff;
        request_data[8] = ((request_data.size() - header_size) >> 8) & 0xff;
        request_data[11] = static_cast<uint16_t>(command) & 0xff;
        request_data[12] = (static_cast<uint16_t>(command) >> 8) & 0xff;
        request_data[13] = static_cast<uint16_t>(subcommand) & 0xff;
        request_data[14] = (static_cast<uint16_t>(subcommand) >> 8) & 0xff;

        const auto send_result = socket.send(request_data.data(), request_data.size());
        fmt::print("{:02x}\n", fmt::join(request_data.begin(), request_data.end(), ","));
        request_data.resize(header_size);
        if (!send_result.has_value()) {
            this->disconnect();
            return {};
        }
        const auto recv_result = socket.recv(buffer.data(), buffer.size());
        if (!recv_result.has_value()) {
            this->disconnect();
            return {};
        }

        return recv_result;
    }
};