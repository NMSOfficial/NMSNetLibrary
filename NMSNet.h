#ifndef NMSNET_H
#define NMSNET_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <memory>

namespace NMSNet {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
namespace json = boost::json;

class TCPClient {
public:
    TCPClient(asio::io_context& io_context)
        : io_context_(io_context), socket_(io_context) {}

    void connect(const std::string& host, const std::string& port) {
        asio::ip::tcp::resolver resolver(io_context_);
        asio::connect(socket_, resolver.resolve(host, port));
    }

    void send(const std::string& message) {
        asio::write(socket_, asio::buffer(message));
    }

    std::string receive() {
        beast::flat_buffer buffer;
        asio::read(socket_, buffer.prepare(1024));
        buffer.commit(1024);
        return beast::buffers_to_string(buffer.data());
    }

private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
};

class UDPClient {
public:
    UDPClient(asio::io_context& io_context)
        : io_context_(io_context), socket_(io_context) {}

    void connect(const std::string& host, const std::string& port) {
        asio::ip::udp::resolver resolver(io_context_);
        asio::ip::udp::endpoint endpoint = *resolver.resolve(host, port).begin();
        socket_.connect(endpoint);
    }

    void send(const std::string& message) {
        socket_.send(asio::buffer(message));
    }

    std::string receive() {
        char data[1024];
        size_t len = socket_.receive(asio::buffer(data));
        return std::string(data, len);
    }

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
};

class SSLClient {
public:
    SSLClient(asio::io_context& io_context, ssl::context& ssl_context)
        : io_context_(io_context), ssl_context_(ssl_context),
          socket_(io_context, ssl_context) {}

    void connect(const std::string& host, const std::string& port) {
        asio::ip::tcp::resolver resolver(io_context_);
        asio::connect(socket_.lowest_layer(), resolver.resolve(host, port));
        socket_.handshake(ssl::stream_base::client);
    }

    void send(const std::string& message) {
        asio::write(socket_, asio::buffer(message));
    }

    std::string receive() {
        beast::flat_buffer buffer;
        asio::read(socket_, buffer.prepare(1024));
        buffer.commit(1024);
        return beast::buffers_to_string(buffer.data());
    }

private:
    asio::io_context& io_context_;
    ssl::context& ssl_context_;
    ssl::stream<asio::ip::tcp::socket> socket_;
};

class HTTPClient {
public:
    HTTPClient(asio::io_context& io_context)
        : io_context_(io_context) {}

    std::string get(const std::string& host, const std::string& target, const std::string& port = "80") {
        asio::ip::tcp::resolver resolver(io_context_);
        beast::tcp_stream stream(io_context_);
        auto const results = resolver.resolve(host, port);
        stream.connect(results);

        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);

        return beast::buffers_to_string(res.body().data());
    }

private:
    asio::io_context& io_context_;
};

class HTTPSClient {
public:
    HTTPSClient(asio::io_context& io_context, ssl::context& ssl_context)
        : io_context_(io_context), ssl_context_(ssl_context) {}

    std::string get(const std::string& host, const std::string& target, const std::string& port = "443") {
        asio::ip::tcp::resolver resolver(io_context_);
        beast::ssl_stream<beast::tcp_stream> stream(io_context_, ssl_context_);
        auto const results = resolver.resolve(host, port);
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);

        http::request<http::string_body> req{http::verb::get, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);

        return beast::buffers_to_string(res.body().data());
    }

private:
    asio::io_context& io_context_;
    ssl::context& ssl_context_;
};

// JSON işleme fonksiyonu
json::value parseJSON(const std::string& jsonStr) {
    return json::parse(jsonStr);
}

// Logging ve hata yönetimi
class Logger {
public:
    enum class LogLevel {
        INFO,
        WARNING,
        ERROR
    };

    static void log(const std::string& message, LogLevel level = LogLevel::INFO) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        std::ofstream log_file("NMSNet.log", std::ios_base::app);
        log_file << "[" << logLevelToString(level) << "] " << message << std::endl;
    }

private:
    static std::string logLevelToString(LogLevel level) {
        switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
        }
    }

    static std::mutex log_mutex_;
};

std::mutex Logger::log_mutex_;

} // NMSNet

#endif // NMSNET_H
