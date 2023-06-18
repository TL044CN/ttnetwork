#ifndef SOCKET_EXCEPTIONS_H
#define SOCKET_EXCEPTIONS_H

#include <stdexcept>
#include <string>
#include <sstream>

namespace Network {

    /// @brief Represents a generic Network Exception
    class NetworkException : public std::exception {
    private:
        std::string mMessage;
    public:
        NetworkException(std::string message="Unknown", std::string kind="NetworkException"){
            std::stringstream stream;
            stream << kind << ": " << message;
            mMessage = stream.str();
        }
    private:
        virtual const char* what() const throw() {
            return mMessage.data();
        }
    };

    /// @brief Represents a Socket Exception (probably problems with POSIX calls)
    class SocketException : public NetworkException {
    public:
        SocketException(std::string message="Unknown", std::string kind = "SocketException")
        : NetworkException(message, kind) {}
    };

    /// @brief Represents an Excpetion while Sending data to a socket
    class SendError : public SocketException {
    public:
        SendError(std::string message = "Unknown")
        : SocketException(message,"SendError") {}
    };

    /// @brief Represents an Exception while Receiveing Data from a Socket
    class ReceiveError : public SocketException {
    public:
        ReceiveError(std::string message = "Unknown")
        : SocketException(message,"ReceiveError"){}
    };

}

#endif