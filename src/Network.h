/// Network Library
/// Author: Turbo Taube
/// Datae:  19.05.2023

#ifndef NETWORK_H
#define NETWORK_H
#include <memory>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/unistd.h>
#include <netdb.h>
#include <cstring>
#include <sstream>

#include "SocketException.h"

namespace Network {

    enum class AddressFamily { IPV4, IPV6 };
    enum class Protocol { TCP, UDP };

    namespace Util {
        /// @brief      Converts an Enum of type Address Family into
        ///             its host systems native int
        /// @param af   the input AddressFamily
        /// @return     Host system integer representation
        /// @throws NetworkException
        int toNative(AddressFamily af);

        /// @brief          Converts an Enum of type Protocol into
        ///                 its host systems native int
        /// @param proto    the input Protocol
        /// @returns        Host system integer representation
        /// @throws NetworkException
        int toNative(Protocol proto);
    }

    /// @brief Represents the Endpoint of a Socket.
    ///        Wraps Sockaddr Structs
    class Endpoint {
    private:
        union Sockaddr {
            sockaddr     base;
            sockaddr_in  ipv4;
            sockaddr_in6 ipv6;
        } mSockaddr;

    public:
        /// @brief      Creates a new Endpoint from a given sockaddr
        /// @param addr the sockaddr to wrap
        /// @param size the size of the sockaddr derived type
        /// @throws NetworkException
        Endpoint(sockaddr* addr, socklen_t size);

        /// @brief          Creates a new Endpoint that points at the
        ///                 Address behind the given hostname
        /// @param hostname the Hostname of the Peer
        /// @throws NetworkException
        Endpoint(
            std::string hostname="localhost",
            uint16_t port = 80
        );

        ~Endpoint();

        /// @brief  Returns the Address Family of the Endpoint
        /// @return Address Family of the Endpoint
        /// @throws NetworkException
        AddressFamily family() const;

        /// @brief  Returns the Struct associated with the Endpoint
        /// @return sockaddr* stored in the Endpoint
        /// @throws NetworkException
        sockaddr* c_addr();

        /// @brief  Returns the Size of the underlying 
        ///         sockaddr struct
        /// @return the szie of the sockaddr struct
        socklen_t addr_size() const;
    };

    /// @brief Represents a Network Socket (TCP for now)
    class Socket {
    private:
        /// @brief Represents a received UDP Package
        struct UDPPacket {
        public:
            std::shared_ptr<Endpoint> endpoint;
            size_t length;
            const char* message;
            const size_t bufferSize;

            /// @brief      Creates a basic UDP PAcket struct and
            ///             allocates enough memory for the maximum
            ///             safe UDP Payload size of 509 bytes
            /// @param size the size of the Buffer to allocate
            UDPPacket(size_t size = 508);

            ~UDPPacket();
        };
    private:
        int mInternalFD = 0;
        Protocol mProtocol;
        AddressFamily mAF;
        std::shared_ptr<Endpoint> mEndpoint;

    private:
        /// @brief       Creates a Socket Object from within the Socket class
        /// @param fd    the underlzing File Descriptor of the Socket
        /// @param ep    the Endpoint object to point to
        /// @param proto the Protocol to use
        Socket(int fd, std::shared_ptr<Endpoint> ep, Protocol proto);

    public:
        /// @brief          Creates a new Socket with the given
        ///                 Address Family and Protocol
        /// @param af       the Address Family to use
        /// @param protocol the Protocol to use
        /// @throws SocketException
        Socket(AddressFamily af, Protocol protocol);

        /// @brief Cleans up after the Socket is destroyed
        ///        e.g. closes the underlying socket
        ~Socket();

    public:
        /// @brief          Bind the Socket to the given Endpoint
        /// @param endpoint the Endpoint to bind to
        /// @throws SocketException
        void bind(std::shared_ptr<Endpoint> endpoint);

        /// @brief      Binds the Socket to the given Port.
        ///             Useful when Listening to a Port
        /// @param port the Port to bind to
        /// @throws SocketException
        void bindToPort(uint16_t port);

        /// @brief        connect the Socket to the given Endpoint.
        ///               Only works with TCP.
        ///               This Socket will then be the Client Socket.
        /// @param target the Endpoint to connect to
        /// @throws SocketException
        void connect(std::shared_ptr<Endpoint> target);

        /// @brief Listen to Messages on internal Endpoint
        /// @throws SocketException
        void listen();

        /// @brief  Accepts a TCP Connection from a requesting Client
        ///         Only works with TCP.
        /// @return a connected Socket that can be written to and read from
        /// @throws SocketException
        std::shared_ptr<Socket> accept();
        
        /// @brief        Configures the Socket for broadcast mode,
        ///               or disables it.
        ///               When disabling, the Address will be set to Any (0)
        /// @param enable Enable or Disable
        /// @throws       SocketException
        void setBroadcast(bool enable = true);

        /// @brief        Configures the Socket for Port Reuse,
        ///               or disables it.
        ///               UDP benefits greatly from this.
        /// @param enable Enable or Disable
        void enablePortReuse(bool enable = true);

        /// @brief      Sends data to the internal Socket.
        ///             Should be used with either UDP Sockets
        ///             or a TCP Socket, that was returned from
        ///             Socket::accept()
        /// @param data the Data to send
        /// @return     the size of data that was sent
        /// @throws     SendError
        /// @see        Socket::accept()
        ssize_t send(const std::string& data) const;

        /// @brief            Receives data from the internal Socket.
        ///                   Should be used with either a UDP Socket
        ///                   or a TCP Socket, that was returned from
        ///                   Socket::accept()
        /// @param data       the Data that was received
        /// @param bufferSize the size of the supplied Buffer
        /// @return           the size of the Data that was received
        /// @throws           ReceiveError
        /// @see              Socket::accept()
        ssize_t receive(char* data, size_t bufferSize) const;

        /// @brief          Send data to the given Endpoint
        ///                 Only works with UDP Sockets.
        ///                 for UDP Sockets it works like Socket::send()
        /// @param data     the Data to send in the Package
        /// @param dataSize the size of the Data Buffer
        /// @param endpoint the Endpoint to send the Data to
        /// @return         the size of data that was sent
        /// @throws         SendError
        /// @see            Socket::send()
        ssize_t sendTo(
            const char* data,
            size_t dataSize,
            std::shared_ptr<Endpoint> endpoint
        );

        /// @brief  Receives a UDPPacket from the internal Socket.
        ///         Obviously only works with UDP
        /// @return the Packet that was received, including sender.
        UDPPacket receiveFrom();

    public:
        /// @brief      Send data to the underlying File Descriptor
        /// @param data the Data to send
        /// @return     the size of data that was sent
        ssize_t operator<<(const std::string& data) const;

        /// @brief      Receive data from the underlying File Descriptor
        /// @param data the Data that was received
        /// @return     the size of data received
        ssize_t operator>>(std::string& data);

        /// @brief      Receive data from the underlying File Descriptor
        /// @param data the Data toat was received
        /// @return     the Size of data received
        /// @throws           ReceiveError
        ssize_t operator>>(std::stringstream& data);
    };


}

#endif