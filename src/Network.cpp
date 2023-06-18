#include "Network.h"
#include <fcntl.h>
#include <errno.h>

#include <functional>
#include <iostream>

namespace Network {
    namespace Util {
        int toNative(AddressFamily af){
            switch(af){
                case AddressFamily::IPV4: return AF_INET; break;
                case AddressFamily::IPV6: return AF_INET6; break;
                default: throw NetworkException("Unknown AddressFamily.");
            }
        }

        int toNative(Protocol proto){
            switch(proto){
                case Protocol::TCP: return SOCK_STREAM; break;
                case Protocol::UDP: return SOCK_DGRAM; break;
                default: throw NetworkException("Unknown Protocol.");
            }
        }

    }

    Endpoint::Endpoint(sockaddr* addr, socklen_t size){
        switch(addr->sa_family){
            case AF_INET:
                if(size < sizeof(sockaddr_in)) throw NetworkException("Insufficient Bytes");
                std::memcpy(&mSockaddr.ipv4, addr, sizeof(sockaddr_in));
            break;
            case AF_INET6:
                if(size < sizeof(sockaddr_in6)) throw NetworkException("Insufficient Bytes");
                std::memcpy(&mSockaddr.ipv6, addr, sizeof(sockaddr_in6));
            break;
        }
    }

    Endpoint::Endpoint (
        std::string hostname,
        uint16_t port
    ){
        struct hostent* hostEntity;
        if( (hostEntity = gethostbyname(hostname.c_str())) == NULL ){
            std::stringstream stream;
            stream << "unknown hostname: " << hostname;
            throw NetworkException(stream.str());
        }

        switch(hostEntity->h_addrtype){
            case AF_INET:
                std::memcpy(&mSockaddr.ipv4, hostEntity->h_addr_list[0], hostEntity->h_length);
                mSockaddr.ipv4.sin_family = AF_INET;
                mSockaddr.ipv4.sin_port = htons(port);
                break;
            case AF_INET6:
                std::memcpy(&mSockaddr.ipv6, hostEntity->h_addr_list[0], hostEntity->h_length);
                mSockaddr.ipv6.sin6_family = AF_INET6;
                mSockaddr.ipv6.sin6_port = htons(port);
                break;
            default: {
                std::stringstream stream;
                stream << "Unknown Address Type in Hostent struct: " << hostEntity->h_addrtype;
                throw NetworkException(stream.str());
            }
        }
    }

    Endpoint::~Endpoint(){}

    AddressFamily Endpoint::family() const {
        switch(mSockaddr.base.sa_family){
            case AF_INET: return AddressFamily::IPV4;
            case AF_INET6: return AddressFamily::IPV6;
            default:{
                std::stringstream stream;
                stream << "[Endpoint::family]Unknown Address Family:" << mSockaddr.base.sa_family;
                throw NetworkException(stream.str());
            }
        }
    }

    sockaddr* Endpoint::c_addr() {
        switch(mSockaddr.base.sa_family){
            case AF_INET:{
                return reinterpret_cast<sockaddr*>(&mSockaddr.ipv4);
            }
            case AF_INET6:{
                return reinterpret_cast<sockaddr*>(&mSockaddr.ipv6);
            }
            default:{
                std::stringstream stream;
                stream << "[Endpoint::c_addr]Unknown Address Family:"
                       << mSockaddr.base.sa_family;
                throw NetworkException(stream.str());
            }
        }
    }

    socklen_t Endpoint::addr_size() const {
        switch(mSockaddr.base.sa_family){
            case AF_INET:{
                return sizeof(sockaddr_in);
            }
            case AF_INET6:{
                return sizeof(sockaddr_in6);
            }
            default:{
                std::stringstream stream;
                stream << "[Endpoint::addr_size]Unknown Address Family:" 
                       << mSockaddr.base.sa_family;
                throw NetworkException(stream.str());
            }
        }
    }

    Socket::UDPPacket::UDPPacket(size_t size)
    : bufferSize(size){
        message = new char[bufferSize];
    }

    Socket::UDPPacket::~UDPPacket(){
        delete message;
    }

    Socket::Socket(int fd, std::shared_ptr<Endpoint> ep, Protocol proto)
    : mInternalFD(fd), mProtocol(proto), mAF(ep->family()), mEndpoint(ep) {
#if TTDEBUG
        std::cout << "Creating fd " << mInternalFD << '\n';
#endif
    }

    Socket::Socket(AddressFamily af, Protocol protocol)
    : mAF(af), mProtocol(protocol) {

        if(mAF != AddressFamily::IPV4) throw SocketException(
            "Currently only IPV4 is support."
        );

        if(mProtocol != Protocol::TCP) throw SocketException(
            "Currently only TCP is supported."
        );

        mInternalFD = ::socket(
            Util::toNative(mAF),
            Util::toNative(mProtocol),
            0
        );
        if(mInternalFD < 0) throw SocketException(
            "Creation of Socket File Descriptor failed!"
        );
#if TTDEBUG
        std::cout << "creating fd " << mInternalFD << '\n';
#endif
    }

    Socket::~Socket() {
#if TTDEBUG
        std::cout << "closing fd " << mInternalFD << '\n';
#endif
        shutdown(mInternalFD, SHUT_RDWR);
        close(mInternalFD);
    }

    void Socket::bind(std::shared_ptr<Endpoint> endpoint) {
        switch(endpoint->family()){
            case AddressFamily::IPV4:
                ::bind(mInternalFD,
                    endpoint->c_addr(),
                    endpoint->addr_size()
                );
            break;
            default:
            throw SocketException(
                "Unsupported Address Family when binding."
            );
        }
        mEndpoint = endpoint;
    }

    void Socket::bindToPort(uint16_t port){
        switch(mAF){
            case AddressFamily::IPV4:{
                sockaddr_in* addr = new sockaddr_in;
                addr->sin_family = AF_INET;
                addr->sin_addr = in_addr{0x0};
                addr->sin_port = ::htons(port);

                bind(std::make_shared<Endpoint>(
                    Endpoint(reinterpret_cast<sockaddr*>(addr), sizeof(sockaddr_in))
                ));

            }
            break;
            default: throw SocketException(
                "Unsupported Address Family. "
                "How did you even get here??"
            );
        }
    }

    void Socket::connect(std::shared_ptr<Endpoint> target) {
        if(target->family() != mAF) throw SocketException(
            "Atempt to connect to Endpoint with different Address Family!"
        );

        switch(target->family()){
            case AddressFamily::IPV4:{

                ssize_t ret = ::connect(
                    mInternalFD, target->c_addr(), sizeof(sockaddr_in)
                );
                if(ret == 0) return;
                else {
                    std::stringstream stream;
                    stream << "::connect error: " << strerror(errno);
                    throw SocketException(stream.str());
                }

            }
            break;
            default: throw SocketException(
                "Unsupported Address Family. How did you even get here??"
            );
        }
    }

    void Socket::listen() {
        if(::listen(mInternalFD, SOMAXCONN) < 0){
            std::stringstream stream;
            stream << "::listen error: " << strerror(errno);
            throw SocketException(stream.str());
        } 
    }

    std::shared_ptr<Socket> Socket::accept(){
        
        sockaddr_in6* addr = new sockaddr_in6;
        socklen_t size = sizeof(sockaddr_in6);
        const int fd = ::accept(
            mInternalFD, reinterpret_cast<sockaddr*>(addr), &size
        );
        if(fd <= 0){
            std::stringstream stream;
            stream << "::accept error: " << strerror(errno);
            throw SocketException(stream.str());
        } 

        auto socket = new Socket(
            fd,
            std::make_shared<Endpoint>(reinterpret_cast<sockaddr*>(addr), size),
            mProtocol
        );

        return std::make_shared<Socket>(*socket);
    }

    void Socket::setBroadcast(bool enable) {
        if(mEndpoint->family() != AddressFamily::IPV4) throw SocketException(
            "Attempting to set Broadcast Mode of IPV6 Socket. "
            "IPV6 does not support broadcast."
        );
        uint32_t value = enable;
        if(setsockopt(mInternalFD, SOL_SOCKET, SO_BROADCAST, &value, 4) > 0)
            throw SocketException(
                "Error while trying to set Broadcast Mode of Socket."
            );
    }

    void Socket::enablePortReuse(bool enable) {
        uint32_t opt = enable? 1:0;
        if(setsockopt(mInternalFD, SOL_SOCKET, SO_REUSEPORT, &opt, 4) > 0){
            std::stringstream stream;
            stream << "::setsockopt: " << strerror(errno);
            throw SocketException(stream.str());
        }

    }

    ssize_t Socket::send(const std::string& data) const {
        int ret = ::send(mInternalFD, data.c_str(), data.size(), 0);

        if(ret < 0){
            std::stringstream stream;
            stream << "::send error: " << errno << ' ' << strerror(errno);
            throw SendError(stream.str());
        }
        return ret;
    }

    ssize_t Socket::receive(char* data, size_t bufferSize) const {
        ssize_t ret = ::recv(mInternalFD, data, bufferSize, MSG_NOSIGNAL);
        if(ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK){
            std::stringstream stream;
            stream << "::recv error: " << strerror(errno);
            throw ReceiveError(stream.str());
        }
        return ret;
    }

    ssize_t Socket::sendTo(
        const char* data, 
        size_t dataSize,
        std::shared_ptr<Endpoint> endpoint
    ){
        ssize_t ret = ::sendto(
            mInternalFD, data, dataSize, MSG_NOSIGNAL,
            endpoint->c_addr(), endpoint->addr_size()
        );
        if(ret < 0) throw SendError(
            "Error while trying to Send data to endpoint"
        );
        return ret;
    }

    Socket::UDPPacket Socket::receiveFrom() {
        UDPPacket packet;
        
        sockaddr sender_addr;
        socklen_t sender_addr_len;

        auto ret = ::recvfrom(
            mInternalFD, &packet.message, packet.bufferSize,
            MSG_NOSIGNAL, &sender_addr, &sender_addr_len
        );

        if(ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            throw ReceiveError("Error while trying to receive Data");

        packet.endpoint = std::make_shared<Endpoint>(
            &sender_addr, sender_addr_len
        );

        packet.length = ret;
        return packet;
    }

    ssize_t Socket::operator<<(const std::string& data) const {
        return send(data);
    }

    ssize_t Socket::operator>>(std::string& data)  {
        std::stringstream stream;
        ssize_t size = *this >> stream;
        data = stream.str();
        return size;
    }

    ssize_t Socket::operator>>(std::stringstream& data) {

        ssize_t ret = 0;
        ssize_t acc = 0;
        char* buffer;

        switch(mProtocol){
            case Protocol::TCP:{
                buffer = new char[4096];
                int flag = 0;
                do {
                    ::bzero(buffer, 4096);
                    ret = ::recv(mInternalFD, buffer, 4096, flag);
                    flag = MSG_DONTWAIT;
#if TTDEBUG
                    std::cout << "Received " << ret << "B\n"
                    "Last Error: " << errno << ' ' << strerror(errno) << '\n';
#endif
                    if(ret == 0 && errno == 0 || errno == EWOULDBLOCK) break;

                    if(ret < 0 && errno != EWOULDBLOCK){
                        std::stringstream stream;
                        stream << "::recv error: " << strerror(errno);
                        throw ReceiveError(stream.str());
                    }
                    acc += ret;
                    data << buffer;
                } while (true);
            }
            break;
            case Protocol::UDP:{

                ::bzero(buffer, 508);

                buffer = new char[508];
                ret = ::recv(mInternalFD, buffer, 508, MSG_NOSIGNAL);
                if(ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK){
                    std::stringstream stream;
                    stream << "::recv error: " << strerror(errno);
                    throw ReceiveError(stream.str());
                } 
                data << buffer;
                acc = ret;
            }
            break;
        }
        return acc;
    } 

}