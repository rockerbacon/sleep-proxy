// Copyright (C) 2014  Lutz Reinhardt
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "main.h"
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "packet_test_utils.h"
#include "ethernet.h"

#include "socket.h"

struct Socket_listen : public Socket {
  Socket_listen(int domain, int type, int protocol = 0)
      : Socket(domain, type, protocol) {}

  template <typename Sockaddr> void bind(Sockaddr &&sockaddr) {
    const int ret_val =
        ::bind(sock, reinterpret_cast<const struct sockaddr *>(&sockaddr),
               sizeof(Sockaddr));
    if (ret_val != 0) {
      throw std::runtime_error(std::string("bind() failed: ") +
                               strerror(errno));
    }
  }

  std::vector<uint8_t> recv(size_t len = 2000) {
    std::vector<uint8_t> data(len);
    ssize_t read_data = ::recv(sock, data.data(), len, 0);
    if (read_data == -1) {
      throw std::runtime_error(std::string("recv() failed: ") +
                               strerror(errno));
    }
    data.resize(static_cast<size_t>(read_data));
    return data;
  }

  template <typename Optval> Optval get_sock_opt(int level, int optname) const {
    Optval optval;
    socklen_t optlen = sizeof(Optval);
    const int ret_val = getsockopt(sock, level, optname, &optval, &optlen);
    if (ret_val) {
      throw std::runtime_error(std::string("getsockopt() failed: ") +
                               strerror(errno));
    }
    return optval;
  }

  void close_early() { close(sock); }
};

class Socket_test : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(Socket_test);
  CPPUNIT_TEST(test_constructor_throws);
  CPPUNIT_TEST(test_ioctl_throws);
  CPPUNIT_TEST(test_send_to);
  CPPUNIT_TEST(test_get_ifindex);
  CPPUNIT_TEST(test_set_sock_opt);
  CPPUNIT_TEST(test_destructor);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override {}

  void tearDown() override {}

  void test_constructor_throws() {
    CPPUNIT_ASSERT_THROW(Socket(-1, -1), std::runtime_error);
  }

  void test_ioctl_throws() {
    Socket s0(AF_INET, SOCK_DGRAM);

    struct ifreq ifreq {
      {
        { 0 }
      }
      , {
        {
          0, { 0 }
        }
      }
    };

    CPPUNIT_ASSERT_THROW(s0.ioctl(0, ifreq), std::runtime_error);
  }

  void test_send_to() {
    sockaddr_in addr{0, 0, {0}, {0}};
    addr.sin_family = AF_INET;
    addr.sin_port = 31337;

    // Socket(int domain, int type, int protocol = 0)
    Socket_listen s0(AF_INET, SOCK_DGRAM);
    s0.bind(addr);

    std::vector<uint8_t> data{1, 2, 3};
    Socket s1(AF_INET, SOCK_DGRAM);

    s1.send_to(data, 0, addr);
    CPPUNIT_ASSERT(data == s0.recv());
    data.clear();
    s1.send_to(data, 0, addr);
    CPPUNIT_ASSERT(data == s0.recv());
    data.push_back(255);
    data.push_back(0);
    data.push_back(255);
    data.push_back(0);
    data.push_back(128);
    data.push_back(127);
    data.push_back(64);
    s1.send_to(data, 0, addr);
    CPPUNIT_ASSERT(data == s0.recv());

    sockaddr_in const broken_addr{0xff, 0xff, {0xff}, {0xff}};
    CPPUNIT_ASSERT_THROW(s1.send_to(data, 0, broken_addr), std::runtime_error);
  }

  void test_get_ifindex() {
    // Socket(int domain, int type, int protocol = 0)
    Socket s0(AF_INET, SOCK_DGRAM);

    CPPUNIT_ASSERT_EQUAL(1, s0.get_ifindex("lo"));
    CPPUNIT_ASSERT(1 < s0.get_ifindex("eth0"));
    const ether_addr ea = s0.get_hwaddr("eth0");
    CPPUNIT_ASSERT("" != binary_to_mac(ea));
  }

  void test_set_sock_opt() {
    Socket_listen sock(AF_INET, SOCK_DGRAM);
    CPPUNIT_ASSERT_EQUAL(0, sock.get_sock_opt<int>(SOL_SOCKET, SO_BROADCAST));
    sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 1);
    CPPUNIT_ASSERT_EQUAL(1, sock.get_sock_opt<int>(SOL_SOCKET, SO_BROADCAST));
    sock.set_sock_opt(SOL_SOCKET, SO_BROADCAST, 0);
    CPPUNIT_ASSERT_EQUAL(0, sock.get_sock_opt<int>(SOL_SOCKET, SO_BROADCAST));

    CPPUNIT_ASSERT_THROW(sock.set_sock_opt(-1, -1, -1), std::runtime_error);
  }

  void test_destructor() {
    auto out_in = get_self_pipes();
    {
      Tmp_fd_remap const out_remap(std::get<1>(out_in),
                                   get_fd_from_stream(stdout));
      {
        Socket_listen sock(AF_INET, SOCK_DGRAM);
        sock.close_early();
      }
      std::cout << std::flush;
    }
    auto const log_text = std::get<0>(out_in).read();
    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(1), log_text.size());
    CPPUNIT_ASSERT_EQUAL(
        std::string("close() failed with errno: Bad file descriptor"),
        log_text.at(0));
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(Socket_test);
