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

#include "socket.h"
#include "log.h"
#include "to_string.h"
#include <cstring>
#include <linux/if_ether.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>

Socket::Socket(int domain, int type, int protocol)
    : sock{socket(domain, type, protocol)} {
  if (sock < 0) {
    throw std::runtime_error(std::string("sock() failed with errno: ") +
                             strerror(errno));
  }
}

Socket::~Socket() {
  if (close(sock) != 0) {
    log_string(LOG_ERR,
               std::string("close() failed with errno: ") + strerror(errno));
  }
}

void Socket::ioctl(const unsigned long req_number, ifreq &ifr) const {
  if (::ioctl(sock, req_number, &ifr) == -1) {
    throw std::runtime_error(std::string("ioctl() failed with request ") +
                             to_string(req_number) + ": " + strerror(errno));
  }
}

ifreq get_ifreq(const std::string &iface) {
  struct ifreq ifr {
    {{0}}, {
      {
        0, { 0 }
      }
    }
  };
  std::copy(std::begin(iface), std::end(iface), std::begin(ifr.ifr_name));
  return ifr;
}

int Socket::get_ifindex(const std::string &iface) const {
  struct ifreq ifr = get_ifreq(iface);
  ioctl(SIOCGIFINDEX, ifr);
  return ifr.ifr_ifindex;
}

ether_addr Socket::get_hwaddr(const std::string &iface) const {
  struct ifreq ifr = get_ifreq(iface);
  ioctl(SIOCGIFHWADDR, ifr);
  ether_addr addr;
  std::copy(ifr.ifr_hwaddr.sa_data,
            ifr.ifr_hwaddr.sa_data + sizeof(addr.ether_addr_octet),
            std::begin(addr.ether_addr_octet));
  return addr;
}
