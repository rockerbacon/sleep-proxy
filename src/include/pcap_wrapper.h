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

#pragma once

#include <array>
#include <functional>
#include <memory>
#include <pcap/pcap.h>
#include <string>
#include <thread>
#include <vector>

/** Provide a nice interface to pcap and close the handle upon an exception */
struct Pcap_wrapper {
  enum class Loop_end_reason {
    unset,
    packets_captured,
    signal,
    duplicate_address,
    error
  };

private:
  /** error buffer */
  std::array<char, PCAP_ERRBUF_SIZE> errbuf{{0}};
  /** pointer to the opened pcap_t struct with its close function */
  std::unique_ptr<pcap_t, void (*)(pcap_t *)> pc;
  std::thread loop_thread;
  Loop_end_reason loop_end_reason = Loop_end_reason::unset;

protected:
  /** this is only present to run tests as non-root, do not use */
  Pcap_wrapper();

  Loop_end_reason get_end_reason() const;

public:
  static auto const default_snaplen = int{65000};
  static auto const default_timeout = int{1000};

  /** open a pcap instance on iface */
  explicit Pcap_wrapper(std::string const &iface, int snaplen = default_snaplen,
                        bool promisc = false, int timeout = default_timeout);

  Pcap_wrapper(Pcap_wrapper const &) = delete;
  Pcap_wrapper(Pcap_wrapper &&) = default;

  virtual ~Pcap_wrapper();

  Pcap_wrapper &operator=(Pcap_wrapper const &) = delete;
  Pcap_wrapper &operator=(Pcap_wrapper &&) = default;

  /** tell if the first header is ethernet, unix socket, ... */
  int get_datalink() const;

  std::string get_verbose_datalink() const;

  /** sets a BPF (berkeley packet filter) filter the pcap instance */
  void set_filter(const std::string &filter);

  /** sniff count packets calling cb each time */
  using Callback_t =
      std::function<void(const struct pcap_pkthdr *, const u_char *)>;
  virtual Pcap_wrapper::Loop_end_reason loop(int count, Callback_t cb);

  void break_loop(const Loop_end_reason &ler);

  int inject(const std::vector<uint8_t> &data);
};
