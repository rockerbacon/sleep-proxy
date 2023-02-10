# Copyright (C) 2017  Lutz Reinhardt
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

sleep_proxy_sources = files('sleep-proxy/pcap_wrapper.cpp', 'sleep-proxy/ethernet.cpp', 'sleep-proxy/ip.cpp', 'sleep-proxy/scope_guard.cpp', 'sleep-proxy/ip_utils.cpp', 'sleep-proxy/socket.cpp', 'sleep-proxy/args.cpp', 'sleep-proxy/to_string.cpp', 'sleep-proxy/libsleep_proxy.cpp', 'sleep-proxy/spawn_process.cpp', 'sleep-proxy/int_utils.cpp', 'sleep-proxy/wol.cpp', 'sleep-proxy/packet_parser.cpp', 'sleep-proxy/log.cpp', 'sleep-proxy/ip_address.cpp', 'sleep-proxy/file_descriptor.cpp', 'sleep-proxy/duplicate_address_watcher.cpp', 'sleep-proxy/wol_watcher.cpp')

pcap_dep = meson.get_compiler('cpp').find_library('pcap')
thread_dep = dependency('threads')

sleep_proxy_include = include_directories('include')
sleep_proxy_lib = static_library(
        'sleep-proxy',
         sleep_proxy_sources,
         dependencies : [pcap_dep, thread_dep],
         include_directories : sleep_proxy_include)
sleep_proxy_dep = declare_dependency(
        link_with : sleep_proxy_lib,
        include_directories : sleep_proxy_include,
        dependencies: thread_dep)

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries : sleep_proxy_lib,
                 version : '0.0.1',
                 name : 'sleep_proxy',
                 filebase : 'sleep_proxy',
                 description : 'A Library to barnicate your foos.')

programs = ['emulateHost', 'waker', 'sniffer', 'watchHost']

foreach pr : programs
        executable(pr, '@0@.cpp'.format(pr), dependencies : [sleep_proxy_dep])
endforeach
