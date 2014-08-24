#include "scope_guard.h"
#include <iostream>
#include <map>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include "to_string.h"
#include "ip_utils.h"
#include "split.h"
#include "spawn_process.h"

Scope_guard::Scope_guard() : freed{true}, aquire_release{} {
}

Scope_guard::Scope_guard(std::function<std::string(const Action)> aquire_release_arg) : freed{false}, aquire_release(aquire_release_arg) {
        take_action(Action::add);
}

Scope_guard::Scope_guard(Scope_guard&& rhs) : freed{std::move(rhs.freed)}, aquire_release(std::move(rhs.aquire_release)) {
        rhs.freed = true;
}

Scope_guard::~Scope_guard() {
        free();
}

void Scope_guard::free() {
        if (!freed) {
                take_action(Action::del);
                freed = true;
        }
}

void Scope_guard::take_action(const Action a) const {
        std::string cmd = aquire_release(a);
        if (cmd.size() > 0 ) {
                std::cout << cmd << std::endl;
                pid_t pid = spawn(split(cmd, ' '));
                uint8_t status = wait_until_pid_exits(pid);
                if (status != 0) {
                        throw std::runtime_error("command failed: " + cmd);
                }
        }
}

bool file_exists(const std::string& filename) {
        struct stat stats;
        auto errno_save = errno;
        bool ret_val = stat(filename.c_str(), &stats) == 0;
        errno = errno_save;
        return ret_val;
}

const std::array<std::string, 4> paths{{"/sbin", "/usr/sbin", "/bin", "/usr/bin"}};

std::string get_path(const std::string command) {
        for (const auto& p : paths) {
                const std::string fn = p + '/' + command;
                if (file_exists(fn))
                        return fn;
        }
        throw std::runtime_error("unable to find path for file: " + command);
        return "";
}

std::string Temp_ip::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "add"}, {Action::del, "del"}};
        std::string saction{which_action.at(action)};
        return get_path("ip") + " addr " + saction + " " + ip + " dev " + iface;
}

/**
 * ipv4 and ipv6 have different iptables commands. return the one matching
 * the version of ip
 */
std::string get_iptables_cmd(const std::string& ip) {
        const static std::map<int, std::string> which_iptcmd{{AF_INET, "iptables"}, {AF_INET6, "ip6tables"}};
        return get_path(which_iptcmd.at(getAF(ip)));
}

std::string Block_rst::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        std::string saction{which_action.at(action)};
        return get_iptables_cmd(ip) + " -w -" + saction + " OUTPUT -s " + get_pure_ip(ip) + " -p tcp --tcp-flags ALL RST,ACK -j DROP";
}

std::string Open_port::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        std::string saction{which_action.at(action)};
        std::string iptcmd = get_iptables_cmd(ip);
        std::string pip = get_pure_ip(ip);
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p tcp --syn --dport " + to_string(port) + " -j ACCEPT";
}

std::string Reject_tp::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        const static std::map<TP, std::string> which_tp{{TP::TCP, "tcp"}, {TP::UDP, "udp"}};
        std::string saction{which_action.at(action)};
        std::string stp{which_tp.at(tcp_udp)};
        std::string iptcmd = get_iptables_cmd(ip);
        std::string pip = get_pure_ip(ip);
        return iptcmd + " -w -" + saction + " INPUT -d " + pip + " -p " + stp + " -j REJECT";
}


std::string Reject_outgoing_tcp::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        const std::string saction{which_action.at(action)};
        const std::string iptcmd = get_iptables_cmd(ip);
        const std::string pip = get_pure_ip(ip);
        return iptcmd + " -w -" + saction + " OUTPUT -s " + pip + " -p tcp -j REJECT";
}

/**
 * in iptables the icmp parameter is differenct for IPv4 and IPv6. return
 * the correct one according to the ip version
 */
std::string get_icmp_version(const std::string& ip) {
        switch (getAF(ip)) {
                case AF_INET: return "icmp";
                case AF_INET6: return "icmpv6";
		default: throw std::runtime_error("can't determine icmp type for ip:" + ip);
        }
        return "";
}

std::string Block_icmp::operator()(const Action action) const {
        const static std::map<Action, std::string> which_action{{Action::add, "I"}, {Action::del, "D"}};
        std::string saction{which_action.at(action)};
        std::string iptcmd = get_iptables_cmd(ip);
        std::string icmpv = get_icmp_version(ip);
        return iptcmd + " -w -" + saction + " OUTPUT -d " + get_pure_ip(ip) + " -p " + icmpv + " --" + icmpv + "-type destination-unreachable -j DROP";
}

