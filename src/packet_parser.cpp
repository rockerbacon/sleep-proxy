#include "packet_parser.h"
#include "log.h"

template<typename T>
void print_if_not_nullptr(std::ostream& out, T&& ptr) {
        if (ptr != nullptr) {
                out << *ptr;
        }
}

std::ostream& operator<<(std::ostream& out, const basic_headers& headers) {
        print_if_not_nullptr(out, std::get<0>(headers));
        out << '\n';
        print_if_not_nullptr(out, std::get<1>(headers));
        out << '\n';
        print_if_not_nullptr(out, std::get<2>(headers));
        return out;
}

basic_headers get_headers(const int type, const std::vector<u_char>& packet) {
        std::vector<u_char>::const_iterator data = std::begin(packet);
        std::vector<u_char>::const_iterator end = std::end(packet);

        // link layer header
        std::unique_ptr<Link_layer> ll = parse_link_layer(type, data, end);
        if (ll == nullptr) {
                log(LOG_ERR, "unsupported link layer protocol: %i", type);
                return std::make_tuple(std::unique_ptr<Link_layer>(nullptr), std::unique_ptr<ip>(nullptr), std::unique_ptr<tp>(nullptr));
        }
        data += static_cast<std::vector<u_char>::const_iterator::difference_type>(ll->header_length());

        // possible VLAN header, skip it
        uint16_t payload_type = ll->payload_protocol();
        if (payload_type == VLAN_HEADER) {
                std::unique_ptr<Link_layer> vlan_header = parse_link_layer(payload_type, data, end);
                payload_type = vlan_header->payload_protocol();
                data += static_cast<std::vector<u_char>::const_iterator::difference_type>(vlan_header->header_length());
        }

        // IP header
        std::unique_ptr<ip> ipp = parse_ip(payload_type, data, end);
        if (ipp == nullptr) {
                log(LOG_ERR, "unsupported link layer payload: %u", payload_type);
                return std::make_tuple(std::move(ll), std::unique_ptr<ip>(nullptr), std::unique_ptr<tp>(nullptr));
        }
        data += static_cast<std::vector<u_char>::const_iterator::difference_type>(ipp->header_length());

        // TCP/UDP header
        std::unique_ptr<tp> tpp = parse_tp(ipp->payload_protocol(), data, end);
        if (tpp == nullptr) {
                log(LOG_ERR, "unsupported ip payload: %u", ipp->payload_protocol());
        }

        return std::make_tuple(std::move(ll), std::move(ipp), std::move(tpp));
}

Catch_incoming_connection::Catch_incoming_connection(const int link_layer_typee) : link_layer_type(link_layer_typee) {}

void Catch_incoming_connection::operator()(const pcap_pkthdr * header, const u_char * packet) {
        if (header == nullptr || packet == nullptr) {
                log_string(LOG_ERR, "header or packet are nullptr");
                return;
        }
        data = std::vector<uint8_t>(packet, packet + header->len);
        headers = get_headers(link_layer_type, data);
}

