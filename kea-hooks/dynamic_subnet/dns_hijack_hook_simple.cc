// DNS Hijack Hook - checks MAC registration status before hijacking
#include <hooks/hooks.h>
#include <dhcpsrv/lease.h>
#include <dhcp/hwaddr.h>
#include <iostream>
#include <cstdlib>
#include <algorithm>

using namespace isc::hooks;
using namespace isc::dhcp;

extern "C" {

int version() {
    return 30002;
}

int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "DNS Hijack Hook: Loaded (MAC-aware mode)" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook: Unloaded" << std::endl;
    return 0;
}

bool is_mac_registered(const std::string& mac) {
    // Query PostgreSQL to check if MAC is registered
    std::string mac_hex = mac;
    // Remove colons from MAC address
    mac_hex.erase(std::remove(mac_hex.begin(), mac_hex.end(), ':'), mac_hex.end());
    
    std::string query = "PGPASSWORD=change_this_password psql -h 127.0.0.1 -U portal_user -d captive_portal -t -c \"SELECT COUNT(*) FROM hosts WHERE encode(dhcp_identifier, 'hex') = '" + mac_hex + "'\" 2>/dev/null";
    
    FILE* pipe = popen(query.c_str(), "r");
    if (!pipe) {
        std::cout << "DNS Hijack: Failed to query database for MAC " << mac << std::endl;
        return false;
    }
    
    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    
    // Trim whitespace
    result.erase(0, result.find_first_not_of(" \n\r\t"));
    result.erase(result.find_last_not_of(" \n\r\t") + 1);
    
    bool registered = (!result.empty() && result != "0");
    std::cout << "DNS Hijack: MAC " << mac << " registration check: " << (registered ? "REGISTERED" : "UNREGISTERED") << std::endl;
    std::cout.flush();
    
    return registered;
}

void call_hijack(const std::string& ip) {
    // Add iptables rules directly (container has NET_ADMIN capability)
    // Check if rules already exist before adding
    std::string check_udp = "iptables -t nat -C PREROUTING -s " + ip + " -d 192.168.99.4 -p udp --dport 53 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null";
    std::string check_tcp = "iptables -t nat -C PREROUTING -s " + ip + " -d 192.168.99.4 -p tcp --dport 53 -j DNAT --to-destination 192.168.99.5:53 2>/dev/null";
    
    if (system(check_udp.c_str()) != 0) {
        std::string cmd_udp = "iptables -t nat -A PREROUTING -s " + ip + " -d 192.168.99.4 -p udp --dport 53 -j DNAT --to-destination 192.168.99.5:53";
        int ret = system(cmd_udp.c_str());
        std::cout << "DNS Hijack: Added UDP rule for " << ip << " (ret=" << ret << ")" << std::endl;
        std::cout.flush();
    }
    
    if (system(check_tcp.c_str()) != 0) {
        std::string cmd_tcp = "iptables -t nat -A PREROUTING -s " + ip + " -d 192.168.99.4 -p tcp --dport 53 -j DNAT --to-destination 192.168.99.5:53";
        int ret = system(cmd_tcp.c_str());
        std::cout << "DNS Hijack: Added TCP rule for " << ip << " (ret=" << ret << ")" << std::endl;
        std::cout.flush();
    }
}

int lease4_select(CalloutHandle& handle) {
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (!lease) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string ip = lease->addr_.toText();
        std::string mac = hwaddr->toText(false);
        
        std::cout << "DNS Hijack Hook: lease4_select - MAC=" << mac << " IP=" << ip << std::endl;
        std::cout.flush();
        
        // Only hijack if MAC is NOT registered
        if (!is_mac_registered(mac)) {
            std::cout << "DNS Hijack Hook: Hijacking " << ip << " (unregistered MAC)" << std::endl;
            std::cout.flush();
            call_hijack(ip);
        } else {
            std::cout << "DNS Hijack Hook: Skipping " << ip << " (registered MAC)" << std::endl;
            std::cout.flush();
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cerr << "DNS Hijack Hook ERROR in lease4_select: " << ex.what() << std::endl;
        std::cerr.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

int lease4_renew(CalloutHandle& handle) {
    try {
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        if (!lease) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        HWAddrPtr hwaddr = lease->hwaddr_;
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::string ip = lease->addr_.toText();
        std::string mac = hwaddr->toText(false);
        
        std::cout << "DNS Hijack Hook: lease4_renew - MAC=" << mac << " IP=" << ip << std::endl;
        std::cout.flush();
        
        // Only hijack if MAC is NOT registered
        if (!is_mac_registered(mac)) {
            std::cout << "DNS Hijack Hook: Hijacking " << ip << " (unregistered MAC)" << std::endl;
            std::cout.flush();
            call_hijack(ip);
        } else {
            std::cout << "DNS Hijack Hook: Skipping " << ip << " (registered MAC)" << std::endl;
            std::cout.flush();
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cerr << "DNS Hijack Hook ERROR in lease4_renew: " << ex.what() << std::endl;
        std::cerr.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

}
