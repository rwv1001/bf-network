// #include <config.h>  // Not needed for basic hooks
#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcp/hwaddr.h>
#include <dhcpsrv/subnet.h>
#include <dhcpsrv/host_mgr.h>
#include <dhcpsrv/host.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>
#include <iostream>
#include <cstdlib>
#include <sstream>

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace isc::asiolink;

extern "C" {

int version() {
    return 30002;  // Kea 3.0.2 - hardcoded since we compile with 2.6.3 headers
}

// Declare multi-threading compatibility
int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "DNS Hijack Hook: Loaded successfully" << std::endl;
    return 0;
}

int unload() {
    std::cout << "DNS Hijack Hook: Unloaded" << std::endl;
    return 0;
}

// Helper function to call DNS hijacking script
void manage_dns_hijack(const std::string& action, const std::string& ip_address) {
    std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack ENTRY (action=" 
              << action << ", ip=" << ip_address << ")" << std::endl;
    std::cout.flush();
    
    std::stringstream cmd;
    
    std::cout << "DNS Hijack Hook: [DEBUG] Building command" << std::endl;
    std::cout.flush();
    
    // Run in background to avoid blocking Kea
    cmd << "/scripts/dns-hijack.sh " << action << " " << ip_address << " >/dev/null 2>&1 &";
    
    std::cout << "DNS Hijack Hook: [DEBUG] Command: " << cmd.str() << std::endl;
    std::cout.flush();
    
    std::cout << "DNS Hijack Hook: [DEBUG] Calling system()" << std::endl;
    std::cout.flush();
    
    int status = system(cmd.str().c_str());
    
    std::cout << "DNS Hijack Hook: [DEBUG] system() returned: " << status << std::endl;
    std::cout.flush();
    
    if (status != 0) {
        std::cerr << "DNS Hijack Hook WARNING: Script launch status " << status << std::endl;
        std::cerr.flush();
    }
    
    std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack EXIT" << std::endl;
    std::cout.flush();
}

int lease4_select(CalloutHandle& handle) {
    try {
        // Get the lease that was selected
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        // Get the query packet
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        if (!lease || !query4) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get hardware address
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get the allocated IP address
        std::string ip_address = lease->addr_.toText();
        std::string mac_address = hwaddr->toText();
        
        std::cout << "DNS Hijack Hook: Lease allocated - MAC: " << mac_address 
                  << " IP: " << ip_address << std::endl;
        
        // Check if device has a reservation (is registered)
        ConstHostPtr host;
        
        // Check global reservations
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        // Check subnet-specific reservations if not found globally
        if (!host) {
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            if (subnet) {
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
            }
        }
        
        if (host) {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is REGISTERED - removing DNS hijack" << std::endl;
            manage_dns_hijack("unhijack", ip_address);
        } else {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            manage_dns_hijack("hijack", ip_address);
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook ERROR: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

// Called when a lease is being renewed (RENEW/REBIND/INIT-REBOOT)
int lease4_renew(CalloutHandle& handle) {
    std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew ENTRY" << std::endl;
    std::cout.flush();
    
    try {
        std::cout << "DNS Hijack Hook: [DEBUG] Getting lease4" << std::endl;
        std::cout.flush();
        
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        std::cout << "DNS Hijack Hook: [DEBUG] Got lease4, checking if NULL" << std::endl;
        std::cout.flush();
        
        if (!lease) {
            std::cout << "DNS Hijack Hook: [DEBUG] lease4 is NULL, returning" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Getting hwaddr from lease" << std::endl;
        std::cout.flush();
        
        // Get hardware address from lease
        HWAddrPtr hwaddr = lease->hwaddr_;
        
        std::cout << "DNS Hijack Hook: [DEBUG] Got hwaddr, checking if NULL" << std::endl;
        std::cout.flush();
        
        if (!hwaddr) {
            std::cout << "DNS Hijack Hook: [DEBUG] hwaddr is NULL, returning" << std::endl;
            std::cout.flush();
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Converting IP to text" << std::endl;
        std::cout.flush();
        
        std::string ip_address = lease->addr_.toText();
        
        std::cout << "DNS Hijack Hook: [DEBUG] IP: " << ip_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: [DEBUG] Converting MAC to text" << std::endl;
        std::cout.flush();
        
        std::string mac_address = hwaddr->toText(false);
        
        std::cout << "DNS Hijack Hook: [DEBUG] MAC: " << mac_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: Lease renewal - MAC: " << mac_address 
                  << " IP: " << ip_address << std::endl;
        std::cout.flush();
        
        std::cout << "DNS Hijack Hook: [DEBUG] Checking for reservation" << std::endl;
        std::cout.flush();
        
        // Check if device has a reservation (is registered)
        ConstHostPtr host;
        
        std::cout << "DNS Hijack Hook: [DEBUG] Checking global reservations" << std::endl;
        std::cout.flush();
        
        // Check global reservations
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        std::cout << "DNS Hijack Hook: [DEBUG] Global check done, host=" 
                  << (host ? "FOUND" : "NULL") << std::endl;
        std::cout.flush();
        
        // Check subnet-specific reservations if not found globally
        if (!host) {
            std::cout << "DNS Hijack Hook: [DEBUG] Checking subnet reservations" << std::endl;
            std::cout.flush();
            
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);
            
            std::cout << "DNS Hijack Hook: [DEBUG] Got subnet4" << std::endl;
            std::cout.flush();
            
            if (subnet) {
                std::cout << "DNS Hijack Hook: [DEBUG] Subnet valid, querying HostMgr" << std::endl;
                std::cout.flush();
                
                host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
                
                std::cout << "DNS Hijack Hook: [DEBUG] Subnet check done, host=" 
                          << (host ? "FOUND" : "NULL") << std::endl;
                std::cout.flush();
            }
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Reservation check complete" << std::endl;
        std::cout.flush();
        
        if (host) {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is REGISTERED - removing DNS hijack" << std::endl;
            std::cout.flush();
            
            std::cout << "DNS Hijack Hook: [DEBUG] Calling manage_dns_hijack(unhijack)" << std::endl;
            std::cout.flush();
            
            manage_dns_hijack("unhijack", ip_address);
            
            std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack(unhijack) returned" << std::endl;
            std::cout.flush();
        } else {
            std::cout << "DNS Hijack Hook: Device " << mac_address 
                      << " is UNREGISTERED - enabling DNS hijack" << std::endl;
            std::cout.flush();
            
            std::cout << "DNS Hijack Hook: [DEBUG] Calling manage_dns_hijack(hijack)" << std::endl;
            std::cout.flush();
            
            manage_dns_hijack("hijack", ip_address);
            
            std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack(hijack) returned" << std::endl;
            std::cout.flush();
        }
        
        std::cout << "DNS Hijack Hook: [DEBUG] Setting NEXT_STEP_CONTINUE" << std::endl;
        std::cout.flush();
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        
        std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew EXIT (success)" << std::endl;
        std::cout.flush();
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "DNS Hijack Hook ERROR in lease4_renew: " << ex.what() << std::endl;
        std::cout.flush();
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

}
