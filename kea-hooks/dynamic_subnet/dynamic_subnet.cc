#include <config.h>
#include <hooks/hooks.h>
#include <dhcp/pkt4.h>
#include <dhcp/hwaddr.h>
#include <dhcpsrv/subnet.h>
#include <dhcpsrv/host_mgr.h>
#include <dhcpsrv/host.h>
#include <dhcpsrv/lease.h>
#include <asiolink/io_address.h>
#include <iostream>

using namespace isc::hooks;
using namespace isc::dhcp;
using namespace isc::asiolink;

extern "C" {

int version() {
    return KEA_HOOKS_VERSION;
}

// Declare multi-threading compatibility
int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    std::cout << "Dynamic Subnet Hook: Loaded successfully" << std::endl;
    return 0;
}

int unload() {
    std::cout << "Dynamic Subnet Hook: Unloaded" << std::endl;
    return 0;
}

int subnet4_select(CalloutHandle& handle) {
    try {
        // Get the query packet
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        // Get the subnet collection
        const Subnet4Collection* subnets = nullptr;
        handle.getArgument("subnet4collection", subnets);
        
        if (!query4 || !subnets || subnets->empty()) {
            std::cout << "Dynamic Subnet Hook: Missing arguments or empty subnet collection" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get hardware address from the packet
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            std::cout << "Dynamic Subnet Hook: No hardware address" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "Dynamic Subnet Hook: Processing packet from MAC: " 
                  << hwaddr->toText() << std::endl;
        
        // Check for host reservation using HostMgr
        ConstHostPtr host;
        
        // Check global reservations first
        host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                          &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
        
        if (!host) {
            // Check each subnet for reservations
            for (const auto& s : *subnets) {
                host = HostMgr::instance().get4Any(s->getID(), Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
                if (host) {
                    break;
                }
            }
        }
        
        // Select the appropriate subnet based on reservation status
        ConstSubnet4Ptr selected_subnet;
        SubnetID target_id = host ? 10 : 11;  // 10 for registered, 11 for unregistered
        
        if (host) {
            std::cout << "Dynamic Subnet Hook: Found reservation for " << hwaddr->toText() 
                      << " - selecting registered subnet (ID 10)" << std::endl;
        } else {
            std::cout << "Dynamic Subnet Hook: No reservation for " << hwaddr->toText()
                      << " - selecting unregistered subnet (ID 11)" << std::endl;
        }
        
        // Find and select the target subnet
        for (const auto& s : *subnets) {
            if (s->getID() == target_id) {
                selected_subnet = s;
                break;
            }
        }
        
        if (selected_subnet) {
            handle.setArgument("subnet4", selected_subnet);
            std::cout << "Dynamic Subnet Hook: Selected subnet " << selected_subnet->toText() << std::endl;
            
            // Check if this is a REQUEST and if the requested IP is compatible with selected subnet
            if (query4->getType() == DHCPREQUEST) {
                IOAddress requested_ip("0.0.0.0");
                
                // Check ciaddr first (used in RENEW/REBIND)
                if (query4->getCiaddr() != IOAddress("0.0.0.0")) {
                    requested_ip = query4->getCiaddr();
                    std::cout << "Dynamic Subnet Hook: Client has ciaddr: " << requested_ip.toText() << std::endl;
                }
                // Then check requested-address option (used in INIT-REBOOT)
                else {
                    OptionPtr requested_ip_option = query4->getOption(DHO_DHCP_REQUESTED_ADDRESS);
                    if (requested_ip_option && requested_ip_option->len() >= 4) {
                        const uint8_t* data = requested_ip_option->getData().data();
                        requested_ip = IOAddress::fromBytes(AF_INET, data);
                        std::cout << "Dynamic Subnet Hook: Client has requested-address: " << requested_ip.toText() << std::endl;
                    }
                }
                
                // If client is requesting a specific IP, check if it's in the selected subnet's pools
                if (requested_ip != IOAddress("0.0.0.0")) {
                    bool in_pool = false;
                    const PoolCollection& pools = selected_subnet->getPools(Lease::TYPE_V4);
                    std::cout << "Dynamic Subnet Hook: Checking if " << requested_ip.toText() 
                              << " is in any of " << pools.size() << " pools" << std::endl;
                    
                    for (const auto& pool : pools) {
                        std::cout << "Dynamic Subnet Hook: Pool: " << pool->getFirstAddress().toText() 
                                  << " - " << pool->getLastAddress().toText() << std::endl;
                        if (pool->inRange(requested_ip)) {
                            in_pool = true;
                            std::cout << "Dynamic Subnet Hook: IP IS in pool" << std::endl;
                            break;
                        }
                    }
                    
                    if (!in_pool) {
                        std::cout << "Dynamic Subnet Hook: IP " << requested_ip.toText() 
                                  << " NOT in any pool of subnet " << selected_subnet->toText() 
                                  << " - will construct NAK response" << std::endl;
                        
                        // Create a NAK response
                        Pkt4Ptr nak = Pkt4Ptr(new Pkt4(DHCPNAK, query4->getTransid()));
                        
                        // Copy addressing information
                        nak->setIface(query4->getIface());
                        nak->setIndex(query4->getIndex());
                        nak->setLocalAddr(query4->getLocalAddr());
                        nak->setLocalPort(DHCP4_SERVER_PORT);
                        nak->setRemoteAddr(query4->getRemoteAddr());
                        nak->setRemotePort(DHCP4_CLIENT_PORT);
                        nak->setHWAddr(query4->getHWAddr());
                        
                        // Copy client identifier if present
                        OptionPtr client_id = query4->getOption(DHO_DHCP_CLIENT_IDENTIFIER);
                        if (client_id) {
                            nak->addOption(client_id);
                        }
                        
                        // Add server identifier (use the local address from the query)
                        OptionBuffer server_id_data;
                        const std::vector<uint8_t>& bytes = query4->getLocalAddr().toBytes();
                        server_id_data.insert(server_id_data.end(), bytes.begin(), bytes.end());
                        OptionPtr server_id = OptionPtr(new Option(Option::V4, DHO_DHCP_SERVER_IDENTIFIER, server_id_data));
                        nak->addOption(server_id);
                        
                        // Set the response
                        handle.setArgument("response4", nak);
                        
                        std::cout << "Dynamic Subnet Hook: NAK response created and set" << std::endl;
                        
                        // Use SKIP to bypass normal processing and send our NAK
                        handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
                        return 0;
                    }
                }
            }
        } else {
            std::cout << "Dynamic Subnet Hook: ERROR - Could not find subnet ID " << target_id << std::endl;
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "Dynamic Subnet Hook ERROR: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

int lease4_select(CalloutHandle& handle) {
    try {
        std::cout << "Dynamic Subnet Hook (lease4_select): ENTERED" << std::endl;
        
        // Get the lease that was selected
        Lease4Ptr lease;
        handle.getArgument("lease4", lease);
        
        // Get the query packet
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        // Get the subnet
        ConstSubnet4Ptr subnet;
        handle.getArgument("subnet4", subnet);
        
        std::cout << "Dynamic Subnet Hook (lease4_select): Got arguments - lease=" 
                  << (lease ? "yes" : "no") << " query4=" << (query4 ? "yes" : "no")
                  << " subnet=" << (subnet ? "yes" : "no") << std::endl;
        
        if (!lease || !query4 || !subnet) {
            std::cout << "Dynamic Subnet Hook (lease4_select): Missing arguments, exiting" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "Dynamic Subnet Hook (lease4_select): Query type=" << (int)query4->getType() 
                  << " Lease IP=" << lease->addr_.toText() 
                  << " Subnet=" << subnet->toText() << std::endl;
        
        // Only interested in REQUEST packets
        if (query4->getType() != DHCPREQUEST) {
            std::cout << "Dynamic Subnet Hook (lease4_select): Not a REQUEST, skipping" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get hardware address
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            std::cout << "Dynamic Subnet Hook (lease4_select): No hardware address, exiting" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get the requested IP address
        IOAddress requested_ip("0.0.0.0");
        
        // Check ciaddr first (used in RENEW/REBIND)
        if (query4->getCiaddr() != IOAddress("0.0.0.0")) {
            std::cout << "Dynamic Subnet Hook (lease4_select): Found ciaddr: " 
                      << query4->getCiaddr().toText() << std::endl;
            requested_ip = query4->getCiaddr();
        }
        // Then check requested-address option (used in INIT-REBOOT)
        else {
            OptionPtr requested_ip_option = query4->getOption(DHO_DHCP_REQUESTED_ADDRESS);
            if (requested_ip_option && requested_ip_option->len() >= 4) {
                std::cout << "Dynamic Subnet Hook (lease4_select): Found requested-address option" << std::endl;
                const uint8_t* data = requested_ip_option->getData().data();
                requested_ip = IOAddress::fromBytes(AF_INET, data);
            }
        }
        
        std::cout << "Dynamic Subnet Hook (lease4_select): Client " << hwaddr->toText() 
                  << " requesting IP " << requested_ip.toText() << std::endl;
        
        // Check if the requested IP belongs to any pool in this subnet
        bool in_pool = false;
        const PoolCollection& pools = subnet->getPools(Lease::TYPE_V4);
        std::cout << "Dynamic Subnet Hook (lease4_select): Checking " << pools.size() << " pools" << std::endl;
        
        for (const auto& pool : pools) {
            std::cout << "Dynamic Subnet Hook (lease4_select): Pool range: " 
                      << pool->getFirstAddress().toText() << " - " 
                      << pool->getLastAddress().toText() << std::endl;
            if (pool->inRange(requested_ip)) {
                in_pool = true;
                std::cout << "Dynamic Subnet Hook (lease4_select): Requested IP " << requested_ip.toText() 
                          << " IS in this pool" << std::endl;
                break;
            }
        }
        
        if (!in_pool && requested_ip != IOAddress("0.0.0.0")) {
            std::cout << "Dynamic Subnet Hook (lease4_select): Requested IP " << requested_ip.toText() 
                      << " not in any pool of subnet " << subnet->toText() 
                      << " - dropping lease to force NAK" << std::endl;
            
            // Drop the lease - this will cause Kea to send NAK
            handle.setArgument("lease4", Lease4Ptr());
            
            std::cout << "Dynamic Subnet Hook (lease4_select): Lease dropped, Kea should send NAK" << std::endl;
        } else {
            std::cout << "Dynamic Subnet Hook (lease4_select): Requested IP is valid - allowing lease" << std::endl;
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "Dynamic Subnet Hook lease4_select ERROR: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

int pkt4_send(CalloutHandle& handle) {
    try {
        std::cout << "Dynamic Subnet Hook (pkt4_send): ENTERED" << std::endl;
        
        // Get the response packet
        Pkt4Ptr response;
        handle.getArgument("response4", response);
        
        // Get the query packet
        Pkt4Ptr query4;
        handle.getArgument("query4", query4);
        
        // Get the subnet
        ConstSubnet4Ptr subnet;
        handle.getArgument("subnet4", subnet);
        
        std::cout << "Dynamic Subnet Hook (pkt4_send): Got arguments - response=" 
                  << (response ? "yes" : "no") << " query4=" << (query4 ? "yes" : "no")
                  << " subnet=" << (subnet ? "yes" : "no") << std::endl;
        
        if (!response || !query4 || !subnet) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): Missing arguments, exiting" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "Dynamic Subnet Hook (pkt4_send): Response type=" << (int)response->getType() 
                  << " Query type=" << (int)query4->getType() << std::endl;
        
        // Only interested in ACK responses that we might need to convert to NAK
        if (response->getType() != DHCPACK) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): Not an ACK, skipping" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Only interested in REQUEST packets (RENEW/REBIND/INIT-REBOOT)
        if (query4->getType() != DHCPREQUEST) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): Not a REQUEST, skipping" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get hardware address
        HWAddrPtr hwaddr = query4->getHWAddr();
        if (!hwaddr) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): No hardware address, exiting" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        // Get the requested IP address
        IOAddress requested_ip("0.0.0.0");
        
        // Check ciaddr first (used in RENEW/REBIND)
        if (query4->getCiaddr() != IOAddress("0.0.0.0")) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): Found ciaddr: " 
                      << query4->getCiaddr().toText() << std::endl;
            requested_ip = query4->getCiaddr();
        }
        // Then check requested-address option (used in INIT-REBOOT)
        else {
            OptionPtr requested_ip_option = query4->getOption(DHO_DHCP_REQUESTED_ADDRESS);
            if (requested_ip_option && requested_ip_option->len() >= 4) {
                std::cout << "Dynamic Subnet Hook (pkt4_send): Found requested-address option: " 
                          << requested_ip_option->toText() << std::endl;
                const uint8_t* data = requested_ip_option->getData().data();
                requested_ip = IOAddress::fromBytes(AF_INET, data);
            }
        }
        
        // If no requested IP, nothing to check
        if (requested_ip == IOAddress("0.0.0.0")) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): No requested IP, exiting" << std::endl;
            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
            return 0;
        }
        
        std::cout << "Dynamic Subnet Hook (pkt4_send): Client " << hwaddr->toText() 
                  << " requesting IP " << requested_ip.toText() 
                  << " in subnet " << subnet->toText() << std::endl;
        
        // Check if the requested IP belongs to any pool in this subnet
        bool in_pool = false;
        const PoolCollection& pools = subnet->getPools(Lease::TYPE_V4);
        std::cout << "Dynamic Subnet Hook (pkt4_send): Checking " << pools.size() << " pools" << std::endl;
        
        for (const auto& pool : pools) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): Pool range: " 
                      << pool->getFirstAddress().toText() << " - " 
                      << pool->getLastAddress().toText() << std::endl;
            if (pool->inRange(requested_ip)) {
                in_pool = true;
                std::cout << "Dynamic Subnet Hook (pkt4_send): IP " << requested_ip.toText() 
                          << " IS in this pool" << std::endl;
                break;
            }
        }
        
        if (!in_pool) {
            std::cout << "Dynamic Subnet Hook (pkt4_send): IP " << requested_ip.toText() 
                      << " not in any pool of subnet " << subnet->toText() 
                      << " - converting ACK to NAK" << std::endl;
            
            // Convert ACK to NAK
            response->setType(DHCPNAK);
            response->setYiaddr(IOAddress("0.0.0.0"));
            
            std::cout << "Dynamic Subnet Hook (pkt4_send): NAK conversion complete - response type now=" 
                      << (int)response->getType() << " (NAK=6)" << std::endl;
            
            // Clear any options that shouldn't be in a NAK
            response->delOption(DHO_DHCP_LEASE_TIME);
            response->delOption(DHO_DHCP_RENEWAL_TIME);
            response->delOption(DHO_DHCP_REBINDING_TIME);
        } else {
            std::cout << "Dynamic Subnet Hook (pkt4_send): IP " << requested_ip.toText() 
                      << " is in a valid pool - allowing ACK" << std::endl;
        }
        
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 0;
        
    } catch (const std::exception& ex) {
        std::cout << "Dynamic Subnet Hook pkt4_send ERROR: " << ex.what() << std::endl;
        handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
        return 1;
    }
}

}
