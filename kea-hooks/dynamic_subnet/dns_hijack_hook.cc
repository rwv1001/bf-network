// #include <config.h>  // Not needed for basic hooks

#include <hooks/hooks.h>

#include <dhcp/pkt4.h>

#include <dhcp/dhcp4.h>

#include <dhcp/hwaddr.h>

#include <dhcpsrv/subnet.h>

#include <dhcpsrv/host_mgr.h>

#include <dhcpsrv/host.h>

#include <dhcpsrv/client_class_def.h>

#include <dhcpsrv/lease.h>
#include <dhcpsrv/lease_mgr_factory.h>

#include <asiolink/io_address.h>

#include <cc/data.h>

#include <cerrno>

#include <cstring>

#include <iostream>

#include <cstdlib>

#include <sstream>

#include <string>

#include <map>

#include <vector>

#include <unistd.h>

#include <sys/types.h>

#include <sys/wait.h>

#include <fcntl.h>

#include <cstdio>

#include <cctype>

#include <mutex>

using namespace isc::hooks;

using namespace isc::dhcp;

using namespace isc::asiolink;

extern "C"

{

    int version()

    {

        return KEA_HOOKS_VERSION; // Use the version from the Kea headers we compiled against
    }

    // Declare multi-threading compatibility

    int multi_threading_compatible()

    {

        return 1;
    }

    int load(LibraryHandle &handle)

    {

        std::cout << "DNS Hijack Hook: Loaded successfully" << std::endl;

        return 0;
    }

    int unload()

    {

        std::cout << "DNS Hijack Hook: Unloaded" << std::endl;

        return 0;
    }
    bool is_unregistered_vlan_subnet(uint32_t subnet_id)
    {
        const char *wired_vlan_env = std::getenv("WIRED_VLAN");
        uint32_t wired_vlan = wired_vlan_env && *wired_vlan_env
                                  ? static_cast<uint32_t>(std::atoi(wired_vlan_env))
                                  : 250;

        return subnet_id == wired_vlan;
    }
    ConstHostPtr findRegisteredHost(const std::vector<uint8_t> &hwaddr)
    {
        const char *valid_vlans_env = std::getenv("VALID_VLANS");
        if (!valid_vlans_env || !*valid_vlans_env)
        {
            std::cout << "DNS Hijack Hook: [DEBUG] VALID_VLANS not set or empty" << std::endl;
            return ConstHostPtr();
        }

        std::cout << "DNS Hijack Hook: [DEBUG] findRegisteredHost: searching VALID_VLANS="
                  << valid_vlans_env << std::endl;

        std::istringstream iss(valid_vlans_env);
        std::string token;

        while (std::getline(iss, token, ','))
        {
            // Trim whitespace
            token.erase(0, token.find_first_not_of(" \t"));
            token.erase(token.find_last_not_of(" \t") + 1);

            if (token.empty())
                continue;

            try
            {
                uint32_t subnet_id = static_cast<uint32_t>(std::stoul(token));

                std::cout << "DNS Hijack Hook: [DEBUG] Trying subnet_id=" << subnet_id << " ..." << std::endl;

                ConstHostPtr host = HostMgr::instance().get4Any(
                    subnet_id, Host::IDENT_HWADDR,
                    hwaddr.data(), hwaddr.size());

                if (host)
                {
                    std::cout << "DNS Hijack Hook: [DEBUG] get4Any returned a host for subnet "
                              << subnet_id << std::endl;

                    // Check user_context
                    try
                    {
                        isc::data::ConstElementPtr ctx = host->getContext();

                        if (!ctx)
                        {
                            std::cout << "DNS Hijack Hook: [DEBUG]   -> No user_context" << std::endl;
                            continue;
                        }

                        if (ctx->getType() != isc::data::Element::map)
                        {
                            std::cout << "DNS Hijack Hook: [DEBUG]   -> user_context is not a map" << std::endl;
                            continue;
                        }

                        isc::data::ConstElementPtr registered = ctx->get("registered");

                        if (!registered)
                        {
                            std::cout << "DNS Hijack Hook: [DEBUG]   -> No 'registered' key in user_context" << std::endl;
                            continue;
                        }

                        if (registered->getType() != isc::data::Element::boolean)
                        {
                            std::cout << "DNS Hijack Hook: [DEBUG]   -> 'registered' is not boolean (type="
                                      << registered->getType() << ")" << std::endl;
                            continue;
                        }

                        bool is_registered = registered->boolValue();
                        std::cout << "DNS Hijack Hook: [DEBUG]   -> 'registered' = "
                                  << (is_registered ? "true" : "false") << std::endl;

                        if (is_registered)
                        {
                            std::cout << "DNS Hijack Hook: [DEBUG] Found registered host in subnet "
                                      << subnet_id << std::endl;
                            return host;
                        }
                    }
                    catch (const std::exception &ex)
                    {
                        std::cout << "DNS Hijack Hook: [DEBUG] Exception while checking user_context: "
                                  << ex.what() << std::endl;
                    }
                }
                else
                {
                    std::cout << "DNS Hijack Hook: [DEBUG] No host found in subnet " << subnet_id << std::endl;
                }
            }
            catch (const std::exception &ex)
            {
                std::cout << "DNS Hijack Hook: [DEBUG] Exception parsing token '" << token
                          << "': " << ex.what() << std::endl;
            }
        }

        std::cout << "DNS Hijack Hook: [DEBUG] No registered host found in VALID_VLANS" << std::endl;
        return ConstHostPtr();
    }

    int subnet4_select(CalloutHandle &handle)
    {
        try
        {
            Pkt4Ptr query;
            handle.getArgument("query4", query);

            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);

            if (!query || !subnet)
            {
                return 0;
            }

            if (query->getType() != DHCPDISCOVER)
            {
                return 0;
            }

            if (!is_unregistered_vlan_subnet(subnet->getID()))
            {
                return 0;
            }

            HWAddrPtr hwaddr = query->getHWAddr();
            if (!hwaddr || hwaddr->hwaddr_.empty())
            {
                return 0;
            }

            ConstHostPtr registered_host = findRegisteredHost(hwaddr->hwaddr_);

            if (registered_host)
            {
                std::cout << "DNS Hijack Hook: Registered device "
                          << hwaddr->toText(false)
                          << " sent DHCPDISCOVER on unregistered VLAN subnet "
                          << subnet->getID()
                          << " - dropping until switch port moves to assigned VLAN"
                          << std::endl;

                handle.setStatus(CalloutHandle::NEXT_STEP_DROP);
                return 0;
            }

            return 0;
        }
        catch (const std::exception &ex)
        {
            std::cout << "DNS Hijack Hook ERROR in subnet4_select: "
                      << ex.what() << std::endl;
            return 1;
        }
    }

    // Wrapper around system() that temporarily restores SIGCHLD to SIG_DFL.

    // Kea sets SIGCHLD to SIG_IGN to auto-reap children; this causes system()'s

    // internal waitpid() to fail with ECHILD even when the child ran successfully.

    // Saving and restoring the handler makes the exit status reliable.

    int run_script(const std::string &cmd)

    {

        struct sigaction sa_old, sa_new;

        sa_new.sa_handler = SIG_DFL;

        sigemptyset(&sa_new.sa_mask);

        sa_new.sa_flags = 0;

        sigaction(SIGCHLD, &sa_new, &sa_old);

        int status = system(cmd.c_str());

        sigaction(SIGCHLD, &sa_old, nullptr);

        return status;
    }
    bool is_unregistered_pool_ip(const std::string &ip_address)
    {
        // Helper to convert "a.b.c.d" to uint32_t
        auto ip_to_u32 = [](const std::string &s) -> uint32_t
        {
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
                return 0;
            return (a << 24) | (b << 16) | (c << 8) | d;
        };

        static uint32_t start = 0;
        static uint32_t end = 0;

        // Initialize the range once (lazy)
        if (start == 0)
        {
            const char *wired_vlan_env = std::getenv("WIRED_VLAN");
            int wired_vlan = (wired_vlan_env && *wired_vlan_env) ? std::atoi(wired_vlan_env) : 250;

            const char *net_word = std::getenv("NETWORK_WORD");
            std::string base = (net_word && *net_word) ? net_word : "192.168";

            std::string start_ip = base + "." + std::to_string(wired_vlan) + ".1";
            std::string end_ip = base + "." + std::to_string(wired_vlan) + ".254";

            start = ip_to_u32(start_ip);
            end = ip_to_u32(end_ip);
        }

        uint32_t ip = ip_to_u32(ip_address);
        if (ip == 0)
            return false;

        return (ip >= start && ip <= end);
    }

    // Helper function to call DNS hijacking script

    void manage_dns_hijack(const std::string &action, const std::string &ip_address)

    {

        std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack ENTRY (action="

                  << action << ", ip=" << ip_address << ")" << std::endl;

        std::cout.flush();

        std::stringstream cmd;

        std::cout << "DNS Hijack Hook: [DEBUG] Building command" << std::endl;

        std::cout.flush();

        // Run inline (quick iptables updates) to avoid fork failures

        cmd << "/scripts/dns-hijack.sh " << action << " " << ip_address << " >/dev/null 2>&1";

        std::cout << "DNS Hijack Hook: [DEBUG] Command: " << cmd.str() << std::endl;

        std::cout.flush();

        std::cout << "DNS Hijack Hook: [DEBUG] Calling run_script()" << std::endl;

        std::cout.flush();

        int status = run_script(cmd.str());

        std::cout << "DNS Hijack Hook: [DEBUG] run_script() returned: " << status << std::endl;

        std::cout.flush();

        if (status == -1)

        {

            std::cerr << "DNS Hijack Hook WARNING: Script launch failed errno="

                      << errno << " (" << std::strerror(errno) << ")" << std::endl;

            std::cerr.flush();
        }

        else if (status != 0)

        {

            std::cerr << "DNS Hijack Hook WARNING: Script exit status " << status << std::endl;

            std::cerr.flush();
        }

        std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack EXIT" << std::endl;

        std::cout.flush();
    }

    // Helper function to call DNS hijacking script without an IP argument

    void manage_dns_hijack_pools(const std::string &action)

    {

        std::cout << "DNS Hijack Hook: [DEBUG] manage_dns_hijack_pools ENTRY (action="

                  << action << ")" << std::endl;

        std::cout.flush();

        std::stringstream cmd;

        cmd << "/scripts/dns-hijack.sh " << action << " >/dev/null 2>&1";

        std::cout << "DNS Hijack Hook: [DEBUG] Pools Command: " << cmd.str() << std::endl;

        std::cout.flush();

        int status = run_script(cmd.str());

        if (status == -1)

        {

            std::cerr << "DNS Hijack Hook WARNING: Pools script launch failed errno="

                      << errno << " (" << std::strerror(errno) << ")" << std::endl;

            std::cerr.flush();
        }

        else if (status != 0)

        {

            std::cerr << "DNS Hijack Hook WARNING: Pools script exit status " << status << std::endl;

            std::cerr.flush();
        }
    }
    // Helper: extract "blocked-ip" from reservation user-context if present
    // Helper: extract "blocked-ip" from reservation user-context if present
    std::string get_blocked_ip_from_reservation(const ConstHostPtr &host)
    {
        if (!host)
        {
            return "";
        }

        std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation ENTRY" << std::endl;

        try
        {
            isc::data::ConstElementPtr ctx = host->getContext();
            if (!ctx)
            {
                std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - No user_context present" << std::endl;
                return "";
            }

            if (ctx->getType() != isc::data::Element::map)
            {
                std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - user_context is not a map" << std::endl;
                return "";
            }

            isc::data::ConstElementPtr blocked_ip_elem = ctx->get("blocked-ip");

            if (!blocked_ip_elem)
            {
                std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - No 'blocked-ip' key found" << std::endl;
                return "";
            }

            if (blocked_ip_elem->getType() != isc::data::Element::string)
            {
                std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - 'blocked-ip' exists but is not a string "
                          << "(type=" << blocked_ip_elem->getType() << ")" << std::endl;
                return "";
            }

            std::string blocked_ip = blocked_ip_elem->stringValue();
            std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - Found blocked-ip=\""
                      << blocked_ip << "\"" << std::endl;

            return blocked_ip;
        }
        catch (const std::exception &ex)
        {
            std::cout << "DNS Hijack Hook: [DEBUG] get_blocked_ip_from_reservation - Exception: "
                      << ex.what() << std::endl;
            return "";
        }
    }

    bool is_blocked_pool_ip(const std::string &ip_address)

    {

        // Convert a dotted-quad string to a uint32_t for range comparisons.

        auto ip_to_u32 = [](const std::string &s) -> uint32_t

        {
            unsigned a = 0, b = 0, c = 0, d = 0;

            if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)

                return 0;

            return (a << 24) | (b << 16) | (c << 8) | d;
        };

        // Cache blocked pool ranges on first call by reading the Kea config via Python.

        static std::mutex s_mutex;

        static bool s_loaded = false;

        static std::vector<std::pair<uint32_t, uint32_t>> s_ranges;

        {

            std::lock_guard<std::mutex> lk(s_mutex);

            if (!s_loaded)

            {

                s_loaded = true;

                const char *cfg = std::getenv("KEA_CONFIG_PATH");

                if (!cfg || !*cfg)

                    cfg = "/kea/config/dhcp4.json";

                std::string cmd =

                    "python3 -c \""

                    "import json\n"

                    "with open('" +

                    std::string(cfg) + "') as f:\n"

                                       "    data=json.load(f)\n"

                                       "for s in data.get('Dhcp4',{}).get('subnet4',[]):\n"

                                       "    for p in s.get('pools',[]):\n"

                                       "        if 'BLOCKED' in (p.get('client-classes') or []):\n"

                                       "            r=p['pool'].replace(' ','')\n"

                                       "            print(r)\n"

                                       "\" 2>/dev/null";

                FILE *pipe = popen(cmd.c_str(), "r");

                if (pipe)

                {

                    char line[256];

                    while (fgets(line, sizeof(line), pipe))

                    {

                        std::string range(line);

                        while (!range.empty() &&

                               (range.back() == '\n' || range.back() == '\r' || range.back() == ' '))

                            range.pop_back();

                        auto dash = range.find('-');

                        if (dash == std::string::npos)

                            continue;

                        uint32_t start = ip_to_u32(range.substr(0, dash));

                        uint32_t end = ip_to_u32(range.substr(dash + 1));

                        if (start && end && start <= end)

                            s_ranges.push_back({start, end});
                    }

                    pclose(pipe);

                    std::cout << "DNS Hijack Hook: loaded " << s_ranges.size()

                              << " blocked-pool range(s) from " << cfg << std::endl;
                }

                else

                {

                    std::cerr << "DNS Hijack Hook: WARNING is_blocked_pool_ip: "

                                 "failed to load ranges from Kea config"

                              << std::endl;
                }
            }
        }

        uint32_t ip = ip_to_u32(ip_address);

        if (ip == 0)

            return false;

        for (const auto &r : s_ranges)

        {

            if (ip >= r.first && ip <= r.second)

                return true;
        }

        return false;
    }

    // Helper: parse SWITCH_HOSTS (space-separated) env var.

    std::vector<std::string> get_switch_hosts()

    {

        const char *env = std::getenv("SWITCH_HOSTS");

        std::vector<std::string> hosts;

        if (!env || !*env)

            return hosts;

        std::istringstream iss(env);

        std::string h;

        while (iss >> h)

        {

            if (!h.empty())

                hosts.push_back(h);
        }

        return hosts;
    }

    // Helper: query isp_routers + vlan_mappings to find which HP5130 switch hosts

    // the ISP router for the given device VLAN.  That switch is the internet choke

    // point: blocking there prevents internet access regardless of which physical

    // switch the device is currently connected to.

    // vlan_id is an integer from the lease (no SQL injection risk).

    std::string get_isp_router_switch_for_vlan(uint32_t vlan_id)

    {

        if (vlan_id == 0)

            return "";

        const char *db_host = std::getenv("DB_HOST");

        const char *db_port = std::getenv("DB_PORT");

        const char *db_name = std::getenv("DB_NAME");

        const char *db_user = std::getenv("DB_USER");

        const char *db_pass = std::getenv("DB_PASSWORD");

        if (!db_host || !db_name || !db_user || !db_pass)

            return "";

        setenv("PGPASSWORD", db_pass, 1);

        std::stringstream cmd;

        cmd << "psql -h " << db_host

            << " -p " << (db_port ? db_port : "5432")

            << " -U " << db_user

            << " -d " << db_name

            << " -t -A -q"

            << " -c \"SELECT ir.switch_host FROM isp_routers ir"

            << " JOIN vlan_mappings vm ON vm.isp_router_id = ir.id"

            << " WHERE vm.vlan_id = " << vlan_id

            << " AND ir.switch_host IS NOT NULL LIMIT 1\""

            << " 2>/dev/null";

        FILE *pipe = popen(cmd.str().c_str(), "r");

        if (!pipe)

            return "";

        char buf[64] = {};

        bool got = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);

        pclose(pipe);

        if (!got)

            return "";

        std::string result(buf);

        while (!result.empty() &&

               (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))

        {

            result.pop_back();
        }

        return result;
    }

    // Helper function to call HP5130 ACL script on the appropriate switch(es).

    // For "block": targets only the ISP router's switch for the VLAN (the internet

    //              choke point). Falls back to all switches if not configured.

    // For "unblock": targets all switches to remove any stale deny rules.

    void manage_acl(const std::string &action, const std::string &ip_address,

                    uint32_t vlan_id = 0)

    {

        std::cout << "DNS Hijack Hook: [DEBUG] manage_acl ENTRY (action="

                  << action << ", ip=" << ip_address

                  << ", vlan=" << vlan_id << ")" << std::endl;

        std::cout.flush();

        std::vector<std::string> all_hosts = get_switch_hosts();

        if (all_hosts.empty())

        {

            std::cerr << "DNS Hijack Hook WARNING: no SWITCH_HOSTS configured"

                      << std::endl;

            std::cerr.flush();

            return;
        }

        std::vector<std::string> targets;

        if (action == "block")

        {

            // Target only the ISP router's switch for this VLAN.

            std::string isp_sw = get_isp_router_switch_for_vlan(vlan_id);

            if (!isp_sw.empty())

            {

                // Validate against the configured hosts list.

                for (const auto &h : all_hosts)

                {

                    if (h == isp_sw)

                    {

                        targets.push_back(h);

                        break;
                    }
                }
            }

            if (targets.empty())

            {

                std::cout << "DNS Hijack Hook: ACL block for " << ip_address

                          << " vlan=" << vlan_id

                          << " — ISP router switch not found, targeting all switches"

                          << std::endl;

                targets = all_hosts;
            }

            else

            {

                std::cout << "DNS Hijack Hook: ACL block for " << ip_address

                          << " targeting ISP router switch " << targets[0]

                          << " (vlan=" << vlan_id << ")" << std::endl;
            }
        }

        else

        {

            // Unblock: hit all switches to remove any stale deny rules.

            targets = all_hosts;
        }

        for (const auto &target : targets)

        {

            std::stringstream cmd;

            cmd << "SWITCH_HOSTS='" << target << "' /scripts/hp5130-acl.sh "

                << action << " " << ip_address << " >/dev/null 2>&1 &";

            std::cout << "DNS Hijack Hook: [DEBUG] ACL Command: " << cmd.str() << std::endl;

            std::cout.flush();

            int status = run_script(cmd.str());

            std::cout << "DNS Hijack Hook: [DEBUG] ACL run_script() returned: " << status << std::endl;

            std::cout.flush();

            if (status == -1)

            {

                std::cerr << "DNS Hijack Hook WARNING: ACL script launch failed for "

                          << target << " errno=" << errno

                          << " (" << std::strerror(errno) << ")" << std::endl;

                std::cerr.flush();
            }
        }
    }

    // Helper function to track unregistered leases in DB

    void manage_unregistered_lease(const std::string &action,

                                   const std::string &mac_address,

                                   const std::string &ip_address,

                                   int lease_seconds)

    {

        std::stringstream cmd;

        if (action == "cleanup")

        {

            cmd << "/scripts/unregistered-lease.sh cleanup >/dev/null 2>&1";
        }

        else if (action == "upsert")

        {

            cmd << "/scripts/unregistered-lease.sh upsert " << mac_address

                << " " << ip_address << " " << lease_seconds << " >/dev/null 2>&1";
        }

        else if (action == "remove" || action == "expire")

        {

            cmd << "/scripts/unregistered-lease.sh remove " << mac_address

                << " " << ip_address << " >/dev/null 2>&1";
        }

        else

        {

            return;
        }

        int status = run_script(cmd.str());

        if (status == -1)

        {

            std::cerr << "DNS Hijack Hook WARNING: unregistered-lease script launch failed errno="

                      << errno << " (" << std::strerror(errno) << ")" << std::endl;

            std::cerr.flush();
        }

        else if (status != 0)

        {

            std::cerr << "DNS Hijack Hook WARNING: unregistered-lease script exit status "

                      << status << std::endl;

            std::cerr.flush();
        }
    }

    // Helper: query central for an unknown MAC via central_import.py.

    // Returns one of: "registered", "blocked", "not_found", "disabled", "error".

    // The call is synchronous but central_import.py uses a 3-second HTTP timeout,

    // so the total wall time is bounded.  We validate the MAC before exec to

    // prevent shell injection.

    std::string query_central_for_mac(const std::string &mac_colon,
                                      uint32_t subnet_id = 0)
    {
        std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac ENTRY - "
                  << "mac=" << mac_colon << " subnet_id=" << subnet_id << std::endl;

        // Only allow hex digits and colons (aa:bb:cc:dd:ee:ff)
        if (mac_colon.size() > 17)
        {
            std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                      << "MAC too long (" << mac_colon.size() << " chars) → error" << std::endl;
            return "error";
        }

        for (unsigned char c : mac_colon)
        {
            if (!isxdigit(c) && c != ':')
            {
                std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                          << "Invalid character in MAC: '" << c << "' → error" << std::endl;
                return "error";
            }
        }

        // Build command
        std::string cmd = "python3 /scripts/central_import.py '" + mac_colon + "' " + std::to_string(subnet_id) + " 2>/dev/null";

        std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                  << "Executing: " << cmd << std::endl;

        FILE *pipe = popen(cmd.c_str(), "r");
        if (!pipe)
        {
            std::cerr << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                      << "popen failed for command: " << cmd << std::endl;
            return "error";
        }

        char buf[32] = {};
        bool got = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);
        int exit_status = pclose(pipe);

        if (!got)
        {
            std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                      << "No output from central_import.py (exit_status=" << exit_status << ") → error" << std::endl;
            return "error";
        }

        std::string result(buf);

        // Strip trailing whitespace / newline
        while (!result.empty() &&
               (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))
        {
            result.pop_back();
        }

        std::cout << "DNS Hijack Hook: [DEBUG] query_central_for_mac - "
                  << "Raw output: \"" << buf << "\" → Cleaned result: \"" << result << "\""
                  << " (pclose exit=" << exit_status << ")" << std::endl;

        return result;
    }

    bool is_blocked_host(const ConstHostPtr &host)
    {
        if (!host)
        {
            return false;
        }

        // Prefer client-classes if present

        try
        {

            const ClientClasses &classes4 = host->getClientClasses4();
            if (classes4.contains("BLOCKED"))
            {
                return true;
            }
        }

        catch (...)
        {
            // Ignore and fall back to user-context
        }

        try
        {

            isc::data::ConstElementPtr ctx = host->getContext();

            if (!ctx || (ctx->getType() != isc::data::Element::map))
            {
                return false;
            }

            isc::data::ConstElementPtr blocked = ctx->get("blocked");

            if (!blocked)
            {
                return false;
            }

            if (blocked->getType() == isc::data::Element::boolean)
            {
                return blocked->boolValue();
            }
        }

        catch (...)

        {

            return false;
        }

        return false;
    }

    // Helper: fire-and-forget switch port lookup.

    // Uses a double-fork so Kea never needs to waitpid() for the grandchild,

    // and SIGCHLD is never touched - avoiding interference with system() calls

    // elsewhere in the hook.

    // Gated by SWITCH_PORT_LOOKUP_ENABLED=1 env var (default off).

    // Helper: fire-and-forget switch port lookup.
    // Uses a double-fork so Kea never needs to waitpid() for the grandchild,
    // and SIGCHLD is never touched - avoiding interference with system() calls
    // elsewhere in the hook.
    // Gated by SWITCH_PORT_LOOKUP_ENABLED=1 env var (default off).
    void spawn_port_lookup(const std::string &mac_colon)
    {
        const char *enabled = std::getenv("SWITCH_PORT_LOOKUP_ENABLED");

        // Log decision clearly
        if (!enabled || std::string(enabled) != "1")
        {
            std::cout << "DNS Hijack Hook: [DEBUG] spawn_port_lookup - "
                      << "SWITCH_PORT_LOOKUP_ENABLED is not set to '1' (value="
                      << (enabled ? enabled : "null") << ") → skipping" << std::endl;
            return;
        }

        std::cout << "DNS Hijack Hook: [DEBUG] spawn_port_lookup ENTRY - "
                  << "MAC=" << mac_colon << std::endl;

        // Double-fork: first child exits immediately so Kea can waitpid() it
        // right away with no delay; grandchild runs the script detached.
        pid_t pid = fork();
        if (pid < 0)
        {
            std::cerr << "DNS Hijack Hook: [ERROR] spawn_port_lookup - "
                      << "fork() failed: " << std::strerror(errno) << std::endl;
            return;
        }

        if (pid == 0)
        {
            // --- First child ---
            pid_t pid2 = fork();
            if (pid2 != 0)
            {
                // First child exits immediately (success or failure)
                _exit(0);
            }

            // --- Grandchild: detach and exec the script ---
            setsid();

            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0)
            {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO)
                    close(devnull);
            }

            // Close any other inherited fds
            for (int fd = 3; fd < 256; fd++)
                close(fd);

            static char mac_arg[64];
            std::strncpy(mac_arg, mac_colon.c_str(), sizeof(mac_arg) - 1);
            mac_arg[sizeof(mac_arg) - 1] = '\0';

            char *const args[] = {
                const_cast<char *>("/scripts/hp5130-port-lookup.sh"),
                mac_arg,
                nullptr};

            execv("/scripts/hp5130-port-lookup.sh", args);

            // If execv fails
            std::cerr << "DNS Hijack Hook: [ERROR] spawn_port_lookup - "
                      << "execv failed for hp5130-port-lookup.sh (errno=" << errno << ")" << std::endl;
            _exit(127);
        }

        // --- Parent process ---
        // Reap the first child immediately (it exits right away)
        int status;
        waitpid(pid, &status, 0);

        std::cout << "DNS Hijack Hook: [DEBUG] spawn_port_lookup - "
                  << "Port lookup spawned successfully for MAC=" << mac_colon << std::endl;
    }

    // Helper: fire-and-forget lease event notification for Table 6 + Table 7 writes.

    // Calls /scripts/kea-lease-event.sh asynchronously via double-fork so Kea

    // never blocks waiting for the DB write to complete.

    void manage_lease_event(const std::string &action,

                            const std::string &mac_colon,

                            const std::string &ip_address,

                            uint32_t vlan_id,

                            int lease_seconds,

                            bool from_blocked_pool,

                            bool dns_hijacked)

    {

        static const char *script = "/scripts/kea-lease-event.sh";

        std::string vlan_str = std::to_string(vlan_id);

        std::string secs_str = std::to_string(lease_seconds);

        std::string pool_str = from_blocked_pool ? "true" : "false";

        std::string hijack_str = dns_hijacked ? "true" : "false";

        pid_t pid = fork();

        if (pid < 0)

        {

            std::cerr << "DNS Hijack Hook: manage_lease_event fork failed: "

                      << std::strerror(errno) << std::endl;

            return;
        }

        if (pid == 0)

        {

            // First child: fork again then exit immediately so Kea reaps it instantly.

            pid_t pid2 = fork();

            if (pid2 != 0)

                _exit(0);

            // Grandchild: detach from Kea and exec the script.

            setsid();

            int devnull = open("/dev/null", O_RDWR);

            if (devnull >= 0)

            {

                dup2(devnull, STDIN_FILENO);

                dup2(devnull, STDOUT_FILENO);

                dup2(devnull, STDERR_FILENO);

                if (devnull > STDERR_FILENO)

                    close(devnull);
            }

            for (int fd = 3; fd < 256; fd++)

                close(fd);

            // Local arrays for execv args (stack-allocated in grandchild).

            char a_action[16], a_mac[32], a_ip[20], a_vlan[12],

                a_secs[12], a_pool[8], a_hijack[8];

            std::strncpy(a_action, action.c_str(), sizeof(a_action) - 1);

            std::strncpy(a_mac, mac_colon.c_str(), sizeof(a_mac) - 1);

            std::strncpy(a_ip, ip_address.c_str(), sizeof(a_ip) - 1);

            std::strncpy(a_vlan, vlan_str.c_str(), sizeof(a_vlan) - 1);

            std::strncpy(a_secs, secs_str.c_str(), sizeof(a_secs) - 1);

            std::strncpy(a_pool, pool_str.c_str(), sizeof(a_pool) - 1);

            std::strncpy(a_hijack, hijack_str.c_str(), sizeof(a_hijack) - 1);

            a_action[sizeof(a_action) - 1] = a_mac[sizeof(a_mac) - 1] = a_ip[sizeof(a_ip) - 1] = '\0';

            a_vlan[sizeof(a_vlan) - 1] = a_secs[sizeof(a_secs) - 1] = '\0';

            a_pool[sizeof(a_pool) - 1] = a_hijack[sizeof(a_hijack) - 1] = '\0';

            char *const args[] = {

                const_cast<char *>(script),

                a_action, a_mac, a_ip, a_vlan, a_secs, a_pool, a_hijack,

                nullptr};

            execv(script, args);

            _exit(127);
        }

        // Reap first child immediately (it exits right away).

        int wstatus;

        waitpid(pid, &wstatus, 0);
    }

    // Helper: safely read a bool from the callout context without throwing.
    bool get_bool_context(CalloutHandle &handle, const std::string &name)
    {
        bool value = false;
        try
        {
            handle.getContext(name, value);
        }
        catch (...)
        {
            value = false;
        }
        return value;
    }

    // Helper: apply DNS hijack / ACL actions for pool-mismatch policy scenarios.
    // admin_blocked=true  → device is BLOCKED, restrict its current (wrong-pool) IP.
    // admin_blocked=false → device was just unblocked, release its stale blocked-pool IP.
    void apply_policy_actions(const Lease4Ptr &lease, bool admin_blocked)
    {
        if (!lease || !lease->hwaddr_)
        {
            return;
        }

        const std::string ip_address = lease->addr_.toText();
        const std::string mac_address = lease->hwaddr_->toText(false);

        if (admin_blocked)
        {
            manage_dns_hijack_pools("hijack-blocked-pools");
            manage_dns_hijack("hijack", ip_address);
            manage_acl("block", ip_address, lease->subnet_id_);
            manage_lease_event("expire", mac_address, ip_address,
                               lease->subnet_id_, 0, false, true);
        }
        else
        {
            manage_dns_hijack("unhijack", ip_address);
            manage_acl("unblock", ip_address, lease->subnet_id_);
            manage_lease_event("expire", mac_address, ip_address,
                               lease->subnet_id_, 0, true, false);
        }
    }

    // Synchronously query the portal DB to check whether a registered device's

    // assigned_vlan matches the VLAN subnet being allocated.

    // Returns true if there is a mismatch (device is on the wrong network segment

    // and should have DNS hijack applied despite having a registered reservation).

    // Only called for non-blocked registered devices; uses popen(psql).

    // Latency: ~10-50 ms on a local PostgreSQL instance.

    bool is_assigned_vlan_mismatch(const std::string &mac_colon, uint32_t lease_vlan_id)

    {

        // Input validation: MAC must contain only hex digits and colons.

        if (mac_colon.size() > 17)

            return false;

        for (char c : mac_colon)

        {

            if (!isxdigit(static_cast<unsigned char>(c)) && c != ':')

                return false;
        }

        const char *db_host = std::getenv("DB_HOST");

        const char *db_port = std::getenv("DB_PORT");

        const char *db_name = std::getenv("DB_NAME");

        const char *db_user = std::getenv("DB_USER");

        const char *db_pass = std::getenv("DB_PASSWORD");

        if (!db_host || !db_name || !db_user || !db_pass)

            return false;

        // Expose DB_PASSWORD as PGPASSWORD so psql authenticates without .pgpass.

        setenv("PGPASSWORD", db_pass, 1);

        std::stringstream cmd;

        cmd << "psql -h " << db_host

            << " -p " << (db_port ? db_port : "5432")

            << " -U " << db_user

            << " -d " << db_name

            << " -t -A -q"

            << " -c \"SELECT assigned_vlan FROM devices"

            << " WHERE mac_address='" << mac_colon << "'"

            << " AND assigned_vlan IS NOT NULL LIMIT 1\""

            << " 2>/dev/null";

        FILE *pipe = popen(cmd.str().c_str(), "r");

        if (!pipe)

            return false;

        char buf[32] = {};

        bool got_data = (fgets(buf, sizeof(buf) - 1, pipe) != nullptr);

        pclose(pipe);

        if (!got_data)

            return false;

        // Trim trailing whitespace / newline.

        std::string result(buf);

        while (!result.empty() &&

               (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))

        {

            result.pop_back();
        }

        if (result.empty())

            return false; // No assigned_vlan set — no mismatch.

        try

        {

            int assigned = std::stoi(result);

            if (assigned <= 0)

                return false;

            bool mismatch = (static_cast<uint32_t>(assigned) != lease_vlan_id);

            if (mismatch)

            {

                std::cout << "DNS Hijack Hook: VLAN mismatch for " << mac_colon

                          << " (assigned=" << assigned

                          << " lease_vlan=" << lease_vlan_id << ")" << std::endl;
            }

            return mismatch;
        }

        catch (...)

        {

            return false;
        }
    }

    int lease4_select(CalloutHandle &handle)

    {
        try
        {
            bool fake_allocation = true;
            handle.getArgument("fake_allocation", fake_allocation);
            const bool force_nak =
                get_bool_context(handle, "policy_force_nak");

            if (!fake_allocation && force_nak)
            {
                // Policy vars were set by pkt4_receive (pool-state mismatch on the
                // incoming DHCPREQUEST).  Kea's class-based pool selection has already
                // corrected the allocation, so the proposed lease IP is already in the
                // right pool — calling apply_policy_actions here would wrongly apply
                // DNS/ACL side-effects to an IP that will never be committed.
                // Just skip the lease write; pkt4_send will send the DHCPNAK.
                handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
                return 0;
            }

            // During DHCPDISCOVER, fake_allocation=true: Kea is selecting a candidate
            // IP to offer but the client has not committed to it yet.  Skip DNS hijack
            // and ACL changes — apply them only on the real allocation (DHCPREQUEST,
            // fake_allocation=false) so we never leave stale rules for IPs that were
            // offered but never actually leased.
            if (fake_allocation)
            {
                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
                return 0;
            }

            // Get the lease that was selected
            Lease4Ptr lease;
            handle.getArgument("lease4", lease);
            // Get the query packet
            Pkt4Ptr query4;
            handle.getArgument("query4", query4);
            if (!lease || !query4)
            {
                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
                return 0;
            }

            // Get hardware address

            HWAddrPtr hwaddr = query4->getHWAddr();

            if (!hwaddr)
            {
                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
                return 0;
            }

            // Get the allocated IP address

            std::string ip_address = lease->addr_.toText();

            std::string mac_address = hwaddr->toText(); // "hwtype=1 aa:bb:cc:dd:ee:ff"

            std::string mac_clean = hwaddr->toText(false); // "aa:bb:cc:dd:ee:ff" (for DB queries)

            int lease_seconds = static_cast<int>(lease->valid_lft_);

            bool ip_is_blocked_pool = is_blocked_pool_ip(ip_address);

            std::cout << "DNS Hijack Hook: Lease allocated - MAC: " << mac_address

                      << " IP: " << ip_address << std::endl;

            // Cleanup expired unregistered leases on every allocation

            manage_unregistered_lease("cleanup", "", "", 0);

            // Check if device has a reservation (is registered)

            ConstHostPtr host;

            // Check subnet-specific reservations FIRST (they override global in Kea's
            // own precedence), then fall back to global.  This mirrors Kea's allocation
            // engine so the hook and Kea agree on which reservation governs the device.

            {
                ConstSubnet4Ptr subnet;
                handle.getArgument("subnet4", subnet);
                if (subnet)
                {
                    uint32_t subnet_id = subnet->getID();
                    host = HostMgr::instance().get4Any(subnet->getID(), Host::IDENT_HWADDR,

                                                       &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
                    std::cout << "DNS Hijack Hook: [DEBUG] lease4_select: Subnet-specific lookup (subnet_id="
                              << subnet_id << ") → " << (host ? "FOUND" : "NOT FOUND") << std::endl;
                }
            }

            // Fall back to global reservation only if no subnet-specific found.

            if (!host)
            {
                host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,

                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());
                std::cout << "DNS Hijack Hook: [DEBUG] lease4_select: Global lookup → "
                          << (host ? "FOUND" : "NOT FOUND") << std::endl;
            }

            if (!host)
            {
                std::vector<uint8_t> mac_vec = hwaddr->hwaddr_;
                std::cout << "DNS Hijack Hook: [DEBUG] lease4_select: Searching VALID_VLANS for registered host..." << std::endl;
                host = findRegisteredHost(mac_vec);
            }

            bool do_hijack = false; // track for lease event
            if (host)
            {
                bool blocked = is_blocked_host(host);
                std::string blocked_ip = get_blocked_ip_from_reservation(host);
                isc::data::ConstElementPtr ctx = host->getContext();

                if (ctx)
                {
                    std::cout << "DNS Hijack Hook: [DEBUG] user-context=" << ctx->str() << std::endl;
                }

                try
                {
                    const ClientClasses &classes4 = host->getClientClasses4();
                    std::cout << "DNS Hijack Hook: [DEBUG] client-classes=" << classes4.toText() << std::endl;
                }

                catch (...)
                {
                    std::cout << "DNS Hijack Hook: [DEBUG] client-classes unavailable" << std::endl;
                }

                if (blocked)
                {
                    std::cout << "DNS Hijack Hook: Device " << mac_address
                              << " is BLOCKED - enabling DNS hijack" << std::endl;
                    if (ip_is_blocked_pool)

                    {

                        std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;

                        manage_dns_hijack_pools("hijack-blocked-pools");
                    }

                    else

                    {

                        // Unusual: Kea should have put a BLOCKED device in the blocked pool.

                        std::cerr << "DNS Hijack Hook WARNING: blocked device " << mac_clean

                                  << " received non-blocked-pool IP " << ip_address

                                  << " (subnet_id=" << lease->subnet_id_ << ")" << std::endl;
                    }

                    manage_dns_hijack("hijack", ip_address);

                    do_hijack = true;
                }

                else

                {

                    // Registered (non-blocked) device.

                    // Check assigned_vlan: if the device is on the wrong network segment,

                    // restrict access even though it has a valid registration.

                    if (is_assigned_vlan_mismatch(mac_clean, lease->subnet_id_))

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_clean

                                  << " registered but on wrong VLAN (subnet "

                                  << lease->subnet_id_ << ") - restricting access" << std::endl;

                        manage_dns_hijack("hijack", ip_address);

                        manage_acl("block", ip_address, lease->subnet_id_);

                        do_hijack = true;
                    }

                    else

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_address

                                  << " is REGISTERED - removing DNS hijack" << std::endl;

                        manage_dns_hijack("unhijack", ip_address);

                        manage_acl("unblock", ip_address, lease->subnet_id_);

                        do_hijack = false;
                    }
                }

                manage_unregistered_lease("remove", mac_clean, ip_address, 0);

                if (!blocked_ip.empty() && blocked_ip != ip_address)

                {

                    std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "

                              << blocked_ip << std::endl;

                    manage_acl("unblock", blocked_ip, lease->subnet_id_);

                    std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "

                              << blocked_ip << std::endl;

                    manage_dns_hijack("unhijack", blocked_ip);
                }
            }

            else

            {

                // No local reservation — query central before treating as unregistered.

                std::string central_status = query_central_for_mac(mac_clean, lease->subnet_id_);

                std::cout << "DNS Hijack Hook: Device " << mac_clean

                          << " not in local DB - central query returned: "

                          << central_status << std::endl;

                std::cout.flush();

                if (central_status == "registered")

                {

                    // Device was imported from central with REGISTERED class reservation.

                    // There is no separate registered-only pool, so the device will get

                    // the same IP on re-DISCOVER — drop-and-rediscover is pointless and

                    // races with the portal.  Grant access immediately, exactly as we

                    // do for a device that already has a local REGISTERED reservation.

                    manage_unregistered_lease("remove", mac_clean, ip_address, 0);

                    if (is_assigned_vlan_mismatch(mac_clean, lease->subnet_id_))

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_clean

                                  << " imported from central (registered) but on wrong VLAN (subnet "

                                  << lease->subnet_id_ << ") - restricting access" << std::endl;

                        std::cout.flush();

                        manage_dns_hijack("hijack", ip_address);

                        manage_acl("block", ip_address, lease->subnet_id_);

                        do_hijack = true;
                    }

                    else

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_clean

                                  << " imported from central (registered) - granting immediate access"

                                  << std::endl;

                        std::cout.flush();

                        manage_dns_hijack("unhijack", ip_address);

                        manage_acl("unblock", ip_address, lease->subnet_id_);

                        do_hijack = false;
                    }
                }

                else if (central_status == "blocked")

                {

                    // Device imported from central with BLOCKED class reservation.

                    // Force a NAK so the client re-DISCOVERs and Kea uses the newly-

                    // created BLOCKED host reservation to assign a blocked-pool IP.

                    // NEXT_STEP_DROP does not reliably prevent DHCP4_LEASE_ALLOC/DHCPACK

                    // in Kea 3.0, so we explicitly delete the stale regular-pool lease

                    // and set policy_force_nak so pkt4_send converts DHCPACK → DHCPNAK.

                    std::cout << "DNS Hijack Hook: Device " << mac_clean

                              << " imported from central (blocked) - forcing NAK for re-DISCOVER"

                              << std::endl;

                    std::cout.flush();

                    manage_unregistered_lease("remove", mac_clean, ip_address, 0);

                    // Delete the stale regular-pool lease so the next DISCOVER starts fresh.

                    LeaseMgrFactory::instance().deleteLease(lease);

                    // Tell pkt4_send to convert the outgoing DHCPACK to DHCPNAK.

                    handle.setContext("policy_force_nak", true);

                    handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);

                    return 0;
                }

                else

                {

                    // not_found / disabled / error → fail-open: treat as unregistered

                    std::cout << "DNS Hijack Hook: Device " << mac_address

                              << " is UNREGISTERED - enabling DNS hijack" << std::endl;

                    std::cout.flush();

                    manage_dns_hijack("hijack", ip_address);

                    // Blocked-pool IPs are already covered by blanket ACL range rules;

                    // a redundant per-IP rule would survive lease expiry and litter the ACL.

                    if (!ip_is_blocked_pool)

                    {

                        manage_acl("block", ip_address, lease->subnet_id_);
                    }

                    manage_unregistered_lease("upsert", mac_clean, ip_address, lease_seconds);

                    do_hijack = true;
                }
            }

            // Table 6 + Table 7: record this new lease in the portal DB (async).

            manage_lease_event("new_lease", mac_clean, ip_address,

                               lease->subnet_id_, lease_seconds,

                               ip_is_blocked_pool, do_hijack);

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            return 0;
        }

        catch (const std::exception &ex)

        {

            std::cout << "DNS Hijack Hook ERROR: " << ex.what() << std::endl;

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            return 1;
        }
    }

    // Called when a lease is being renewed (RENEW/REBIND/INIT-REBOOT)

    int lease4_renew(CalloutHandle &handle)

    {

        std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew ENTRY" << std::endl;

        std::cout.flush();

        try
        {

            Lease4Ptr lease;
            handle.getArgument("lease4", lease);

            if (!lease)
            {

                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

                return 0;
            }

            // Get hardware address from lease

            HWAddrPtr hwaddr = lease->hwaddr_;

            if (!hwaddr)
            {
                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
                return 0;
            }

            std::string ip_address = lease->addr_.toText();
            std::string mac_address = hwaddr->toText(false); // clean colon format

            int lease_seconds = static_cast<int>(lease->valid_lft_);
            bool ip_is_blocked_pool = is_blocked_pool_ip(ip_address);

            std::cout << "DNS Hijack Hook: Lease renewal - MAC: " << mac_address

                      << " IP: " << ip_address << std::endl;

            std::cout.flush();

            // Cleanup expired unregistered leases on every renewal

            manage_unregistered_lease("cleanup", "", "", 0);

            // Check if device has a reservation (registered or blocked)

            // ==================== RESERVATION LOOKUP WITH DEBUG ====================
            ConstHostPtr host;
            ConstSubnet4Ptr subnet;
            handle.getArgument("subnet4", subnet);

            std::string mac_clean = hwaddr->toText(false); // aa:bb:cc:dd:ee:ff

            std::cout << "DNS Hijack Hook: [DEBUG] Reservation lookup - "
                      << "MAC=" << mac_clean
                      << " current_lease_subnet_id=" << (subnet ? std::to_string(subnet->getID()) : "NULL")
                      << std::endl;

            // Try subnet-specific reservation first
            if (subnet)
            {
                uint32_t subnet_id = subnet->getID();
                host = HostMgr::instance().get4Any(subnet_id, Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());

                std::cout << "DNS Hijack Hook: [DEBUG] Subnet-specific lookup (subnet_id="
                          << subnet_id << ") → " << (host ? "FOUND" : "NOT FOUND") << std::endl;
            }

            // Fall back to global reservation
            if (!host)
            {
                host = HostMgr::instance().get4Any(SUBNET_ID_GLOBAL, Host::IDENT_HWADDR,
                                                   &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());

                std::cout << "DNS Hijack Hook: [DEBUG] Global lookup → "
                          << (host ? "FOUND" : "NOT FOUND") << std::endl;
            }
            if (!host)
            {
                std::vector<uint8_t> mac_vec = hwaddr->hwaddr_;
                std::cout << "DNS Hijack Hook: [DEBUG] Searching VALID_VLANS for registered host..." << std::endl;
                host = findRegisteredHost(mac_vec);
            }

            std::cout << "DNS Hijack Hook: [DEBUG] Final reservation result: host="
                      << (host ? "FOUND" : "NULL") << std::endl;
            // =====================================================================

            std::cout.flush();

            bool do_hijack = false;

            if (host)

            {

                bool blocked = is_blocked_host(host);

                std::string blocked_ip = get_blocked_ip_from_reservation(host);

                isc::data::ConstElementPtr ctx = host->getContext();

                if (ctx)

                {

                    std::cout << "DNS Hijack Hook: [DEBUG] user-context=" << ctx->str() << std::endl;

                    std::cout.flush();
                }

                try

                {

                    const ClientClasses &classes4 = host->getClientClasses4();

                    std::cout << "DNS Hijack Hook: [DEBUG] client-classes=" << classes4.toText() << std::endl;

                    std::cout.flush();
                }

                catch (...)

                {

                    std::cout << "DNS Hijack Hook: [DEBUG] client-classes unavailable" << std::endl;

                    std::cout.flush();
                }

                // ── Pool mismatch detection: force DHCP NAK so the client re-discovers ──

                //

                // Case 1: Device is BLOCKED (BLOCKED Kea class) but is renewing a

                // non-blocked-pool IP — it was blocked after the lease was issued.

                // NAK the renewal so the client re-DHCPs and gets a blocked-pool IP.

                if (blocked && !ip_is_blocked_pool)

                {

                    std::cout << "DNS Hijack Hook: Pool mismatch - BLOCKED device "

                              << mac_address << " renewing non-blocked IP "

                              << ip_address << " - sending NAK" << std::endl;

                    std::cout.flush();

                    // Ensure blocked-pool DNS hijack ranges are active.
                    // Do NOT add per-IP hijack/ACL-block rules for ip_address here:
                    // we are about to delete this lease and free the IP back to the
                    // regular pool.  Stale per-IP rules would incorrectly block the
                    // next registered device that receives this IP.  The correct
                    // per-IP rules for the new blocked-pool IP will be applied by
                    // lease4_select once the device re-discovers.

                    manage_dns_hijack_pools("hijack-blocked-pools");

                    manage_lease_event("expire", mac_address, ip_address,

                                       lease->subnet_id_, 0, false, true);

                    // Delete the existing lease so Kea performs a fresh allocation
                    // (lease4_select) on the next DHCPDISCOVER.  Without this Kea
                    // keeps finding the still-valid lease and calling lease4_renew
                    // again, creating an infinite NAK loop instead of moving the
                    // device to the blocked pool.
                    try
                    {
                        LeaseMgrFactory::instance().deleteLease(lease);
                        std::cout << "DNS Hijack Hook: Deleted lease " << ip_address
                                  << " to force blocked-pool allocation" << std::endl;
                    }
                    catch (const std::exception &ex)
                    {
                        std::cout << "DNS Hijack Hook: WARNING - failed to delete lease "
                                  << ip_address << ": " << ex.what() << std::endl;
                    }
                    handle.setContext("policy_force_nak", true);
                    handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);

                    return 0;
                }

                // Case 2: Device is now registered (no BLOCKED class) but is renewing a

                // stale blocked-pool IP from when it was previously blocked.

                if (!blocked && ip_is_blocked_pool)

                {

                    std::cout << "DNS Hijack Hook: Pool mismatch - registered device "

                              << mac_address << " renewing blocked-pool IP "

                              << ip_address << " - sending NAK" << std::endl;

                    std::cout.flush();

                    // Remove the hijack so the fresh DHCPDISCOVER can succeed.

                    manage_dns_hijack("unhijack", ip_address);

                    manage_acl("unblock", ip_address, lease->subnet_id_);

                    manage_lease_event("expire", mac_address, ip_address,

                                       lease->subnet_id_, 0, true, false);

                    // Delete the existing lease so Kea performs a fresh allocation
                    // (lease4_select) on the next DHCPDISCOVER rather than endlessly
                    // renewing the stale blocked-pool IP.
                    try
                    {
                        LeaseMgrFactory::instance().deleteLease(lease);
                        std::cout << "DNS Hijack Hook: Deleted lease " << ip_address
                                  << " to force regular-pool allocation" << std::endl;
                    }
                    catch (const std::exception &ex)
                    {
                        std::cout << "DNS Hijack Hook: WARNING - failed to delete lease "
                                  << ip_address << ": " << ex.what() << std::endl;
                    }
                    handle.setContext("policy_force_nak", true);
                    handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);

                    return 0;
                }
                // NAK so the client re-DHCPs and gets a regular-pool IP.
                bool ip_is_unregistered_pool = is_unregistered_pool_ip(ip_address);
                if (!blocked && ip_is_unregistered_pool)
                {
                    std::cout << "DNS Hijack Hook: Pool mismatch - registered device "
                              << mac_address << " renewing in unregistered pool "
                              << ip_address << " - sending NAK" << std::endl;

                    manage_lease_event("expire", mac_address, ip_address,
                                       lease->subnet_id_, 0, false, true);

                    try
                    {
                        LeaseMgrFactory::instance().deleteLease(lease);
                        std::cout << "DNS Hijack Hook: Deleted stale unregistered-VLAN lease "
                                  << ip_address << std::endl;
                    }
                    catch (const std::exception &ex)
                    {
                        std::cout << "DNS Hijack Hook: WARNING - failed to delete lease "
                                  << ip_address << ": " << ex.what() << std::endl;
                    }
                    handle.setContext("policy_force_nak", true);
                    handle.setStatus(CalloutHandle::NEXT_STEP_SKIP);
                    return 0;
                }

                if (blocked)

                {

                    std::cout << "DNS Hijack Hook: Device " << mac_address

                              << " is BLOCKED - enabling DNS hijack" << std::endl;

                    std::cout.flush();

                    if (ip_is_blocked_pool)

                    {

                        std::cout << "DNS Hijack Hook: [DEBUG] Ensuring blocked-pool DNS hijack ranges" << std::endl;

                        std::cout.flush();

                        manage_dns_hijack_pools("hijack-blocked-pools");
                    }

                    manage_dns_hijack("hijack", ip_address);

                    do_hijack = true;
                }

                else

                {

                    // Registered device — check whether it's on its assigned VLAN.

                    if (is_assigned_vlan_mismatch(mac_address, lease->subnet_id_))

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_address

                                  << " registered but on wrong VLAN (subnet "

                                  << lease->subnet_id_ << ") - restricting access" << std::endl;

                        std::cout.flush();

                        manage_dns_hijack("hijack", ip_address);

                        manage_acl("block", ip_address, lease->subnet_id_);

                        do_hijack = true;
                    }

                    else

                    {

                        std::cout << "DNS Hijack Hook: Device " << mac_address

                                  << " is REGISTERED - removing DNS hijack" << std::endl;

                        std::cout.flush();

                        manage_dns_hijack("unhijack", ip_address);

                        manage_acl("unblock", ip_address, lease->subnet_id_);

                        do_hijack = false;
                    }
                }

                manage_unregistered_lease("remove", mac_address, ip_address, 0);

                if (!blocked_ip.empty() && blocked_ip != ip_address)

                {

                    std::cout << "DNS Hijack Hook: [DEBUG] Removing ACL for blocked IP: "

                              << blocked_ip << std::endl;

                    std::cout.flush();

                    manage_acl("unblock", blocked_ip, lease->subnet_id_);

                    std::cout << "DNS Hijack Hook: [DEBUG] Removing per-IP DNS hijack for: "

                              << blocked_ip << std::endl;

                    std::cout.flush();

                    manage_dns_hijack("unhijack", blocked_ip);
                }
            }

            else

            {

                std::cout << "DNS Hijack Hook: Device " << mac_address

                          << " is UNREGISTERED - enabling DNS hijack" << std::endl;

                std::cout.flush();

                manage_dns_hijack("hijack", ip_address);

                if (!ip_is_blocked_pool)

                {

                    manage_acl("block", ip_address, lease->subnet_id_);
                }

                manage_unregistered_lease("upsert", mac_address, ip_address, lease_seconds);

                do_hijack = true;
            }

            // Table 6 + Table 7: update the portal DB with renewal info (async).

            manage_lease_event("renew", mac_address, ip_address,

                               lease->subnet_id_, lease_seconds,

                               ip_is_blocked_pool, do_hijack);

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            std::cout << "DNS Hijack Hook: [DEBUG] lease4_renew EXIT (success)" << std::endl;

            std::cout.flush();

            return 0;
        }

        catch (const std::exception &ex)

        {

            std::cout << "DNS Hijack Hook ERROR in lease4_renew: " << ex.what() << std::endl;

            std::cout.flush();

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            return 1;
        }
    }

    int pkt4_send(CalloutHandle &handle)
    {
        bool force_nak = get_bool_context(handle, "policy_force_nak");
        std::cout << "DNS Hijack Hook: [DEBUG] pkt4_send called - policy_force_nak="
                  << (force_nak ? "true" : "false") << std::endl;

        if (!force_nak)
        {
            return 0;
        }
        if (!get_bool_context(handle, "policy_force_nak"))
        {
            return 0;
        }

        Pkt4Ptr response;
        handle.getArgument("response4", response);
        if (response)
        {
            response->setType(DHCPNAK);
            response->setYiaddr(IOAddress("0.0.0.0"));
            response->delOption(DHO_DHCP_LEASE_TIME);
            response->delOption(DHO_DHCP_RENEWAL_TIME);
            response->delOption(DHO_DHCP_REBINDING_TIME);
            response->delOption(DHO_SUBNET_MASK);
            response->delOption(DHO_ROUTERS);
            response->delOption(DHO_DOMAIN_NAME_SERVERS);
        }
        return 0;
    }

    // Called when a lease expires (cleanup ACL for released IP)

    int lease4_expire(CalloutHandle &handle)
    {
        try
        {
            Lease4Ptr lease;
            handle.getArgument("lease4", lease);
            if (!lease)
            {
                handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);
                return 0;
            }

            std::string ip_address = lease->addr_.toText();
            std::string mac_address;
            HWAddrPtr hwaddr = lease->hwaddr_;

            if (hwaddr)
            {
                mac_address = hwaddr->toText(false);
            }

            bool ip_is_blocked_pool = is_blocked_pool_ip(ip_address);
            bool ip_is_unregistered_pool = is_unregistered_pool_ip(ip_address);

            std::cout << "DNS Hijack Hook: Lease expired - IP: " << ip_address
                      << " blocked_pool=" << ip_is_blocked_pool << std::endl;

            std::cout.flush();

            // Skip ACL unblock for blocked-pool IPs — they are covered by range
            // rules so no per-IP rule was ever added; nothing to undo.
            // For all other IPs, always unblock: the lease is expired so nobody
            // holds this address, and stale per-IP deny rules should not accumulate.
            if (!ip_is_blocked_pool && !ip_is_unregistered_pool)
            {
                manage_acl("unblock", ip_address, lease->subnet_id_);
            }
            else
            {
                std::cout << "DNS Hijack Hook: Skipping ACL unblock for " << ip_address
                          << " because it is a restricted pool address" << std::endl;
            }

            // Always clean up DNS hijack rules — the device will get fresh ones on

            // its next lease (in the blocked pool if it is admin-blocked).

            if (!ip_is_unregistered_pool)
            {
                manage_dns_hijack("unhijack", ip_address);
            }
            else
            {
                std::cout << "DNS Hijack Hook: Skipping DNS unhijack for unregistered VLAN IP "
                          << ip_address << std::endl;
            }

            if (!mac_address.empty())

            {

                manage_unregistered_lease("expire", mac_address, ip_address, 0);

                // Table 7: mark lease as expired in portal DB (async).

                manage_lease_event("expire", mac_address, ip_address,

                                   lease->subnet_id_, 0, false, false);
            }

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            return 0;
        }

        catch (const std::exception &ex)

        {

            std::cout << "DNS Hijack Hook ERROR in lease4_expire: " << ex.what() << std::endl;

            handle.setStatus(CalloutHandle::NEXT_STEP_CONTINUE);

            return 1;
        }
    }
    bool is_registered_host(const ConstHostPtr &host)
    {
        if (!host)
        {
            return false;
        }

        try
        {
            const ClientClasses &classes4 = host->getClientClasses4();
            if (classes4.contains("REGISTERED"))
            {
                return true;
            }
        }
        catch (...)
        {
        }

        try
        {
            isc::data::ConstElementPtr ctx = host->getContext();
            if (ctx && ctx->getType() == isc::data::Element::map)
            {
                isc::data::ConstElementPtr registered = ctx->get("registered");
                if (registered &&
                    registered->getType() == isc::data::Element::boolean)
                {
                    return registered->boolValue();
                }
            }
        }
        catch (...)
        {
        }

        return false;
    }

    bool is_pool_state_mismatch(Pkt4Ptr query, bool &admin_blocked_out)
    {
        if (!query)
            return false;

        const uint8_t msg_type = query->getType();
        if (msg_type != DHCPREQUEST)
            return false;

        HWAddrPtr hwaddr = query->getHWAddr();
        if (!hwaddr || hwaddr->hwaddr_.empty())
            return false;

        std::string mac_str = hwaddr->toText(false); // clean format

        // === Get all reservations for this MAC ===
        ConstHostCollection all_hosts = HostMgr::instance().getAll(
            Host::IDENT_HWADDR,
            &hwaddr->hwaddr_[0], hwaddr->hwaddr_.size());

        bool admin_blocked = false;
        bool has_subnet_specific = false;
        bool global_blocked = false;
        bool is_registered = false;

        for (const auto &h : all_hosts)
        {
            if (!h)
                continue;

            if (is_registered_host(h))
                is_registered = true;

            if (h->getIPv4SubnetID() == SUBNET_ID_GLOBAL)
            {
                if (is_blocked_host(h))
                    global_blocked = true;
            }
            else
            {
                has_subnet_specific = true;
                if (is_blocked_host(h))
                    admin_blocked = true;
            }
        }

        if (!has_subnet_specific)
            admin_blocked = global_blocked;

        // === Get requested / current IP ===
        std::string ip_address;
        {
            OptionPtr opt = query->getOption(DHO_DHCP_REQUESTED_ADDRESS);
            if (opt)
            {
                const OptionBuffer &data = opt->getData();
                if (data.size() == 4)
                {
                    std::stringstream ip;
                    ip << static_cast<unsigned>(data[0]) << "."
                       << static_cast<unsigned>(data[1]) << "."
                       << static_cast<unsigned>(data[2]) << "."
                       << static_cast<unsigned>(data[3]);
                    ip_address = ip.str();
                }
            }
            else
            {
                ip_address = query->getCiaddr().toText(); // INIT-REBOOT / renewals
            }
        }

        // === Debug: Initial request info ===
        std::cout << "DNS Hijack Hook: [DEBUG] is_pool_state_mismatch - "
                  << "MAC=" << mac_str
                  << " IP=" << (ip_address.empty() ? "<none>" : ip_address)
                  << " is_registered=" << (is_registered ? "true" : "false")
                  << " admin_blocked=" << (admin_blocked ? "true" : "false")
                  << std::endl;

        if (ip_address.empty() || ip_address == "0.0.0.0")
        {
            if (ip_address.empty())
            {
                std::cout << "DNS Hijack Hook: [DEBUG] No IP address found in DHCPREQUEST - return false" << std::endl;
            }
            else
            {
                std::cout << "DNS Hijack Hook: [DEBUG] IP address in DHCPREQUEST is " << ip_address << " - return false" << std::endl;
            }
            return false;
        }

        bool ip_is_unregistered_pool = is_unregistered_pool_ip(ip_address);
        bool ip_is_blocked_pool = is_blocked_pool_ip(ip_address);

        // === Case 1: Registered device trying to use unregistered pool ===
        if (is_registered && !admin_blocked && ip_is_unregistered_pool)
        {
            std::cout << "DNS Hijack Hook: [DEBUG] Pool mismatch detected: "
                      << "Registered device on unregistered pool IP=" << ip_address << std::endl;

            admin_blocked_out = false; // Not an admin block, but still a policy mismatch
            return true;
        }

        // === Case 2: Classic blocked vs blocked-pool mismatch ===
        std::cout << "DNS Hijack Hook: [DEBUG] Blocked pool check - "
                  << "IP=" << ip_address
                  << " in_blocked_pool=" << (ip_is_blocked_pool ? "true" : "false")
                  << " admin_blocked=" << (admin_blocked ? "true" : "false") << std::endl;

        if (admin_blocked != ip_is_blocked_pool)
        {
            admin_blocked_out = admin_blocked;
            return true;
        }

        return false;
    }
    // =============================================
    // pkt4_receive hook
    // =============================================
    int pkt4_receive(CalloutHandle &handle)
    {
        Pkt4Ptr query;
        handle.getArgument("query4", query);

        if (query)
        {
            HWAddrPtr hwaddr = query->getHWAddr();
            if (hwaddr)
            {
                spawn_port_lookup(hwaddr->toText(false));
            }
        }

        bool admin_blocked = false;
        if (is_pool_state_mismatch(query, admin_blocked))
        {
            handle.setContext("policy_force_nak", true);
            std::cout << "DNS Hijack Hook: Pool state mismatch - will NAK"
                      << (admin_blocked ? " (blocked device with non-blocked-pool IP)"
                                        : " (registered device with unregistered-pool IP)")
                      << " (pkt4_receive)" << std::endl;
        }

        return 0;
    }
}
