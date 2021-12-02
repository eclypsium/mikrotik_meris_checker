/*
    Copyright 2018-2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
        list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"
#include "md5.hpp"

namespace
{
    const char s_version[] = "By the Way 1.1.0";

    /*!
     * Parses the command line arguments. The program will always use two
     * parameters (ip and winbox port) but the port will default to 8291 if
     * not present on the CLI
     *
     * \param[in] p_arg_count the number of arguments on the command line
     * \param[in] p_arg_array the arguments passed on the command line
     * \param[in,out] p_ip the ip address to connect to
     * \param[in,out] p_winbox_port the winbox port to connect to
     * \return true if we have valid ip and ports. false otherwise.
     */
    bool parseCommandLine(int p_arg_count, const char* p_arg_array[],
                          std::string& p_ip, std::string& p_winbox_port, std::string& p_login, std::string& p_password)
    {
        boost::program_options::options_description description("options");
        description.add_options()
        ("help,h", "A list of command line options")
        ("version,v", "Display version information")
        ("winbox-port,w", boost::program_options::value<std::string>()->default_value("8291"), "The winbox port")
        ("ip,i", boost::program_options::value<std::string>(), "The ip to connect to")
        ("login,l", boost::program_options::value<std::string>()->default_value("admin"), "The username")
        ("password,p", boost::program_options::value<std::string>()->default_value(""), "The password");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_arg_count, p_arg_array, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << "\n" << std::endl;
            std::cerr << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cerr << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cerr << "Version: " << ::s_version << std::endl;
            return false;
        }

        if (argv_map.count("ip") && argv_map.count("winbox-port") && argv_map.count("login") && argv_map.count("password"))
        {
            p_ip.assign(argv_map["ip"].as<std::string>());
            p_winbox_port.assign(argv_map["winbox-port"].as<std::string>());
            p_login.assign(argv_map["login"].as<std::string>());
            p_password.assign(argv_map["password"].as<std::string>());
            return true;
        }
        else
        {
            std::cerr << description << std::endl;
        }

        return false;
    }
}

bool print_schedulers(const std::string& p_ip, const std::string& p_port,
                      const std::string& p_username, const std::string& p_password) {
    Winbox_Session mproxy_session(p_ip, p_port);
    if (!mproxy_session.connect())
    {
        std::cerr << "[-] Failed to connect to the remote host" << std::endl;
        return false;
    }

    boost::uint32_t p_session_id = 0;
    if (!mproxy_session.login(p_username, p_password, p_session_id))
    {
        std::cerr << "[-] Login failed." << std::endl;
        return false;
    }

    WinboxMessage msg;
    msg.set_to(48, 3);
    msg.set_command(16646148);
//    msg.set_command(16646157);
    msg.set_request_id(1);
    msg.set_reply_expected(true);
    msg.set_session_id(p_session_id);
    mproxy_session.send(msg);
    msg.reset();
    mproxy_session.receive(msg);
    if (msg.has_error())
    {
        std::cout << "[-] " << msg.get_error_string() << std::endl;
        return false;
    }

    std::cout << msg.serialize_to_json() << std::endl;
    if(msg.serialize_to_json() == "{}") {
        return false;
    }
    return true;
}

int main(int p_argc, const char** p_argv)
{
    std::string ip;
    std::string winbox_port;
    std::string admin_username = "read";
    std::string admin_password = "";
    if (!parseCommandLine(p_argc, p_argv, ip, winbox_port, admin_username, admin_password))
    {
        return EXIT_FAILURE;
    }

    print_schedulers(ip, winbox_port, admin_username, admin_password);
}