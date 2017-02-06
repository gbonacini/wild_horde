// --------------------------------------------------------------------------
// wh (Wild Horde) - a tool capable to send heavy malformed icmp packets traffic
// Copyright (C) 2017  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// --------------------------------------------------------------------------

#ifndef  WH_INCLUDE
#define  WH_INCLUDE

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <tuple>
#include <cstring>
#include <random>
#include <functional>
#include <bitset>   
#include <utility> 

#include <thread>
#include <mutex>

#include <signal.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <readline/readline.h>
#include <readline/history.h>

#ifdef LINUX_OS
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

namespace wh{
    
    enum SHUTSTAT { SHDEACT, SHACT, SHEXPIRED };
    enum LIMITS   { MAXPARAMS=6, MAXSNDPKTSIZE=2560, MAXRCVPKTSIZE=65535, MAXSCANPACKETS=500 };
    enum PARAMS   { NOPAR=1, BNTPAR=5, SCANPAR=3, KILLPAR=2, SERPAR=3, PLDPAR=4, ALLPAR=2 };
    enum JOB      { THREAD, DESCR, RUN };
    enum JOBTYPE  { STD, SCAN};
    enum CODE     { CODEMIN,  CODEMAX, CODEPSIZE };
    enum IPHDRDEF { DEFHDRLEN=5, DEFTOS=0x0, DEFFRAGOFF=0x0, DEFCHKSUM=0x0, DEFTRASPICMP=1, DEFID=0xF0F0 };
    enum STAGES   { BATCH, WAIT, INTERACTIVE };
    enum PAYLOAD  { NOPLD, STDPLD, MAXPLD, INVLENPLD, INVCHKSPLD, BITSPLD };
    enum CMDTYPE  { SRVCMD, ENVCMD, PLOADCMD };
    enum SCANMODE { ALL, ALLTYPE, ALLCODE, VALIDS};
    
    static volatile sig_atomic_t               shutDown = SHDEACT;
   
    typedef struct ip                                     Ip;
    typedef struct icmp                                   Icmp;
    typedef struct ifreq                                  Ifreq;
    typedef struct ifaddrs                                Ifaddrs;
    typedef struct sockaddr_in                            Sockaddr_in;
    typedef std::tuple<std::thread*, std::string, bool>   bnThread;
    typedef std::tuple<uint8_t, uint8_t, uint16_t>        codeRange;

    #ifdef LINUX_OS
        class Capability{
            public:
                   explicit  Capability(bool noRoot);
                             ~Capability(void);
                   void      printStatus(void)                         const;
                   void      getCredential(void);
                   void      reducePriv(const std::string capText);

            private:
                   uid_t     uid,
                             euid;
                   gid_t     gid,
                             egid;;
                   cap_t     cap,
                             newcaps;
        };
        class CapabilityException final{
            public:
               CapabilityException(std::string&  errString);
               CapabilityException(std::string&& errString);
               std::string what(void)                                  const  noexcept(true);
            private:
               std::string errorMessage;
        };

    #endif
    
    class Env{
        public:
           bool                                           debug;
           std::string                                    iface;
           SCANMODE                                       scanmode;
           uint32_t                                       maxPktSent;
           uint16_t                                       maxPktSize;
           useconds_t                                     thTimeo;
           Ip                                             *ip;
           Icmp                                           *icmp;
           Ifreq                                          ifr;
           std::bitset<BITSPLD>                           payload;  
           bool                                           printIncoming;
           std::vector<std::string>                       params;
           std::vector<uint8_t>                           packet;
           
           explicit Env(std::string& ifc);
                    Env(const Env& env);
                    ~Env(void);
           void     setThreadEnv(Sockaddr_in *sin, bool setIcmp)              noexcept(false);
           uint8_t  genRnd(std::vector<uint8_t>  *array,
                           ptrdiff_t start)                           const   noexcept(false);
    };
    
    class Wh{
        public: 
           void  shellLoop(void);
           ~Wh(void);
           Wh(std::string& iface);
    
        private:
           volatile sig_atomic_t                         stage;    
           mutable std::mutex                            confMtx,
                                                         countMtx,
                                                         screenMtx;
           std::set<std::string>                         ifList;
           unsigned long                                 nextThread;
           const char*                                   prompt;
           size_t                                        currParam;
           Env                                           env;
           std::map<unsigned long, bnThread>             threadsList;
           const std::map<std::string, SCANMODE>         scanModes;
           const std::map<SCANMODE, std::string>         scanModesDescr;
           const std::map<std::string, uint8_t>          opts;
           const std::map<std::string,  
                          std::function<int(void)>>      commands,
                                                         setCmds,
                                                         ploadCmds;
           const std::map<uint8_t, codeRange>            icmpType;
           std::map<uint8_t, codeRange>                  icmpTypeFull;
    
           inline bool   sendpk(const int fd, const uint8_t* buff, 
                                const size_t bufflen, const sockaddr* sin,
                                useconds_t pause)                          const   noexcept(true); 
           void          getLocalIp(void)                                          noexcept(false);
           void          resetIpHdr(void)                                          noexcept(false);
           uint16_t      checksum(void *buff, size_t len)                  const   noexcept(true);
           int           parseCommand(CMDTYPE type)                        const   noexcept(true);
           int           setPayloadMode(std::string& mode, PAYLOAD type)           noexcept(true);
           int           setPrintMode(std::string& mode)                           noexcept(true);
           int           setScanMode(std::string& mode)                            noexcept(true);
           int           setDebugMode(std::string& mode)                           noexcept(true);
           void          addScanThread(void)                                       noexcept(false);
           void          addJobThread(void)                                        noexcept(false);
           void          killThread(void)                                          noexcept(true);
           bool          chkPrno(PARAMS num)                               const   noexcept(true);
           void          printStatus(void)                                 const   noexcept(true);
           void          printHelp(void)                                   const   noexcept(true);
           void          printList(void)                                   const   noexcept(true);
           void          printPromptErr(std::string&& msg, bool prm=false) const   noexcept(true);
           int           openRSocket(Env& cenv)                            const   noexcept(false);
           std::string   getStatus(JOBTYPE type, Env& cenv)                const   noexcept(false);
           void          trace(std::string& header, 
                               const std::vector<uint8_t>* buff,
                               size_t begin, size_t end, size_t max)       const   noexcept(true);
           void          trace(const char* header, const uint8_t* buff, 
                               const size_t size, size_t begin, 
                               size_t end)                                 const   noexcept(true);
           void          waitExit(void)                                            noexcept(false);
    };

    class WhException final{
        public:
           WhException(std::string& errString);
           WhException(std::string&& errString);
           std::string what(void)                                          const  noexcept(true);
        private:
           std::string errorMessage;
    };

}    

#endif
