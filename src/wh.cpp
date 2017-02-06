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

#include <wh.hpp>

using namespace std;

namespace wh{

    #ifdef LINUX_OS

       Capability::Capability(bool noRoot) : uid{getuid()},       euid{geteuid()},
                                             gid{getgid()},       egid{getegid()},
                                             cap{cap_get_proc()}, newcaps{cap}
       {  if(noRoot) 
             if(uid == 0 || gid == 0 )
                 throw CapabilityException("Root user or group are not permitted: use a standard user instead.");
       }

       Capability::~Capability(void){
          cap_free(cap);
          cap_free(nullptr);
       }

       void Capability::printStatus(void) const noexcept(true){
           cerr << "UID: " << to_string(uid) << " EUID: " << to_string(euid) << endl;
           cerr << "GID: " << to_string(gid) << " GID:  " << to_string(egid) << endl;
           cerr << "Running with capabilities: " << cap_to_text(cap, NULL)  << endl;
       }

       void Capability::getCredential(void) noexcept(false){
           uid  = getuid();
           euid = geteuid(); 
           gid  = getgid();
           egid = getegid();
           cap  = cap_get_proc();
           if(cap == nullptr)
               throw CapabilityException(string("Capability error reading credential: ") + strerror(errno));
       }

       void Capability::reducePriv(const string capText) noexcept(false){
           if(prctl(PR_SET_KEEPCAPS, 1) ==  -1)
               throw CapabilityException(string("Capability setting error(a): ") + strerror(errno));
           newcaps                      = cap_from_text(capText.c_str());
           if(setresgid(gid, gid, gid)  ==  -1)
               throw CapabilityException(string("Capability setting error(b): ") + strerror(errno));
           if(setresuid(uid, uid, uid)  ==  -1)
               throw CapabilityException(string("Capability setting error(c): ") + strerror(errno));
           if(cap_set_proc(newcaps)     ==  -1)
               throw WhException(string("Capability setting error(d): ") + strerror(errno));

       }

       CapabilityException::CapabilityException(string& errString){
           errorMessage            = errString;
       }
   
       CapabilityException::CapabilityException(string&& errString){
           errorMessage            = move(errString);
       }
    
       string CapabilityException::what() const noexcept(true){
           return errorMessage;
       }

    #endif

    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    #endif

    Env::Env(string& ifc) : debug{false},                iface{ifc},                scanmode{VALIDS},     
                            maxPktSent{MAXSCANPACKETS},  maxPktSize{MAXSNDPKTSIZE}, thTimeo{0}, 
                            ip{nullptr},                 icmp{nullptr},             ifr{},  
                            payload{0x1F},               printIncoming{false},      params{MAXPARAMS}
    {}

    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif

    Env::Env(const Env& env) : debug{env.debug},            iface{env.iface},               scanmode{env.scanmode},
                               maxPktSent{env.maxPktSent},  maxPktSize{env.maxPktSize},     thTimeo{env.thTimeo},
                               ip{nullptr},                 icmp{nullptr},                  ifr(env.ifr),
                               payload{env.payload},        printIncoming{env.printIncoming}, 
                               params{env.params},          packet(env.maxPktSize)
    {
       ip                            = reinterpret_cast<Ip*>(packet.data());
       icmp                          = reinterpret_cast<Icmp*>((packet.data() + sizeof(Ip)));

       ip->ip_src.s_addr             = env.ip->ip_src.s_addr;
       ip->ip_hl                     = env.ip->ip_hl;    // uint8_t
       ip->ip_v                      = env.ip->ip_v;     // uint8_t
       ip->ip_tos                    = env.ip->ip_tos;   // uint8_t
       ip->ip_ttl                    = env.ip->ip_ttl;   // uint8_t
       ip->ip_p                      = env.ip->ip_p;     // uint8_t
       ip->ip_off                    = env.ip->ip_off;   // uint16_t  
       ip->ip_sum                    = env.ip->ip_sum;   // uint16_t  
       ip->ip_id                     = env.ip->ip_id;    // uint16_t  

       genRnd(&packet, (sizeof(Ip) + ICMP_MINLEN));
    }

    Env::~Env(void){
    }
    
    void Env::setThreadEnv(Sockaddr_in *sin, bool setIcmp) noexcept(false){
        try{

            sin->sin_family                    = AF_INET;

            sin->sin_addr.s_addr           = inet_addr(params[1].c_str()); 
            ip->ip_dst.s_addr              = sin->sin_addr.s_addr;
            if(setIcmp){
                icmp->icmp_type            = static_cast<uint8_t>(stoi(params[2]));  
                icmp->icmp_code            = static_cast<uint8_t>(stoi(params[3])); 
            }
        
        }catch(...){
            throw WhException("setThreadEnv: Error setting thread env.");
        }
    }
        
    uint8_t Env::genRnd(vector<uint8_t> *array, ptrdiff_t start) const noexcept(false){
        try{
            random_device              rdev;         
            mt19937                    gen(rdev());
            uniform_int_distribution<> dis(0, 255);
            
            if(array == nullptr)
                return static_cast<uint8_t>(dis(gen));
            else{
                for(auto i = array->begin() + start; i != array->end(); ++i)
                    *i = static_cast<uint8_t>(dis(gen));
                return 0;
            }   
        }catch(...){
            throw WhException("genRnd: Error generating random numbers");
        }
    }

    Wh::Wh(string& iface) : stage{BATCH}, nextThread{0}, prompt{":-X "}, currParam{0}, env(iface),
                   scanModes{{"all", ALL}, {"alltype", ALLTYPE}, {"allcode", ALLCODE}, {"valids", VALIDS}}, 
                   scanModesDescr{{ALL, "all"}, {ALLTYPE, "alltype"}, {ALLCODE, "allcode"}, {VALIDS, "valids"}}, 
                   opts{{"on", 1}, {"off", 0}},
                   commands{{ "exit",      [ ](){return 1;}}, 
                            { "wexit",     [&](){if(stage == BATCH) waitExit(); 
                                                 else printPromptErr("waitExit only permitted in batch mode.");
                                                 return 0;}},
                            { "job",       [&](){if(chkPrno(BNTPAR))  addJobThread();  return 0; }},
                            { "scan",      [&](){if(chkPrno(SCANPAR)) addScanThread(); return 0; }},
                            { "kill",      [&](){if(chkPrno(KILLPAR)) killThread(); return 0; }},
                            { "help",      [&](){if(chkPrno(NOPAR)) printHelp();  return 0; }}, 
                            { "list",      [&](){if(chkPrno(NOPAR)) printList();  return 0; }},
                            { "reset",     [&](){if(chkPrno(NOPAR)) resetIpHdr(); return 0; }},
                            { "set",       [&](){return parseCommand(ENVCMD); }}
                   },
                   setCmds {{ "iface",     [&](){if(chkPrno(SERPAR)){
                                                    confMtx.lock(); 
                                                    if(ifList.find(env.params[2]) != ifList.end()) {
                                                        env.iface = env.params[2]; 
                                                        getLocalIp();
                                                        env.ip->ip_src.s_addr =  
                                                               reinterpret_cast<Sockaddr_in *>
                                                                    (&env.ifr.ifr_addr)->sin_addr.s_addr;
                                                    }else 
                                                        cerr << "Wrong Parameters (iface).\n";
                                                    confMtx.unlock();
                                                 } return 0; }},
                            { "headerlen", [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_hl  = 
                                                 static_cast<uint32_t>(stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "ipversion", [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_v     = 
                                                 static_cast<uint8_t>( stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "tos",       [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_tos   = 
                                                 static_cast<uint8_t>( stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "fragmoff",  [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_off   = 
                                                 static_cast<uint16_t>(stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "ttl",       [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_ttl   = 
                                                 static_cast<uint8_t>( stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "transp",    [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_p     = 
                                                 static_cast<uint8_t>( stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "checksum",  [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_sum   = 
                                                 static_cast<uint16_t>(stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "srcaddr",   [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 env.ip->ip_src.s_addr = 
                                                 inet_addr(env.params[2].c_str()); confMtx.unlock(); return 0;}},
                            { "print",     [&](){confMtx.lock(); if(chkPrno(SERPAR)) setPrintMode(env.params[2]);
                                                 confMtx.unlock(); return 0;}},
                            { "debug",     [&](){confMtx.lock(); if(chkPrno(SERPAR)) setDebugMode(env.params[2]);
                                                 confMtx.unlock(); return 0;}},
                            { "maxpcksnt", [&](){confMtx.lock(); if(chkPrno(SERPAR)) env.maxPktSent = 
                                                 static_cast<uint16_t>(stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "maxpktsize", [&](){confMtx.lock(); if(chkPrno(SERPAR)) env.maxPktSize = 
                                                 static_cast<uint16_t>(stoi(env.params[2], nullptr, 0)); 
                                                 confMtx.unlock(); return 0;}},
                            { "thrdtimeo", [&](){confMtx.lock(); if(chkPrno(SERPAR)) env.thTimeo    = 
                                                 static_cast<uint32_t>(stoul(env.params[2])); 
                                                 confMtx.unlock(); return 0;}},
                            { "scanmode",  [&](){confMtx.lock(); if(chkPrno(SERPAR)) 
                                                 setScanMode(env.params[2]);
                                                 confMtx.unlock(); return 0;}},
                            { "payload",   [&](){return parseCommand(PLOADCMD); }},
                            { "all",       [&](){if(chkPrno(ALLPAR)) printStatus(); return 0; }}  
                   },
                   ploadCmds{{ "null",      [&](){confMtx.lock(); if(chkPrno(PLDPAR)) 
                                                  setPayloadMode(env.params[3], NOPLD); confMtx.unlock(); return 0; }},
                             { "std",       [&](){confMtx.lock(); if(chkPrno(PLDPAR)) 
                                                  setPayloadMode(env.params[3], STDPLD); confMtx.unlock(); return 0; }},
                             { "huge",      [&](){confMtx.lock(); if(chkPrno(PLDPAR)) 
                                                  setPayloadMode(env.params[3], MAXPLD); confMtx.unlock(); return 0; }},
                             { "invchks",   [&](){confMtx.lock(); if(chkPrno(PLDPAR)) 
                                                  setPayloadMode(env.params[3], INVCHKSPLD); confMtx.unlock(); return 0; }}
                   },
                   #ifdef LINUX_OS 
                       icmpType{{0,make_tuple(0,0,8)},      {3,make_tuple(0,15,8)},     {4,make_tuple(0,0,8)},
                                {5,make_tuple(0,3,8)},      {6,make_tuple(255,255,0)},  {8,make_tuple(0,0,8)},
                                {9,make_tuple(0,0,0)},      {10,make_tuple(0,0,0)},     {11,make_tuple(0,1,8)},
                                {12,make_tuple(0,2,8)},     {13,make_tuple(0,0,16)},    {14,make_tuple(0,0,16)},
                                {15,make_tuple(0,0,4)},     {16,make_tuple(0,0,4)},     {17,make_tuple(0,0,8)},
                                {18,make_tuple(0,0,8)},     {19,make_tuple(255,255,0)}, {20,make_tuple(255,255,0)},
                                {21,make_tuple(255,255,0)}, {22,make_tuple(255,255,0)}, {23,make_tuple(255,255,0)},
                                {24,make_tuple(255,255,0)}, {25,make_tuple(255,255,0)}, {26,make_tuple(255,255,0)},
                                {27,make_tuple(255,255,0)}, {28,make_tuple(255,255,0)}, {29,make_tuple(255,255,0)},
                                {30,make_tuple(0,0,16)},    {31,make_tuple(255,255,8)}, {32,make_tuple(255,255,0)}, 
                                {33,make_tuple(255,255,0)}, {34,make_tuple(255,255,0)}, {35,make_tuple(255,255,0)},
                                {36,make_tuple(255,255,0)}, {37,make_tuple(255,255,4)}, {38,make_tuple(255,255,12)},
                                {39,make_tuple(255,255,0)}, {40,make_tuple(255,255,8)}, {41,make_tuple(255,255,0)},
                                {253,make_tuple(255,255,0)},{254,make_tuple(255,255,0)},{255,make_tuple(255,255,0)} 
                       },
                   #else
                       icmpType{{0,{0,0,8}},       {3,{0,15,8}},      {4,{0,0,8}},       {5,{0,3,8}},      
                                {6,{255,255,0}},   {8,{0,0,8}},       {9,{0,0,0}},       {10,{0,0,0}},  
                                {11,{0,1,8}},      {12,{0,2,8}},      {13,{0,0,16}},     {14,{0,0,16}},
                                {15,{0,0,4}},      {16,{0,0,4}},      {17,{0,0,8}},      {18,{0,0,8}},   
                                {19,{255,255,0}},  {20,{255,255,0}},  {21,{255,255,0}},  {22,{255,255,0}},
                                {23,{255,255,0}},  {24,{255,255,0}},  {25,{255,255,0}},  {26,{255,255,0}}, 
                                {27,{255,255,0}},  {28,{255,255,0}},  {29,{255,255,0}},  {30,{0,0,16}},  
                                {31,{255,255,8}},  {32,{255,255,0}},  {33,{255,255,0}},  {34,{255,255,0}}, 
                                {35,{255,255,0}},  {36,{255,255,0}},  {37,{255,255,4}},  {38,{255,255,12}}, 
                                {39,{255,255,0}},  {40,{255,255,8}},  {41,{255,255,0}},  {253,{255,255,0}}, 
                                {254,{255,255,0}}, {255,{255,255,0}} 
                       },
                   #endif
                   icmpTypeFull(icmpType)
    {
           for(uint16_t idx=0; idx<=255; ++idx){
               if(icmpType.find(static_cast<uint8_t>(idx)) == icmpType.end())
                   icmpTypeFull[static_cast<uint8_t>(idx)]  = make_tuple(0,0,0);
           }
    
           resetIpHdr();
    
           Ifaddrs *ifaddr;
           if(getifaddrs(&ifaddr) == -1)
               throw WhException("Wh: Error unumerating eth interfaces.");

           for(Ifaddrs *ifcurr = ifaddr; ifcurr != nullptr; ifcurr=ifcurr->ifa_next)
                ifList.insert(ifcurr->ifa_name);
    
           freeifaddrs(ifaddr);
    }
    
    Wh::~Wh(void){
           for(auto i = threadsList.begin(); i != threadsList.end(); ++i){
               cerr << "Stopping: " << (*i).first << endl;
               get<RUN>((*i).second) = false;
           }
           delete env.ip;
    }
    
    void Wh::printPromptErr(string&& msg, bool prm) const noexcept(true){
          try{
              screenMtx.lock();
              cerr << msg << "\n"; 
              if(prm) cerr << prompt;
              screenMtx.unlock();
          }catch(...){
              printPromptErr("printList: unhandled Error");
          }
    }
    
    void Wh::printList(void) const noexcept(true){
          try{
              screenMtx.lock();
              cerr << "Threads:" << endl;
              for(auto i = threadsList.cbegin(); i != threadsList.cend(); ++i)
                  cerr << (*i).first << "  " << get<DESCR>((*i).second) << endl;
              cerr << endl;
              screenMtx.unlock();
          }catch(...){
              printPromptErr("printList: unhandled Error");
          }
    }
           
    bool Wh::chkPrno(PARAMS num) const noexcept(true){
        if((currParam + 1) != num){
            printPromptErr(string("Invalid number of parameters, expected ") +
                           to_string(num) + " specified " +  to_string(currParam + 1));
            return false;
        }
        return true; 
    }
   
    void Wh::trace(const char* header, const uint8_t* buff, const size_t size,
                   size_t begin, size_t end) const noexcept(true){
       cerr << header << endl << endl;
   
       bool last  = false, first = false;
       for (size_t i = 0; i < size; i += 16) {
          cerr << setfill('0') << setw(5) << dec << i << ":  ";
          for (size_t j = i; j < i + 16; j++) {
             if(end !=0){
                if(j == begin ){cerr <<  "\033[7m"; first = true;}
                if(j == end   ){cerr <<  "\033[0m"; last  = true;}
             }
             if(j < size)
                cerr << setfill('0') << setw(2) << hex
                          << static_cast<int>(buff[j]) << " ";
             else cerr << "   ";
          }
          if(first){cerr <<  "\033[0m"; }
          cerr << " ";
          for (size_t j = i; j < i + 16; j++) {
             if(end !=0){
                if((last || j == begin)){cerr <<  "\033[7m"; last  = false; }
                if(j == end            ){cerr <<  "\033[0m"; last  = false; }
             }
             if(j < size){
                if((buff[j] > 31) && (buff[j] < 128) && (buff[j] != 127))
                   cerr << buff[j] ;
                else cerr << "." ;
             }
          }
          first = false;
          cerr << endl;
       }
       cerr << endl << endl;
    }
 
    void Wh::trace(string& header, const vector<uint8_t>* buff,
               size_t begin, size_t end, size_t max) const noexcept(true){
       screenMtx.lock();
       cerr << header << endl << endl;
    
       size_t len    = max ? max : buff->size();
       bool   last   = false, first = false;
       for (size_t i = 0; i < len; i += 16) {
          cerr << setfill('0') << setw(5) << dec << i << ":  ";
          for (size_t j = i; j < i + 16; j++) {
             if(end !=0){
                if(j == begin ){cerr <<  "\033[7m"; first = true;}
                if(j == end   ){cerr <<  "\033[0m"; last  = true;}
             }
             if(j < len)
                cerr << setfill('0') << setw(2) << hex
                     << static_cast<int>(buff->at(j)) << " ";
             else cerr << "   ";
          }
          if(first){cerr <<  "\033[0m"; }
          cerr << " ";
          for (size_t j = i; j < i + 16; j++) {
             if(end !=0){
                if(last && !first   ){cerr << "\033[7m"; last  = false; }
                if(j == begin       ){cerr << "\033[7m"; first = false; }
                if(j == end         ){cerr << "\033[0m"; last  = false; }
             }
             if(j < len){
                if((buff->at(j) > 31) && (buff->at(j) < 128) && (buff->at(j) != 127))
                   cerr << buff->at(j);
                else cerr << ".";
             }
          }
          first = false;
          cerr << endl;
       }
       cerr << endl << endl;
       screenMtx.unlock();
    }
    
           
    void Wh::printHelp(void) const noexcept(true){
          screenMtx.lock();
          cerr << "\nCommands:\n--------\n - Create thread:\n"
               << "     job <target_ip> <type> <code> <pause>\n"
               << " - Scan mode:\n     scan <target_ip> <pause>\n"
               << " - Reset IP header to the default values:\n     reset\n" 
               << " - List thread:\n     list\n - Kill thread:\n "
               << "    kill <id>\n - Exit and terminate all the "
               << " threads:\n     exit\n - Set environment:\n     set <var> <value>\n"
               << "     set payload <option> <on/off>\n"
               << " - Wait all the threads complete the tasks and exit:\n"
               << "    wexit\n" 
               << "- List all env variables:\n     set all\n"
               << "Interface List:\n--------------\n" << endl;
          for(auto i = ifList.cbegin(); i != ifList.cend(); ++i)
               cerr << "  " << *i << endl;
          cerr << endl;
          screenMtx.unlock();
    }
    
    void Wh::printStatus(void) const noexcept(true){
           char str[INET_ADDRSTRLEN];
    
           screenMtx.lock();
           cerr << "\nField\t\tDefault\t\tCurrent\t\tNotes\n"
                << "------------------------------------------------------------------------------------"
                << "\niface\t\t"   << "none"             << "\t\t" << env.iface 
                << "\t\thelp cmd to list iface options"
                << "\nheaderlen\t" << DEFHDRLEN          << "\t\t" << env.ip->ip_hl  
                << "\nipversion\t" << IPVERSION          << "\t\t" << env.ip->ip_v   
                << "\ntos\t\t";
                     DEFTOS == (0) ? cerr << "0x0" : cerr  << hex << showbase << DEFTOS;
                     env.ip->ip_tos == 0 ? cerr << "\t\t0x0" : cerr << "\t\t" << hex << showbase 
                     << int(env.ip->ip_tos);
           cerr << "\nfragmoff\t";
                     DEFFRAGOFF == (0) ? cerr << "0x0" : cerr << hex << showbase << DEFFRAGOFF;
                     env.ip->ip_off == 0 ? cerr << "\t\t0x0" : cerr << "\t\t" << hex << showbase
                     << env.ip->ip_off;
           cerr << "\nttl\t\t"     << dec << int(MAXTTL) << "\t\t" << dec << int(env.ip->ip_ttl) 
                << "\ntransp\t\t"  << int(DEFTRASPICMP)  << "\t\t" << int(env.ip->ip_p);
           cerr << "\nchecksum\t";
                     DEFCHKSUM == (0)  ? cerr << "0x0" : cerr << hex << showbase << DEFCHKSUM;
                     env.ip->ip_sum == 0 ? cerr << "\t\t0x0" : 
                     cerr << "\t\t" << hex << showbase << env.ip->ip_sum;
           cerr << "\nscanmode\t" << "valids\t\t" << scanModesDescr.at(env.scanmode) 
                << "\t\tall/alltype/allcode/valids"
                << "\nsrcaddr\t\t" << "iface addr.\t" 
                << inet_ntop(AF_INET, &(env.ip->ip_src.s_addr), str, INET_ADDRSTRLEN) 
                << "\nprint   \t"  << "print incoming\n\t\tdata" << "\t\t" 
                << (env.printIncoming ? "on" : "off") << "\t\ton/off" 
                << "\ndebug   \t"  << "off" << "\t\t" 
                << (env.debug ? "on" : "off") << "\t\tprint debug info - on/off" 
                << "\nmaxscanpks\t" << MAXSCANPACKETS << "\t\t" << env.maxPktSent  
                << "\nmaxpcksnt\t" << MAXSNDPKTSIZE << "\t\t" << env.maxPktSize  
                << "\nthrdtimeo\t" << "0\t\t" << env.thTimeo << "\t\tsender timeo - seconds" 
                << "\npayload invlen\t" << "on\t\t" 
                << (env.payload[INVCHKSPLD]   ? "on" : "off") << "\t\tsend invalid pl checksum - on/off" 
                << "\npayload null\t" << "on\t\t" 
                << (env.payload[NOPLD]       ? "on" : "off") << "\t\tsend empty pl - on/off" 
                << "\npayload std\t"  << "on\t\t" 
                << (env.payload[STDPLD]      ? "on" : "off") << "\t\tsend standard pl size, if exists - on/off" 
                << "\npayload huge\t" << "on\t\t" 
                << (env.payload[MAXPLD]      ? "on" : "off") << "\t\tsend max pl length - ton/off"
                << "\n\n";
           screenMtx.unlock();
    }

    void Wh::resetIpHdr(void) noexcept(false){
         try{
             if(env.ip == nullptr) env.ip   = new Ip; 
             confMtx.lock();
             env.ip->ip_hl    = DEFHDRLEN;   env.ip->ip_v    = IPVERSION;   env.ip->ip_tos   = DEFTOS;
             env.ip->ip_off   = DEFFRAGOFF;  env.ip->ip_ttl  = MAXTTL;      env.ip->ip_p     = DEFTRASPICMP;   
             env.ip->ip_sum   = DEFCHKSUM;     
             env.thTimeo      = 0;           env.maxPktSent  = MAXSCANPACKETS;

             getLocalIp();

             env.ip->ip_src.s_addr      =  reinterpret_cast<Sockaddr_in *>(&env.ifr.ifr_addr)->sin_addr.s_addr;

             confMtx.unlock();
         }catch(const bad_alloc& ex){
             throw WhException(string("resetIpHdr: ") + ex.what());
         }catch(const WhException& ex){
             throw WhException(string("resetIpHdr: ") + ex.what());
         }catch(...){
             throw WhException("resetIpHdr: unhandled exception.");
         }
    }
    
    void Wh::getLocalIp(void) noexcept(false){
         int fd = socket(AF_INET, SOCK_DGRAM, 0);
         if(fd == -1) 
             throw WhException("getLocalIp: Error opening socket.");
     
         env.ifr.ifr_addr.sa_family = AF_INET;
         strncpy(env.ifr.ifr_name, env.iface.c_str(), IFNAMSIZ-1); 
     
         if(ioctl(fd, SIOCGIFADDR, &env.ifr) == -1)
             throw WhException("getLocalIp: Error setting socket fd.");
     
         close(fd);
    }
    
    uint16_t Wh::checksum(void *buff, size_t len) const noexcept(true){	
        uint16_t        odd_byte   =  0,
                        *buffer    =  static_cast<uint16_t*>(buff);
        uint32_t        sum        =  0;
    
        while(len > 1){
            sum += *buffer++;
            len -= 2;
        }

        if( len == 1 ){
            *(reinterpret_cast<uint8_t*>(&odd_byte)) = *(reinterpret_cast<uint8_t*>(buffer));
            sum += odd_byte;
        }
    
        sum =  ( sum >> 16 ) + ( sum & 0xffff ); 
        sum += ( sum >> 16 );                   
        return static_cast<uint16_t>(~sum);
    }
    
    inline bool Wh::sendpk(const int fd, const uint8_t* buff, const size_t bufflen, 
                           const sockaddr* sin, useconds_t pause) const noexcept(true){
        const char  header[]  = "Packet Sent Dump: ";
        if(pause > 0) usleep(pause);
        if(env.debug) trace(header, buff, bufflen, 0, 0);

        if(sendto(fd, buff, bufflen, 0, sin, sizeof(struct sockaddr_in)) == -1){
                if(env.debug) printPromptErr(string("Socket Send Error: ") + strerror(errno) + 
                                            " LEN: " + to_string(sizeof(Ip) + sizeof(Icmp)));
                return false;
        }
        return true;
    }

    int  Wh::openRSocket(Env& cenv) const noexcept(false){

        errno              = 0;
        int sockFd         = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(sockFd == -1){
            printPromptErr(string("Socket Creation Error: ") + strerror(errno));
            throw WhException(string("openRSocket: Socket Creation Error: ") + 
                                     strerror(errno));
        }
            
        #ifdef LINUX_OS 
            #ifdef __GNUC__
            #pragma GCC diagnostic push
            #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
            #endif

            cenv.ifr = {};
            memcpy(cenv.ifr.ifr_name, cenv.iface.c_str(), sizeof(cenv.ifr.ifr_name));
            if(setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE, 
               reinterpret_cast<void *>(&cenv.ifr), sizeof(cenv.ifr)) == -1){

            #ifdef __GNUC__
            #pragma GCC diagnostic pop
            #endif
        #else
            int   recvifOn       = 1;
            static_cast<void>(cenv);
            if(setsockopt(sockFd, IPPROTO_IP, IP_RECVIF, &recvifOn, sizeof(recvifOn)) == -1){ 
        #endif
                 close(sockFd);
                 printPromptErr("Socket Conf. Error (iface binding)");
                 throw WhException("openRSocket: Socket Conf. Error (iface binding)");
             }
            
	int hinclOn        = 1;
        if(setsockopt(sockFd, IPPROTO_IP, IP_HDRINCL, &hinclOn, sizeof(hinclOn)) == -1){
               printPromptErr("Socket Conf. Error (IP_HDRINCL)");
               throw WhException("openRSocket: Socket Conf. Error (IP_HDRINCL)");
        }

	int broadOn        = 1;
        if (setsockopt (sockFd, SOL_SOCKET, SO_BROADCAST, &broadOn, sizeof (broadOn)) == -1){
               printPromptErr("Socket Conf. Error (SO_BROADCAST)");
               throw WhException("openRSocket: Socket Conf. Error (IP_HDRINCL)");
        }  

        return  sockFd;
    }

    string Wh::getStatus(JOBTYPE type, Env& cenv) const noexcept(false){
         try{
              return string(" --> iface: ")     + cenv.iface    + " srcaddr: " + inet_ntoa(cenv.ip->ip_src) +
                     " dstaddr: "               + cenv.params[1]+ 
                     (type == SCAN ? " icmptype: scan" :
                                     " icmptype: " + to_string(cenv.icmp->icmp_type)   + 
                                     " icmpcode: " + to_string(cenv.icmp->icmp_code) ) +
                     " maxpcks: " + to_string(cenv.maxPktSent) + " thrdtmeo: " + to_string(cenv.thTimeo)    +
                     " hdrlen: "  + to_string(cenv.ip->ip_hl)  + " ipver: "    + to_string(cenv.ip->ip_v)   + 
                     " tos: "     + to_string(cenv.ip->ip_tos) + " frgoff: "   + to_string(cenv.ip->ip_off) + 
                     " ttl: "     + to_string(cenv.ip->ip_ttl) + " transp: "   + to_string(cenv.ip->ip_p)   + 
                     " chksum: "  + to_string(cenv.ip->ip_sum);
          }catch(...){
               printPromptErr("Error creating status string.");
               throw WhException("getStatus: Error creating status string.");
	  }
    }

    void Wh::addScanThread(void) noexcept(false){
       try{ 
           countMtx.lock();
           unsigned long        id       = nextThread;
           get<RUN>(threadsList[id])     = true;
           countMtx.unlock();
           
           confMtx.lock(); 
           try{
               get<THREAD>(threadsList[id])  = 
                   new thread([&](unsigned long idcpy, Env cenv){ 
                      if(cenv.params[1].empty() || cenv.params[2].empty()){
                          printPromptErr("Wrong Parameters (dest, pause)."); 
                          goto SYNTERR;
                      }
                      printPromptErr("New scan thread:\nDestination: \n" + env.params[1] + "\nType: scan\n");

                      try{
                           vector<uint8_t>    response(MAXRCVPKTSIZE);
                           Sockaddr_in        sin,
                                              sout;
                           fd_set             readfd, 
                                              writefd;
                           socklen_t          inLen;
                           string             header   = "addScanThread: ";
           
                           cenv.setThreadEnv(&sin, false);
                           get<DESCR>(threadsList[idcpy]) = getStatus(SCAN, cenv);
           
                           int                tmpCnv   = stoi(cenv.params[2]);
                           useconds_t         pause    = tmpCnv >= 0 ? static_cast<unsigned int>(tmpCnv) : 0U;  
                           int sockFd                  = openRSocket(cenv);
           
                           for(const auto& i : (cenv.scanmode == ALL || cenv.scanmode == ALLTYPE) ? 
                                                icmpTypeFull : icmpType){
                                cenv.icmp->icmp_type  = i.first;
                                
                                uint8_t  codeMin,
                                         codeMax;
           
                                if(cenv.scanmode == ALL || cenv.scanmode == ALLCODE){
                                    codeMin = 0;
                                    codeMax = 255;
                                }else{ 
                                    codeMin = get<CODEMIN>(i.second) != 255 ? get<CODEMIN>(i.second) : 0;
                                    codeMax = get<CODEMIN>(i.second) != 255 ? get<CODEMAX>(i.second) : 0;
                                }
           
                                for(uint8_t c = codeMin; c <= codeMax; c++){
                                    cenv.icmp->icmp_code   = c;
                                    bool      stdPld       = icmpType.find(cenv.icmp->icmp_type) != icmpType.end() 
                                                             ? true : false;
                                    uint16_t  stdSize      = sizeof(Ip) + 
                                                                 (icmpType.find(cenv.icmp->icmp_type) != 
                                                                  icmpType.end() ?
                                                                  get<CODEPSIZE>(icmpType.at(cenv.icmp->icmp_type)) : 
                                                                 ICMP_MINLEN);

                                    uint16_t  stdChks      = checksum(cenv.icmp, stdSize - sizeof(Ip)),
                                              zeroSize     = sizeof(Ip) + ICMP_MINLEN,
                                              minChks      = checksum(cenv.icmp, ICMP_MINLEN), 
                                              maxSize      = env.maxPktSize,
                                              maxChks      = checksum(cenv.icmp, env.maxPktSize - sizeof(Ip));
                                    uint32_t  count        = 0;
                   
                                    uint32_t maxPckSent    = MAXSCANPACKETS; 
                                    while(get<RUN>(threadsList[idcpy]) && 
                                                   count <= (cenv.maxPktSent > 0 ? 
                                                             cenv.maxPktSent : maxPckSent)){ 
           
                                         FD_ZERO(&readfd);          FD_ZERO(&writefd);
                                         FD_SET(sockFd,  &readfd);  FD_SET(sockFd,  &writefd);

                                         errno             = 0; 
                                         if(select(sockFd+1, &readfd, &writefd, nullptr, nullptr) > 0 && errno == 0){
                                             if(FD_ISSET(sockFd, &writefd)){
                                                 if(cenv.payload[NOPLD]){
                                                     cenv.ip->ip_len          = zeroSize;
                                                     cenv.icmp->icmp_cksum    = minChks;
                                                     sendpk(sockFd, cenv.packet.data(), zeroSize,
                                                               reinterpret_cast<sockaddr*>(&sin), pause);
                                                     count++;
                                                 }

                                                 if(cenv.payload[INVCHKSPLD]){
                                                     cenv.ip->ip_len          = zeroSize;
                                                     cenv.icmp->icmp_cksum    = stdChks;
                                                     sendpk(sockFd, cenv.packet.data(), zeroSize,
                                                               reinterpret_cast<sockaddr*>(&sin), pause);
                                                     count++;
                                                 }
           
                                                 if(cenv.payload[STDPLD] && stdPld){
                                                     cenv.ip->ip_len          = stdSize;
                                                     cenv.icmp->icmp_cksum    = stdChks;
                                                     sendpk(sockFd, cenv.packet.data(), stdSize,
                                                               reinterpret_cast<sockaddr*>(&sin), pause);
                                                     count++;
                                                 }
           
                                                 if(cenv.payload[MAXPLD]){
                                                     cenv.ip->ip_len          = maxSize;
                                                     cenv.icmp->icmp_cksum    = maxChks;
                                                     sendpk(sockFd, cenv.packet.data(), maxSize,
                                                               reinterpret_cast<sockaddr*>(&sin), pause);
                                                     count++;
                                                 }
                                             }
                                             if(FD_ISSET(sockFd, &readfd)){
                                                 ssize_t res = recvfrom(sockFd, response.data(), MAXRCVPKTSIZE, 0, 
                                                          reinterpret_cast<sockaddr*>(&sout), &inLen); 
                                                 if(cenv.printIncoming){
                                                    if(res > 0) trace(header, &response, 0, 0, 
                                                                      static_cast<size_t>(res));
                                                    else        printPromptErr("addScanThread: Reading error.");
                                                 }
                                             }
                                         }
                                    }
                                }
                            }
                            close(sockFd);
                            printPromptErr(string("Thread ") + to_string(idcpy) + " exits.", true);
                     }catch(...){
                          printPromptErr("Thread of type job exits for unhandled error.", true);
                     }
                     SYNTERR:
                     threadsList.erase(idcpy); 
             },id, env);
                 get<THREAD>(threadsList[id])->detach();
           
           }catch(...){
                 confMtx.unlock(); 
                 countMtx.lock();
                 nextThread--;
                 countMtx.unlock();
                 printPromptErr("Error creating thread.");
                 throw;
           }
    
           confMtx.unlock(); 
           countMtx.lock();
           nextThread++;
           countMtx.unlock();
       }catch(const bad_alloc& ex){
            throw WhException(string("addScanThread: ") + ex.what());
       }catch(...){
            throw WhException("addScanThread: Error creating the thread.");
       }
    }
    
    void  Wh::waitExit(void) noexcept(false){
       try{
           countMtx.lock();
           unsigned long      id        = nextThread;
           get<RUN>(threadsList[id])    = true;
           get<DESCR>(threadsList[id])  = " --> wait-to-exit thread";
           countMtx.unlock();
        
           shutDown                     = SHACT;
        
           try{
               get<THREAD>(threadsList[id])  = 
                   new thread([&](){ 
                       try{
                           while(shutDown == SHACT){
                               if(threadsList.size() == 1)
                                   shutDown    = SHEXPIRED;
                           } 
                       }catch(...){
                           printPromptErr("Thread of type waitExit exits for unhandled error.", true);
                       }
                   });
                   get<THREAD>(threadsList[id])->detach();
           }catch(...){
                 countMtx.lock();
                 nextThread--;
                 countMtx.unlock();
                 printPromptErr("Error creating checker thread.");
                 throw;
           }
        
           countMtx.lock();
           nextThread++;
           countMtx.unlock();
       }catch(const bad_alloc& ex){
            throw WhException(string("waitExit: ") + ex.what());
       }catch(...){
            throw WhException("waitExit: Unhandled exception creating the thread.");
       }
    }
    
    void  Wh::addJobThread(void) noexcept(false){
       try{
           countMtx.lock();
           unsigned long        id        = nextThread;
           get<RUN>(threadsList[id])      = true;
           countMtx.unlock();

           confMtx.lock(); 
           try{
               get<THREAD>(threadsList[id])  = 
                   new thread([&](unsigned long idcpy, Env cenv){
                       if(cenv.params[1].empty() || cenv.params[2].empty() || 
                          cenv.params[3].empty() || cenv.params[4].empty()){
                              printPromptErr("Wrong Parameters (dest,icmp type and code, pause, required)."); 
                              goto SYNTAXERR;
                       }
                       printPromptErr("New job thread:\nDestination: \n" + cenv.params[1] + "\nType: " +
                                      cenv.params[2] + "\nCode: " + cenv.params[3]);

                       try{
                           vector<uint8_t>    response(MAXRCVPKTSIZE);
                           Sockaddr_in        sin,
                                              sout;
                           fd_set             readfd,
                                              writefd;
                           socklen_t          inLen;
                           string             header   = "jobIcmp: ";
                       
                           cenv.setThreadEnv(&sin, true);
                           get<DESCR>(threadsList[idcpy]) = getStatus(STD, cenv);
            
                           int                tmpCnv  = stoi(cenv.params[4]);
                           useconds_t         pause   = tmpCnv >= 0 ? static_cast<unsigned int>(tmpCnv) : 0U;  
                           int sockFd                 = openRSocket(cenv);
            
                           if( cenv.thTimeo > 0){
                               thread* timeoTh = new thread([&](unsigned long idxTimeo){ 
                                                     try{
                                                         unsigned long target = idxTimeo;
                                                         this_thread::sleep_for(chrono::seconds(idxTimeo));
                                                         get<RUN>(threadsList[target]) = false;
                                                     }catch(...){
                                                         printPromptErr("Thread of type timer exits for "
                                                                        "unhandled error.", true);
                                                     }
                                                     return 0; 
                                                 }, (cenv.thTimeo));
                               timeoTh->detach();
                           }
            
                           bool      stdPld        = icmpType.find(cenv.icmp->icmp_type) != icmpType.end() 
                                                     ? true : false;
                           uint16_t  stdSize       = sizeof(Ip) + 
                                                    (icmpType.find(cenv.icmp->icmp_type) != icmpType.end() ?
                                                     get<CODEPSIZE>(icmpType.at(cenv.icmp->icmp_type)) : 
                                                     ICMP_MINLEN);

                           uint16_t  stdChks       = checksum(cenv.icmp, stdSize - sizeof(Ip)),
                                     zeroSize      = sizeof(Ip) + ICMP_MINLEN,
                                     minChks       = checksum(cenv.icmp, ICMP_MINLEN), 
                                     maxSize       = env.maxPktSize,
                                     maxChks       = checksum(cenv.icmp, env.maxPktSize - sizeof(Ip));
                           uint32_t  count         = 0;

                           while(get<RUN>(threadsList[idcpy]) && 
                                          count <= (cenv.maxPktSent > 0 ? 
                                                   cenv.maxPktSent : 0)){ 
            
                                FD_ZERO(&readfd);          FD_ZERO(&writefd);
                                FD_SET(sockFd,  &readfd);  FD_SET(sockFd,  &writefd);
                                   
                                if(select(sockFd+1, &readfd, &writefd, nullptr, nullptr) > 0){
                                    if(FD_ISSET(sockFd, &writefd)){
                                        if(cenv.payload[NOPLD]){        
                                            cenv.ip->ip_len          = zeroSize;
                                            cenv.icmp->icmp_cksum    = minChks;
                                            sendpk(sockFd, cenv.packet.data(), zeroSize,
                                                      reinterpret_cast<sockaddr*>(&sin), pause);
                                            count++;
                                        }
            
                                        if(cenv.payload[STDPLD] && stdPld){  
                                            cenv.ip->ip_len          = stdSize;
                                            cenv.icmp->icmp_cksum    = stdChks;
                                            sendpk(sockFd, cenv.packet.data(), stdSize,
                                                      reinterpret_cast<sockaddr*>(&sin), pause);
                                            count++;
                                        }
            
                                        if(cenv.payload[MAXPLD] ){     
                                            cenv.ip->ip_len          = maxSize;
                                            cenv.icmp->icmp_cksum    = maxChks;
                                            sendpk(sockFd, cenv.packet.data(), maxSize,
                                                      reinterpret_cast<sockaddr*>(&sin), pause);
                                            count++;
                                        }
                                    }
                                    if(FD_ISSET(sockFd, &readfd)){
                                        ssize_t res = recvfrom(sockFd, response.data(), MAXRCVPKTSIZE, 0, 
                                                 reinterpret_cast<sockaddr*>(&sout), &inLen);
                                        if(cenv.printIncoming){
                                            if(res > 0) trace(header, &response, 0, 0, static_cast<size_t>(res));
                                            else        printPromptErr("addScanThread: Reading error.");
                                        }
                                    }
                                }
                    }
            
                    close(sockFd);
                    printPromptErr(string("Thread ") + to_string(idcpy) + " exits.", true); 
               }catch(...){
                   printPromptErr("Thread of type job exits for unhandled error.", true);
               }

               SYNTAXERR:
               threadsList.erase(idcpy);
           },id, env);
               get<THREAD>(threadsList[id])->detach();
         
           }catch(...){
                 confMtx.unlock(); 
                 countMtx.lock();
                 nextThread--;
                 countMtx.unlock();
                 printPromptErr("Error creating thread.");
                 throw;
           }
        
           confMtx.unlock(); 
           countMtx.lock();
           nextThread++;
           countMtx.unlock();
       }catch(const bad_alloc& ex){
            throw WhException(string("addJobThread: ") + ex.what());
       }catch(...){
            throw WhException("addJobThread: Error creating the thread.");
       }
    }
   
    void Wh::killThread(void) noexcept(true){
       confMtx.lock(); 
       try{
           unsigned long id     = stoul(env.params[1]);
           if(env.params[1].empty() || threadsList.find(id) == threadsList.end()){
               printPromptErr("Wrong Parameter."); 
           }else{
               get<RUN>(threadsList[id]) = false;
               threadsList.erase(id);
               printPromptErr(string("Killed thread no: ") + env.params[1]); 
           }
       confMtx.unlock(); 
       }catch(const invalid_argument& ex){
               printPromptErr(string("Wrong Parameter - Invalid argument: ")  +  
                                     ex.what());
       }
    }
    
    int Wh::setDebugMode(string& mode) noexcept(true){
        try{
            env.debug = opts.at(mode);
        }catch(const out_of_range& e){
            static_cast<void>(e);
            printPromptErr(string("Invalid Command: ") + env.params[0]);
        }
        return 0;
    }
    
    int Wh::setPayloadMode(string& mode, PAYLOAD type) noexcept(true){
        try{
            env.payload[type] = opts.at(mode);
        }catch(const out_of_range& e){
            static_cast<void>(e);
            printPromptErr(string("Invalid Command: ") + env.params[0]);
        }
        return 0;
    }
    
    int Wh::setPrintMode(string& mode) noexcept(true){
        try{
            env.printIncoming = opts.at(mode);
        }catch(const out_of_range& e){
            static_cast<void>(e);
            printPromptErr(string("Invalid Command: ") + env.params[0]);
        }
        return 0;
    }
    
    int Wh::setScanMode(string& mode) noexcept(true){
        try{
            env.printIncoming = opts.at(mode);
        }catch(const out_of_range& e){
            static_cast<void>(e);
            printPromptErr(string("Invalid Command: ") + env.params[0]);
        }
        return 0;
    }
    
    int Wh::parseCommand(CMDTYPE type) const noexcept(false){
         int ret           = 0;
         try{
             switch(type){
                 case SRVCMD:
                     ret   =  commands.at(env.params[0])();
                 break;
                 case ENVCMD:
                     ret   =  setCmds.at(env.params[1])();
                 break;
                 case PLOADCMD:
                     ret   =  ploadCmds.at(env.params[2])();
             }
         }catch(const out_of_range& e){
             static_cast<void>(e);
             printPromptErr(string("Invalid Command: ") + env.params[0]);
             ret           =  0;
         }catch(const WhException& ex){
             throw WhException(string("parseCommand: ") + ex.what());
         }catch(...){
             throw WhException("parseCommand: unhandled exception.");
         }
         return ret;
    }
    
    void Wh::shellLoop(void){
         int            stdIn     = -1;
         env.params[0].clear();
    
         while(!isatty(STDIN_FILENO)){
             char       curr;
             ssize_t    status    = read(STDIN_FILENO, &curr, 1);
    
             switch(status){
  	      case  1:
  	           if(curr != '\n' && curr != ' ' && currParam < MAXPARAMS){
                        env.params[currParam].push_back(curr);
                   }else if(curr == ' '){
                        currParam++;
                        env.params[currParam].clear();
                   }
              break;
              case  0:
                   close(STDIN_FILENO);
                   stdIn = open("/dev/tty", O_RDONLY);
                   if(stdIn != 0) {
                       printPromptErr("Error reopening stdin.");
                       throw WhException("shellLoop: Error reopening stdin.");
                   }
                   env.params[0].clear();
              continue;
              default:
                   printPromptErr("Error reading stdin.");
                   throw WhException("shellLoop: Error reading stdin.");
             }
    
             if(curr == '\n'){
                 if(currParam >= MAXPARAMS){
                    printPromptErr("Invalid params number"); 
                 }else if(parseCommand(SRVCMD) == 1)
                    break;
                 env.params[0].clear();
                 currParam    =   0;
             }
         }
      
         stage = WAIT; 
         while(shutDown == SHACT){
            sleep(1);
         }
    
         stage = INTERACTIVE;
         while(shutDown != SHEXPIRED){
            bool   valid  = true;
            char*  line   = readline(prompt);
            if(line == nullptr) break;
            env.params[0].clear();
            for(size_t i=0; i < strlen(line); ++i){
  	        if(line[i] != ' ' && currParam < MAXPARAMS){
                     env.params[currParam].push_back(line[i]);
                }else if(line[i] == ' '){
                     currParam++;
                     env.params[currParam].clear();
                }
                if(currParam >= MAXPARAMS){
                     printPromptErr("Invalid params number");
                     valid  = false;
                     break;
                }
            }
            if(valid){
                if(parseCommand(SRVCMD) == 1)
                    break;
            }
            currParam    =   0;
            add_history(line);
            free(line);
         }
    }

    WhException::WhException(string& errString){
        errorMessage            = errString;
    }

    WhException::WhException(string&& errString){
        errorMessage            = move(errString);
    }
 
    string WhException::what() const noexcept(true){
        return errorMessage;
    }
}

