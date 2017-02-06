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

#include <unistd.h>
#include <stdlib.h>

#include <string>
#include <iostream>

#include <wh.hpp>

using namespace std;
using namespace wh;


#ifdef __clang__
  void printInfo(char* cmd) __attribute__((noreturn));
#else
  [[ noreturn ]]
  void printInfo(char* cmd);
#endif

int main(int argc, char** argv){
   const char  flags[]      = "hi:";
   int         c;
   string      iface;
   bool        initIface    = false;

   try{

       #ifdef LINUX_OS
            Capability cpb(true);
            cpb.reducePriv("cap_net_raw+ep");
            cpb.getCredential();
            cpb.printStatus();
       #endif

       opterr = 0;
       while ((c = getopt(argc, argv, flags)) != -1){
          switch (c){
             case 'i':
                iface = optarg;
                initIface = true;
             break;
             case 'h':
                printInfo(argv[0]);
                #ifdef __clang__
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Wimplicit-fallthrough"
                #endif
             default:
                cerr << "Invalid parameter." << endl << endl;
                printInfo(argv[0]);
                #ifdef __clang__
                #pragma clang diagnostic pop
                #endif
          }
       }
    
       if(!initIface) printInfo(argv[0]);
    
       Wh wh(iface);
       wh.shellLoop();

   }catch(const WhException& ex){
        cerr << "Error: " << ex.what() << endl;
   #ifdef LINUX_OS
       }catch(const CapabilityException& ex){
            cerr << "Error: " << ex.what() << endl;
   #endif
   }catch(...){
        cerr << "Unhandled error !" << endl;
   }

   return 0;
}

void printInfo(char* cmd){
      cerr << cmd << " [-i<iface>] | [-h]\n" << endl;
      cerr << " -i<iface> Specify the initial network interface;" << endl;
      cerr << " -h  print this synopsis;" << endl;
      exit(EXIT_FAILURE);
}

