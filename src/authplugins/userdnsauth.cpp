// IP (range, subnet) auth plugin

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../RegExp.hpp"
#include "../OptionContainer.hpp"

#include <sys/types.h>
#include <syslog.h>
#include <algorithm>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>



// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;
extern int h_errno;

// DECLARATIONS

// user record struct
struct userstruct {
	String ippath;
	String user;
	int group;
};



// class name is relevant!
class userdnsauthinstance:public AuthPlugin
{
public:
	// keep credentials for the whole of a connection - IP isn't going to change.
	// not quite true - what about downstream proxy with x-forwarded-for?
	userdnsauthinstance(ConfigVar &definition):AuthPlugin(definition)
	{
		if (!o.use_xforwardedfor)
			is_connection_based = true;
	};

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);

	int init(void* args);
	int quit();
private:
    String basedomain;
	userstruct userst;
	bool getdnstxt(String &ippath);
	String dns_error(int herror); 
	bool inAuthByPassLists(HTTPHeader &h);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *userdnsauthcreate(ConfigVar & definition)
{
	return new userdnsauthinstance(definition);
}

// end of Class factory

// 

// Standard plugin funcs
//
//

// plugin quit - clear IP, subnet & range lists
int userdnsauthinstance::quit() {
	return 0;
}

// plugin init - read in vars
int userdnsauthinstance::init(void* args) {
	basedomain = cv["basedomain"];
	if (basedomain.length() < 1) {
              if (!is_daemonised)
                        std::cerr << "No basedomain defined in DNS auth plugin config" << std::endl;
                syslog(LOG_ERR, "No basedomain defined in DNS auth plugin config");
                return -1;
        }
	
#ifdef DGDEBUG
		std::cout << "basedomain is " << basedomain  << std::endl;
#endif
	return 0;
}

// DNS-AUTH filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int userdnsauthinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, /*int &fg,*/ std::string &string)
{
	String p1, p2, ippath;
			
	p1 = peercon.getPeerIP();

	if (o.use_xforwardedfor) {
		// grab the X-Forwarded-For IP if available
		p2 = h.getXForwardedForIP();
		if ( p2.length() > 0 ) {
			ippath = p1 + "-" + p2;
		}
		else {
			ippath = p1;
		}
	}
	else {
		ippath = p1;
	}

#ifdef DGDEBUG
		std::cout << "IPPath is " << ippath  << std::endl;
#endif


// change '.' to '-'
	ippath.swapChar('.', '-');
#ifdef DGDEBUG
		std::cout << "IPPath is " << ippath  << std::endl;
#endif
	if ( getdnstxt(ippath) ) {
		string = userst.user;
		return DGAUTH_OK;
	} 
	else {
		  return DGAUTH_NOMATCH;
	}
}

bool userdnsauthinstance::getdnstxt(String &ippath)
{
// get info from DNS
	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} response;
	int responseLen;

	ns_msg handle;  /* handle for response message */
	responseLen = res_querydomain(ippath.c_str(), basedomain.c_str(), ns_c_in, ns_t_txt, (u_char *)&response, sizeof(response));
	if (responseLen < 0) {
#ifdef DGDEBUG
		std::cout << "DNS query returned error " << dns_error(h_errno) << std::endl;
#endif
	return false;
	}
	if (ns_initparse(response.buf, responseLen, &handle) < 0) {
#ifdef DGDEBUG
		std::cout << "ns_initparse returned error " << strerror(errno) << std::endl;
#endif
		return false;
	}

	int rrnum;	/* resource record number */
	ns_rr rr;	/* expanded resource record */
	u_char *cp;
	char ans[MAXDNAME];

	int i = ns_msg_count(handle, ns_s_an);
	if ( i > 0 ) {
		if (ns_parserr(&handle, ns_s_an, 0, &rr)) {
#ifdef DGDEBUG
			std::cout << "ns_paserr returned error " << strerror(errno) << std::endl;
#endif
			return false;
		}
		else {
			if (ns_rr_type(rr) == ns_t_txt) {
#ifdef DGDEBUG
		std::cout << "ns_rr_rdlen returned " << ns_rr_rdlen(rr)  << std::endl;
#endif
		u_char *k = (u_char *)ns_rr_rdata(rr);
		char p[400];
		unsigned int j = 0;
		for (unsigned int j1 = 1; j1 < ns_rr_rdlen(rr); j1++) {
			p[j++] = k[j1];
		}
		p[j] = (char)NULL; 
#ifdef DGDEBUG
		std::cout << "ns_rr_data returned " << p << std::endl;
#endif
		String dnstxt(p);
		userst.user = dnstxt;
		return true;
			}
		}
	}
	return true;
}
 
String userdnsauthinstance::dns_error(int herror) {

	String s;

	switch(herror) {
		case HOST_NOT_FOUND:
		  s = "HOST_NOT_FOUND";
		  break;
		case TRY_AGAIN:
		  s = "TRY_AGAIN - DNS server failure";
		  break;
		case NO_DATA:
		  s = "NO_DATA - unexpected DNS error";
		  break;
		default:
		  String S2(herror);
		  s = "DNS - Unexpected error number " + S2 ;
		  break;
	}
	return s;
}


bool userdnsauthinstance::inAuthByPassLists(HTTPHeader &h) {
 	String url = h.url();
	String urld = h.decode(url);
	url.removePTP();
	if (url.contains("/")) {
		url = url.before("/");
	}
	bool is_ip = (*o.fg[0]).isIPHostname(url);
	bool is_ssl = h.requestType() == "CONNECT";

	if ((*o.fg[0]).inAuthExceptionSiteList(urld, true, is_ip, is_ssl)) {
//						exceptioncat = (*o.lm.l[(*o.fg[filtergroup]).exception_site_list]).lastcategory.toCharArray();
	return true;
	}
	else if ((*o.fg[0]).inAuthExceptionURLList(urld, true, is_ip, is_ssl)) {
//					exceptioncat = (*o.lm.l[(*o.fg[filtergroup]).exception_url_list]).lastcategory.toCharArray();
	return true;
	}
	return false;
}
