// Base socket class - inherit this to implement UNIX/INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include <csignal>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <syslog.h>
#include <sys/select.h>

#ifdef DGDEBUG
#include <iostream>
#endif

#include "BaseSocket.hpp"

// GLOBALS
extern bool reloadconfig;


// DEFINITIONS

#define dgtimercmp(a, b, cmp) \
	(((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec cmp (b)->tv_usec) : ((a)->tv_sec cmp (b)->tv_sec))

#define dgtimersub(a, b, result) \
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
	if ((result)->tv_usec < 0) { \
		(result)->tv_sec--; \
		(result)->tv_usec += 1000000; \
	}


// IMPLEMENTATION

// a wrapper for select so that it auto-restarts after an EINTR.
// can be instructed to watch out for signal triggered config reloads.
int selectEINTR(int numfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval *timeout, bool honour_reloadconfig)
{
	int rc;
	errno = 0;
	// Fix for OSes that do not explicitly modify select()'s timeout value
	// from Soner Tari <list@kulustur.org> (namely OpenBSD)
	// Modified to use custom code in preference to timersub/timercmp etc.
	// to avoid that particular portability nightmare.
	timeval entrytime;
	timeval exittime;
	timeval elapsedtime;
	timeval timeoutcopy;
	while (true) {  // using the while as a restart point with continue
		if (timeout != NULL) {
			gettimeofday(&entrytime, NULL);
			timeoutcopy = *timeout;
			rc = select(numfds, readfds, writefds, exceptfds, &timeoutcopy);
			// explicitly modify the timeout if the OS hasn't done this for us
			if (timeoutcopy.tv_sec == timeout->tv_sec && timeoutcopy.tv_usec == timeout->tv_usec) {
				gettimeofday(&exittime, NULL);
				// calculate time spent sleeping this iteration
				dgtimersub(&exittime, &entrytime, &elapsedtime);
				// did we wait longer than/as long as was left?
				if (!dgtimercmp(timeout, &elapsedtime, <)) {
					// no - reduce the amount that is left
					dgtimersub(timeout, &elapsedtime, timeout);
				} else {
					// yes - we've timed out, so exit
					timeout->tv_sec = timeout->tv_usec = 0;
					break;
				}
			} else {
				// if the OS has modified the timeout for us,
				// propogate the change back to the caller
				*timeout = timeoutcopy;
			}
		} else
			rc = select(numfds, readfds, writefds, exceptfds, NULL);
		if (rc < 0) {
			if (errno == EINTR && (honour_reloadconfig? !reloadconfig : true)) {
				continue;  // was interupted by a signal so restart
			}
		}
		break;  // end the while
	}
	return rc;  // return status
}

// This class contains client and server socket init and handling
// code as well as functions for testing and working with the socket FDs.

// constructor - override this if desired to create an actual socket at startup
BaseSocket::BaseSocket():timeout(5), sck(-1), buffstart(0), bufflen(0), firstRead(true), isTransparentSsl(false)
{}

// create socket from FD - must be overridden to clear the relevant address structs
BaseSocket::BaseSocket(int fd):timeout(5), buffstart(0), bufflen(0), firstRead(true), isTransparentSsl(false)
{
	sck = fd;
}

// destructor - close socket
BaseSocket::~BaseSocket()
{
	// close fd if socket not used
	if (sck > -1) {
		::close(sck);
	}
}

// reset - close socket & reset timeout.
// call this in derived classes' reset() method, which should also clear address structs
void BaseSocket::baseReset()
{
	if (sck > -1) {
		::close(sck);
		sck = -1;
	}
	timeout = 5;
	buffstart = 0;
	bufflen = 0;
}

// mark a socket as a listening server socket
int BaseSocket::listen(int queue)
{
	return ::listen(sck, queue);
}

// "template adaptor" for accept - basically, let G++ do the hard work of
// figuring out the type of the third parameter ;)
template <typename T>
inline int local_accept_adaptor (int (*accept_func)(int, struct sockaddr*, T),
	int sck, struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{
  return accept_func (sck, acc_adr, (T) acc_adr_length);
}

// receive an incoming connection & return FD
// call this in accept methods of derived classes, which should pass in empty sockaddr & socklen_t to be filled out
int BaseSocket::baseAccept(struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{	

	// OS X defines accept as:
	// int accept(int s, struct sockaddr *addr, int *addrlen);
	// but everyone else as:
	// int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
	// NB: except 10.4, which seems to use the more standard definition. grrr.
	return local_accept_adaptor(::accept, sck, acc_adr, acc_adr_length);
}

// return socket's FD - please use sparingly and DO NOT do manual data transfer using it
int BaseSocket::getFD()
{
	return sck;
}

// close the socket
void BaseSocket::close()
{
	if (sck > -1) {
		::close(sck);
		sck = -1;
	}
	buffstart = 0;
	bufflen = 0;
}

// set the socket-wide timeout
void BaseSocket::setTimeout(int t)
{
	timeout = t;
}

// return timeout
int BaseSocket::getTimeout()
{
	return timeout;
}

// non-blocking check to see if there is data waiting on socket
bool BaseSocket::checkForInput()
{
	if ((bufflen - buffstart) > 0)
		return true;

	fd_set fdSet;
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(sck, &fdSet);  // add fd to the set
	timeval t;  // timeval struct
	t.tv_sec = 0;
	t.tv_usec = 0;

	if (selectEINTR(sck + 1, &fdSet, NULL, NULL, &t) < 1) {
		return false;
	}

	return true;
}

// blocking check for waiting data - blocks for up to given timeout, can be told to break on signal-triggered config reloads
void BaseSocket::checkForInput(int timeout, bool honour_reloadconfig) throw(std::exception)
{
#ifdef DGDEBUG
		std::cout << "BaseSocket::checkForInput: starting for sck:" << sck << std::endl;
#endif

	if ((bufflen - buffstart) > 0)
		return;

	// blocks if socket blocking
	// until timeout
	fd_set fdSet;
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(sck, &fdSet);  // add fd to the set
	timeval t;  // timeval struct
	t.tv_sec = timeout;
	t.tv_usec = 0;
	if (selectEINTR(sck + 1, &fdSet, NULL, NULL, &t, honour_reloadconfig) < 1) {
		std::string err("select() on input: ");
		throw std::runtime_error(err + (errno ? strerror(errno) : "timeout"));
	}
}

// non-blocking check to see if a socket is ready to be written
bool BaseSocket::readyForOutput()
{
	fd_set fdSet;
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(sck, &fdSet);  // add fd to the set
	timeval t;  // timeval struct
	t.tv_sec = 0;
	t.tv_usec = 0;
	if (selectEINTR(sck + 1, NULL, &fdSet, NULL, &t) < 1) {
		return false;
	}
	return true;
}

// blocking equivalent of above, can be told to break on signal-triggered reloads
void BaseSocket::readyForOutput(int timeout, bool honour_reloadconfig) throw(std::exception)
{
	// blocks if socket blocking
	// until timeout
	fd_set fdSet;
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(sck, &fdSet);  // add fd to the set
	timeval t;  // timeval struct
	t.tv_sec = timeout;
	t.tv_usec = 0;
	if (selectEINTR(sck + 1, NULL, &fdSet, NULL, &t, honour_reloadconfig) < 1) {
		std::string err("select() on output: ");
		throw std::runtime_error(err + (errno ? strerror(errno) : "timeout"));
	}
}

std::string getSNIHostname(unsigned char* buffer, int length) {
    std::string hostname = "";
        
    int pos = 0, len = 0;
    
    // check v_major
    if (buffer[pos + 1] < 3) {
        return hostname;
    }

    len = ((buffer[pos + 3] << 8) | buffer[pos + 4]) + 5;
    if (length < len) {
        return hostname;
    }

    length = std::min(len, length); 

    if (buffer[pos + 5] != 0x1) {
        return hostname;
    }

    pos += 43; //skip to session id length

    len = buffer[pos];
    pos += len + 1; //skip past session id

    len = (buffer[pos] << 8) | buffer[pos + 1];
    pos += len + 2; //skip past cipher suites

    len = buffer[pos];
    pos += len + 1; //skip past compression methods
    
    if (pos >= length) {
        return hostname;
    }

    len = (buffer[pos] << 8) | buffer[pos + 1]; //extensions length
    pos += 2;

    while (pos + 4 <= length) {
        len = buffer[pos + 2] << 8 | buffer[pos + 3];
        if ((buffer[pos] << 8 | buffer[pos + 1]) == 0x0 && len > 0) //server_name
        {
            int listLen = (buffer[pos + 4] << 8) | buffer[pos + 5], listPos = 0;
            if (listLen > 0)
            {
                while (pos + 6 + listPos + 3 <= length)
                {
                    listLen = buffer[pos + 6 + listPos + 2];
                    if ((buffer[pos + 6 + listPos] << 8 | buffer[pos + 6 + listPos + 1]) == 0x0 && listLen > 0) //host_name
                    {
                        hostname.assign((char*)&buffer[pos + 6 + listPos + 3], listLen);
                        return hostname;
                    }

                    listPos += listLen + 3;
                }
            }

            break;
        }

        pos += len + 4;
    }

    return hostname;
}

// read a line from the socket, can be told to break on config reloads
int BaseSocket::getLine(char *buff, int size, int timeout, bool honour_reloadconfig, bool *chopped, bool *truncated) throw(std::exception)
{
    if (isTransparentSsl && forgeHeaders.size() > 0) {
        std::string header = forgeHeaders.front();
        forgeHeaders.pop();
        
        memcpy(buff, header.c_str(), header.size());
        buff[header.size() - 1] = '\0';
        if (chopped) *chopped = true;
        
        return header.size() - 1;
    }
    
	// first, return what's left from the previous buffer read, if anything
	int i = 0;
	if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
		std::cout << "data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif

		//work out the maximum size we want to read from our internal buffer
		int tocopy = size-1;
		if ((bufflen - buffstart) < tocopy)
			tocopy = bufflen - buffstart;
		
		//copy the data to output buffer (up to 8192 chars in loglines case)
		char* result = (char*)memccpy(buff, buffer + buffstart, '\n', tocopy);
		
		//if the result was < max size
		//if the result WAS null this indicates a full buffer copy
		if (result != NULL) {
			// indicate that a newline was chopped off, if desired
			if (chopped)
				*chopped = true;
			
			//make the last char a null
			*(--result) = '\0';
			buffstart += (result - buff) + 1;
			return result - buff;
		} else {
			i += tocopy;
			buffstart += tocopy;
		}
	}
	while (i < (size - 1)) {
		buffstart = 0;
		bufflen = 0;
		try {
			checkForInput(timeout, honour_reloadconfig);
			//only peek if first read so we can intecept transparent ssl connections
			bufflen = recv(sck, buffer, 1024, firstRead ? MSG_PEEK : 0);
		} catch(std::exception & e) {
			throw std::runtime_error(std::string("Can't read from socket: ") + e.what());  // on error
		}
#ifdef DGDEBUG
		std::cout << "read into buffer; bufflen: " << bufflen << std::endl;
#endif
		//if there was a socket error
		if (bufflen < 0) {
			if (errno == EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;
			}
			throw std::runtime_error(std::string("Can't read from socket: ") + strerror(errno));  // on error
		}
		//if socket closed...
		if (bufflen == 0) {
			buff[i] = '\0';  // ...terminate string & return what read
			if (truncated)
				*truncated = true;
			return i;
		}
		if (firstRead) {
			firstRead = false;
			
			//check if this is a client ssl handshake
			if (bufflen >= 6 && buffer[0] == 0x16 && buffer[5] == 0x1) { 
#ifdef DGDEBUG
				std::cout << "first packet is ssl client handshake" << std::endl;
#endif
				std::string hostname = getSNIHostname((unsigned char*)buffer, bufflen);

#ifdef ENABLE_ORIG_IP
				if (hostname == "") {
					sockaddr_in origaddr;
					socklen_t origaddrlen(sizeof(sockaddr_in));

					if (getsockopt(getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen) == 0) {
						std::string orig_dest_ip(inet_ntoa(origaddr.sin_addr));
						hostname = orig_dest_ip;
					}
				}
#endif

				if (hostname != "") {
#ifdef DGDEBUG
					std::cout << "forging headers for transparent ssl connection to " << hostname << std::endl;
#endif
					isTransparentSsl = true;

					std::string header = "CONNECT " + hostname + ":443 HTTP/1.1\r\n";

					memcpy(buff, header.c_str(), header.size());
					buff[header.size() - 1] = '\0';
					if (chopped) *chopped = true;

					forgeHeaders.push("\r\n");

					bufflen = 0;
					return header.size() - 1;
				}
			}
			
			//it wasn't a client ssl handshake or we couldn't get hostname/ip so consume the data in the socket and continue
			try {
				bufflen = recv(sck, buffer, bufflen, 0);
			} catch(std::exception & e) {
				throw std::runtime_error(std::string("Can't read from socket: ") + e.what());  // on error
			}
		}
		int tocopy = bufflen;
		if ((i + bufflen) > (size-1))
			tocopy = (size-1) - i;
		char* result = (char*)memccpy(buff+i, buffer, '\n', tocopy);
		if (result != NULL) {
			// indicate that a newline was chopped off, if desired
			if (chopped)
				*chopped = true;
			*(--result) = '\0';
			buffstart += (result - (buff+i)) + 1;
            //std::cout << "return (" << (i + (result - (buff+i))) << ") " << buff << std::endl;
			return i + (result - (buff+i));
		}
		i += tocopy;
	}
	// oh dear - buffer end reached before we found a newline
	buff[i] = '\0';
	if (truncated)
		*truncated = true;
	return i;
}

// write line to socket
void BaseSocket::writeString(const char *line) throw(std::exception)
{
	int l = strlen(line);
	if (!writeToSocket(line, l, 0, timeout)) {
		throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
	}
}

// write data to socket - throws exception on failure, can be told to break on config reloads
void BaseSocket::writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig) throw(std::exception)
{
	if (!writeToSocket(buff, len, flags, timeout, honour_reloadconfig)) {
		throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
	}
}

// write data to socket - can be told not to do an initial readyForOutput, and to break on config reloads
bool BaseSocket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
	if (isTransparentSsl) {
		//disable forging headers and discard response for transparent ssl
		isTransparentSsl = false;
		return true;
	}
    
	int actuallysent = 0;
	int sent;
	while (actuallysent < len) {
		if (check_first) {
			try {
				readyForOutput(timeout, honour_reloadconfig);  // throws exception on error or timeout
			}
			catch(std::exception & e) {
				return false;
			}
		}
		sent = send(sck, buff + actuallysent, len - actuallysent, 0);
		if (sent < 0) {
			if (errno == EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;  // was interupted by signal so restart
			}
			return false;
		}
		if (sent == 0) {
			return false;  // other end is closed
		}
		actuallysent += sent;
	}
	return true;
}

// read a specified expected amount and return what actually read
int BaseSocket::readFromSocketn(char *buff, int len, unsigned int flags, int timeout)
{
	int cnt, rc;
	cnt = len;
	
	// first, return what's left from the previous buffer read, if anything
	if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
		std::cout << "readFromSocketn: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
		int tocopy = len;
		if ((bufflen - buffstart) < len)
			tocopy = bufflen - buffstart;
		memcpy(buff, buffer + buffstart, tocopy);
		cnt -= tocopy;
		buffstart += tocopy;
		buff += tocopy;
		if (cnt == 0)
			return len;
	}
	
	while (cnt > 0) {
		try {
			checkForInput(timeout);  // throws exception on error or timeout
		}
		catch(std::exception & e) {
			return -1;
		}
		rc = recv(sck, buff, cnt, flags);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (rc == 0) {	// eof
			return len - cnt;
		}
		buff += rc;
		cnt -= rc;
	}
	return len;
}

// read what's available and return error status - can be told not to do an initial checkForInput, and to break on reloads
int BaseSocket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
	// first, return what's left from the previous buffer read, if anything
	int cnt = len;
	int tocopy = 0;
	if ((bufflen - buffstart) > 0) {
		tocopy = len;

#ifdef DGDEBUG
	std::cout << "readFromSocket: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
		if ((bufflen - buffstart) < len)
			tocopy = bufflen - buffstart;

		memcpy(buff, buffer + buffstart, tocopy);
		cnt -= tocopy;
		buffstart += tocopy;
		buff += tocopy;

		if (cnt == 0)
			return len;
	}
	
	int rc = 0;

	if (check_first) {
		try {
			checkForInput(timeout, honour_reloadconfig);
		} catch(std::exception & e) {
			return -1;
		}
	}
	while (true) {
		rc = recv(sck, buff, cnt, flags);
		if (rc < 0) {
			if (errno == EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;
			}
		}

		break;
	}

	return rc + tocopy;
}
