## Basic Usage ##

Start a web server on port 80, serve ./public folder

    $ ./server http://:80

Create test certs, start an HTTPS server on ./public folder

    $ sh make_test_cert.sh
    $ sudo ./server https://:443 http://:80 -cert testsite.crt -key testsite.key

## WHY?
  Because I wanted a small, high-performance, C only mantlepiece

## Technical Details
  1. The nanoserver uses modern event socket handling (kevent, epoll)
  2. Can handle
     - tcp, udp, local (unix) sockets
     - SSL/TLS.
  4. http header-only parsing lib
  5. socket header-only lib
  6. stringbuf header-only lib for secure buffers
  7. It's all in a single process
  8. You can write handlers in c
  9. All in one server.c

## Problems
1. It's got a memory leak - shows up during wrk testing
2. It only does one thing.  That's your problem.

## Future work
1. Add more plumbing for proxies (forward, reverse, hash connections for sticky mapping)
2. Add configuration
3. Add authenticaion / security ?
4. Add threading ?
5. Add range / offset file serving
6. Support application servers (python, kestral, etc..)
7. ...
8. PROFIT ? lol
