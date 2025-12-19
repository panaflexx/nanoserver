## Basic Usage

Start a web server on port 80, serve ./public folder
.. code-block:: sh

   $ ./server http://:80

Create test certs, start an HTTPS server on ./public folder
.. code-block:: sh
   $ sh make_test_cert.sh
   $ sudo ./server https://:443 http://:80 -cert testsite.crt -key testsite.key

## WHY?
  Because I wanted a small, high-performance, C only mantlepiece

## Technical Details
  1. The nanoserver uses modern event socket handling (kevent, epoll) and can handle tcp, udp, local (unix) sockets and SSL/TLS.
  2. http header-only parsing lib
  3. socket header-only lib
  4. stringbuf header-only lib for secure buffers
  5. It's all in a single process
  6. You can write handlers in c
  7. All in one server.c

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
