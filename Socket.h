#ifndef SOCKET_H
#define SOCKET_H

#include <WinSock2.h>

#include <string>

enum TypeSocket {BlockingSocket, NonBlockingSocket};

class Socket {
public:

  virtual ~Socket();
  Socket(const Socket&);
  Socket& operator=(Socket&);

  std::string ReceiveLine();
  std::string ReceiveBytes();

  void   Close();

  // The parameter of SendLine is not a const reference
  // because SendLine modifes the std::string passed.
  void   SendLine (std::string);

  // The parameter of SendBytes is a const reference
  // because SendBytes does not modify the std::string passed 
  // (in contrast to SendLine).
  void   SendBytes(const std::string&);

protected:
  friend class SocketServer;
  friend class SocketSelect;

  Socket(SOCKET s);
  Socket();


  SOCKET s_;

  int* refCounter_;

private:
  static void Start();
  static void End();
  static int  nofSockets_;
};

class SocketClient : public Socket {
public:
  SocketClient(const std::string& host, int port);
};

class SocketServer : public Socket {
public:
  SocketServer(int port, int connections, TypeSocket type=BlockingSocket);

  Socket* Accept();
};

// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/wsapiref_2tiq.asp
class SocketSelect {
  public:
    SocketSelect(Socket const * const s1, Socket const * const s2=NULL, TypeSocket type=BlockingSocket);

    bool Readable(Socket const * const s);

  private:
    fd_set fds_;
}; 



#endif
