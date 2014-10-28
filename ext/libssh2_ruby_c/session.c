#include <libssh2_ruby.h>

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef INADDR_NONE
#define INADDR_NONE (in_addr_t)-1
#endif


struct channel_forwardable {
  LIBSSH2_LISTENER *listener;
  LIBSSH2_CHANNEL *channel;
  VALUE self;
  int forwardsock;
};

struct channel_forwardable ChannelForward;


/*
 * Increases the reference counter on the ruby session container.
 * */
void
libssh2_ruby_session_retain(LibSSH2_Ruby_Session *session_data) {
    session_data->refcount++;
}

/*
 * Decrements the reference counter on the ruby session container.
 * When this goes to 0 then the session will be released.
 * */
void
libssh2_ruby_session_release(LibSSH2_Ruby_Session *session_data) {
    // Decrease the reference count
    session_data->refcount--;

    // If the reference count is 0, free all the things!
    if (session_data->refcount == 0) {
        if (session_data->session != NULL) {
            BLOCK(libssh2_session_disconnect(
                        session_data->session,
                        "Normal shutdown by libssh2-ruby."));
            BLOCK(libssh2_session_free(session_data->session));
        }

        free(session_data);
    }
}

/*
 * Helper to return the LIBSSH2_SESSION pointer for the given
 * instance.
 * */
static inline LIBSSH2_SESSION *
get_session(VALUE self) {
    LibSSH2_Ruby_Session *session;
    Data_Get_Struct(self, LibSSH2_Ruby_Session, session);
    return session->session;
}

/*
 * Called when the object is deallocated in order to deallocate the
 * interal state.
 * */
static void
session_dealloc(LibSSH2_Ruby_Session *session_data) {
    libssh2_ruby_session_release(session_data);
}

/*
 * Called to allocate the memory associated with the object. We allocate
 * memory for internal structs and set them onto the object.
 * */
static VALUE
allocate(VALUE self) {
    LibSSH2_Ruby_Session *session = malloc(sizeof(LibSSH2_Ruby_Session));
    session->session  = NULL;
    session->refcount = 0;

    return Data_Wrap_Struct(self, 0, session_dealloc, session);
}

/*
 * call-seq:
 *     LibSSH2::Native::Session.new
 *
 * Initializes a new LibSSH2 session. This will raise an exception on
 * failure.
 *
 * */
static VALUE
initialize(VALUE self) {
    LibSSH2_Ruby_Session *session;

    // Get the struct that stores our internal state out. This gets
    // setup in the `alloc` method.
    Data_Get_Struct(self, LibSSH2_Ruby_Session, session);

    session->session = libssh2_session_init();
    if (session->session == NULL) {
        // ERROR! Make better exceptions plz.
        rb_raise(rb_eRuntimeError, "session init failed");
        return Qnil;
    }

    // Retain so that we have a proper refcount
    libssh2_ruby_session_retain(session);

    return self;
}

/*
 * call-seq:
 *     session.block_directions
 *
 * Returns an int that determines the direction to wait on the socket
 * in the case of an EAGAIN. This will be a binary mask that can be
 * checked with `Native::SESSION_BLOCK_INBOUND` and
 * `Native::SESSION_BLOCK_OUTBOUND`.
 * */
static VALUE
block_directions(VALUE self) {
    return INT2FIX(libssh2_session_block_directions(get_session(self)));
}

/*
 * call-seq:
 *     session.handshake(socket.fileno) -> int
 *
 * Initiates the handshake sequence for this session. You must
 * pass in the file number for the socket to use. This wll return
 * 0 on success, or raise an exception otherwise.
 *
 * */
static VALUE
handshake(VALUE self, VALUE num_fd) {
    int fd = NUM2INT(num_fd);
    int ret = libssh2_session_handshake(get_session(self), TO_SOCKET(fd));
    HANDLE_LIBSSH2_RESULT(ret);
}

/*
 * call-seq:
 *     session.set_blocking(true) -> true
 *
 * If the argument is true, enables blocking semantics for this session,
 * otherwise enables non-blocking semantics.
 *
 * */
static VALUE
set_blocking(VALUE self, VALUE blocking) {
    int blocking_arg = blocking == Qtrue ? 1 : 0;
    libssh2_session_set_blocking(get_session(self), blocking_arg);
    return blocking;
}

/*
 * call-seq:
 *     session.userauth_authenticated -> true/false
 *
 * Returns a boolean of whether this session has been authenticated or
 * not.
 *
 * */
static VALUE
userauth_authenticated(VALUE self) {
    return libssh2_userauth_authenticated(get_session(self)) == 1 ?
        Qtrue :
        Qfalse;
}

/*
 * call-seq:
 *     session.userauth_password("username", "password")
 *
 * Attempts to authenticate using a username and password.
 *
 * */
static VALUE
userauth_password(VALUE self, VALUE username, VALUE password) {
    int result;
    rb_check_type(username, T_STRING);
    rb_check_type(password, T_STRING);

    result = libssh2_userauth_password(
            get_session(self),
            StringValuePtr(username),
            StringValuePtr(password));
    HANDLE_LIBSSH2_RESULT(result);
}

/*
 * call-seq:
 *     session.userauth_publickey_fromfile("username", "/etc/key.pub", "/etc/key", "foo")
 *
 * Attempts to authenticate using public and private keys from files.
 *
 * */
static VALUE
userauth_publickey_fromfile(VALUE self,
        VALUE username,
        VALUE publickey_path,
        VALUE privatekey_path,
        VALUE passphrase) {
    int result;
    rb_check_type(username, T_STRING);
    rb_check_type(publickey_path, T_STRING);
    rb_check_type(privatekey_path, T_STRING);
    rb_check_type(passphrase, T_STRING);

    result = libssh2_userauth_publickey_fromfile(
            get_session(self),
            StringValuePtr(username),
            StringValuePtr(publickey_path),
            StringValuePtr(privatekey_path),
            StringValuePtr(passphrase));
    HANDLE_LIBSSH2_RESULT(result);
}


static VALUE channel_forward_listen_ex(VALUE self,
                          VALUE rb_host, VALUE rb_port,
                          VALUE rb_bound_port) {
  LIBSSH2_SESSION *session = get_session(self);
  //LIBSSH2_LISTENER *listener = NULL;


  char *host = RSTRING_PTR(rb_host);

  unsigned int port = NUM2UINT(rb_bound_port);
  int tmp_bound_port = NUM2INT(rb_bound_port);
  int *bound_port= &tmp_bound_port;

  ChannelForward.listener = libssh2_channel_forward_listen_ex(session, host, port, bound_port, 1);
  return Qnil;
}

static VALUE channel_forward_accept()
{
  ChannelForward.channel = libssh2_channel_forward_accept(ChannelForward.listener);
  return Qnil;
}

static VALUE start_forward_loop(VALUE self,
                                VALUE rb_host, VALUE rb_port,
                                VALUE rb_bound_port) {
  char *host = RSTRING_PTR(rb_host);
  unsigned int port = NUM2UINT(rb_bound_port);
  int tmp_bound_port = NUM2INT(rb_bound_port);
  int *bound_port= &tmp_bound_port;

  channel_forward_listen_ex(self, rb_host, rb_port, rb_bound_port);
  channel_forward_accept();

  ChannelForward.self=self;
  int rc, i = 0;
  struct sockaddr_in sin;
  socklen_t sinlen = sizeof(sin);
  fd_set fds;
  struct timeval tv;
  ssize_t len, wr;
  char buf[16384];

  if (!ChannelForward.channel) {
    fprintf(stderr, "Could not accept connection!\n"
            "(Note that this can be a problem at the server!"
            " Please review the server logs.)\n");
    cleanup_forward();
  }

  fprintf(stderr,
    "Accepted remote connection. Connecting to local server %s:%d\n",
    host, port);

  ChannelForward.forwardsock=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  //forwardsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  if (INADDR_NONE == (sin.sin_addr.s_addr = inet_addr(host))) {
      perror("inet_addr");
      cleanup_forward();
  }
  if (-1 == connect(ChannelForward.forwardsock, (struct sockaddr *)&sin, sinlen)) {
      perror("connect");
      cleanup_forward();
  }

  fprintf(stderr, "Forwarding connection from remote %s:%d to local %s:%d\n",
          host, bound_port, host, port);

    /* Must use non-blocking IO hereafter due to the current libssh2 API */
  libssh2_session_set_blocking(get_session(self), 0);


    while (1) {
        FD_ZERO(&fds);
        FD_SET(ChannelForward.forwardsock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select(ChannelForward.forwardsock + 1, &fds, NULL, NULL, &tv);
        if (-1 == rc) {
            perror("select");
            cleanup_forward();
        }
        if (rc && FD_ISSET(ChannelForward.forwardsock, &fds)) {
            len = recv(ChannelForward.forwardsock, buf, sizeof(buf), 0);
            if (len < 0) {
                perror("read");
                cleanup_forward();
            } else if (0 == len) {
                fprintf(stderr, "The local server at %s:%d disconnected!\n",
                    host, port);
                cleanup_forward();
            }
            wr = 0;
            do {
                i = libssh2_channel_write(ChannelForward.channel, buf, len);
                if(i == LIBSSH2_ERROR_EAGAIN) {
                  i = 1;
                }
                if (i < 0) {
                    fprintf(stderr, "libssh2_channel_write: %d\n", i);
                    cleanup_forward();
                }
                wr += i;
            } while(i > 0 && wr < len);
        }
        while (1) {
            len = libssh2_channel_read(ChannelForward.channel, buf, sizeof(buf));
            if (LIBSSH2_ERROR_EAGAIN == len)
                break;
            else if (len < 0) {
                fprintf(stderr, "libssh2_channel_read: %d", (int)len);
                cleanup_forward();
            }
            wr = 0;
            while (wr < len) {
                i = send(ChannelForward.forwardsock, buf + wr, len - wr, 0);
                if (i <= 0) {
                    perror("write");
                    cleanup_forward();
                }
                wr += i;
            }
            /*
            if (libssh2_channel_eof(ChannelForward.channel)) {
                fprintf(stderr, "The remote client at %s:%d disconnected!\n",
                    host, port);
                cleanup_forward();
            }
            */
        }
    }


}

int cleanup_forward() {
//static VALUE cleanup_forward(VALUE self) {
    fprintf(stderr, "SHUTDOWN");
#ifdef WIN32
    closesocket(ChannelForward.forwardsock);
#else
    close(ChannelForward.forwardsock);
#endif
    if (ChannelForward.channel)
        libssh2_channel_free(ChannelForward.channel);
    if (ChannelForward.listener)
        libssh2_channel_forward_cancel(ChannelForward.listener);
    libssh2_session_disconnect(get_session(ChannelForward.self), "Client disconnecting normally");
    libssh2_session_free(get_session(ChannelForward.self));


    libssh2_exit();
    return 0;
    //return Qnil;
}

void init_libssh2_session() {
    VALUE cSession = rb_cLibSSH2_Native_Session;
    rb_define_alloc_func(cSession, allocate);
    rb_define_method(cSession, "initialize", initialize, 0);
    rb_define_method(cSession, "block_directions", block_directions, 0);
    rb_define_method(cSession, "handshake", handshake, 1);
    rb_define_method(cSession, "start_forward_loop", start_forward_loop, 3);
    rb_define_method(cSession, "set_blocking", set_blocking, 1);
    rb_define_method(cSession, "userauth_authenticated", userauth_authenticated, 0);
    rb_define_method(cSession, "userauth_password", userauth_password, 2);
    rb_define_method(cSession, "userauth_publickey_fromfile",
            userauth_publickey_fromfile, 4);
}
