#include "uvmyc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void uvmycPulse(uvmyc *conn);

void uvmycInit(uvmyc *conn, unsigned char charset, const char *username,
    const char *password, const char *dbname, const char *host,
    uv_loop_t *loop) {
  char ip[100];
  unsigned short port;
  char *p;
  void *data;
  if (p = strchr(host, ':')) {
    memcpy(ip, host, p - host);
    ip[p - host] = '\0';
    port = atoi(p + 1);
  } else {
    strcpy(ip, host);
    port = 3306;
  }
  data = conn->data;
  memset(conn, 0, sizeof(uvmyc));
  conn->data = data;
  uv_ip4_addr(ip, port, &conn->addr);
  conn->base.data = conn;
  conn->loop = loop;
  mycInit(&conn->base, charset, username, password, dbname);
}

static void uvmycReset(uvmyc *conn) {
  conn->needReset = 1;
  uvmycPulse(conn);
}

static void onAlloc(uv_handle_t *handle,
    size_t suggested_size,
    uv_buf_t *buf) {
  uvmyc *conn = (uvmyc *)handle->data;
  *buf = uv_buf_init(conn->tcpBuf, sizeof(conn->tcpBuf));
}

static void onRead(uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t* buf) {
  uvmyc *conn = (uvmyc *)stream->data;
  //fprintf(stderr, "%s: nread:%d\n", __FUNCTION__, nread);
  if (nread <= 0) {
    uvmycReset(conn);
    return;
  }
  //fprintf(stderr, "read[%.*s]", nread, buf->base);
  if (0 != mycRead(&conn->base, buf->base, nread)) {
    uvmycReset(conn);
    return;
  }
  uvmycPulse(conn);
}

static void onConnect(uv_connect_t *req, int status) {
  uvmyc *conn = (uvmyc *)req->data;
  //fprintf(stderr, "%s: status:%d\n", __FUNCTION__, status);
  conn->isConnecting = 0;
  if (0 != status) {
    return;
  }
  conn->needReset = 0;
  conn->connected = 1;
  if (0 != uv_read_start((uv_stream_t *)&conn->tcp, onAlloc, onRead)) {
    uvmycReset(conn);
    return;
  }
}

static int uvmycIsPending(uvmyc *conn) {
  return conn->isConnecting || conn->isClosing || conn->isSending;
}

static void onClose(uv_handle_t *handle) {
  uvmyc *conn = (uvmyc *)handle->data;
  //fprintf(stderr, "%s:\n", __FUNCTION__);
  conn->isClosing = 0;
  conn->connected = 0;
}

static void onWrite(uv_write_t *req, int status) {
  uvmyc *conn = (uvmyc *)req->data;
  //fprintf(stderr, "%s: status:%d\n", __FUNCTION__, status);
  conn->isSending = 0;
  if (0 != status) {
    uvmycReset(conn);
    return;
  }
  if (0 != mycFinishWrite(&conn->base)) {
    uvmycReset(conn);
    return;
  }
  uvmycPulse(conn);
}

static void uvmycPulse(uvmyc *conn) {
  if (uvmycIsPending(conn)) {
    return;
  }
  if (conn->needReset) {
    if (conn->connected) {
      conn->isClosing = 1;
      uv_close((uv_handle_t *)&conn->tcp, onClose);
      return;
    } else {
      conn->needReset = 0;
      mycReset(&conn->base);
      if (conn->executeCb) {
        uvmycCb cb = conn->executeCb;
        conn->executeCb = 0;
        cb(conn, -1);
        if (uvmycIsPending(conn)) {
          return;
        }
      }
    }
  }
  if (!conn->connected) {
    conn->tcp.data = conn;
    if (0 == uv_tcp_init(conn->loop, &conn->tcp)) {
      conn->connectReq.data = conn;
      conn->isConnecting = 1;
      if (0 != uv_tcp_connect(&conn->connectReq,
          &conn->tcp, (const struct sockaddr *)&conn->addr, onConnect)) {
        conn->isConnecting = 0;
      }
    }
  }
  if (conn->connected) {
    int wantWriteSize = mycWantWriteSize(&conn->base);
    if (wantWriteSize > 0) {
      uv_buf_t buf = uv_buf_init(mycWantWriteData(&conn->base), wantWriteSize);
      conn->writeReq.data = conn;
      conn->isSending = 1;
      if (0 != uv_write(&conn->writeReq, (uv_stream_t *)&conn->tcp, &buf, 1,
          onWrite)) {
        conn->isSending = 0;
        uvmycReset(conn);
        return;
      }
      return;
    }
    if (!conn->executeCb && conn->idleCb && mycIsIdle(&conn->base)) {
      conn->idleCb(conn, 0);
    }
  }
}

static void onTimer(uv_timer_t *timer) {
  uvmyc *conn = (uvmyc *)timer->data;
  uvmycPulse(conn);
}

int uvmycStart(uvmyc *conn, uvmycCb idleCb) {
  conn->idleCb = idleCb;
  conn->timer.data = conn;
  if (0 != uv_timer_init(conn->loop, &conn->timer)) {
    fprintf(stderr, "%s: uv_timer_init failed\n", __FUNCTION__);
    return -1;
  }
  if (0 != uv_timer_start(&conn->timer, onTimer, 0, 1000)) {
     fprintf(stderr, "%s: uv_timer_start failed\n", __FUNCTION__);
    return -1;
  }
  return 0;
}

static void onExecute(myc *base, int status) {
  uvmyc *conn = (uvmyc *)base->data;
  uvmycCb cb = conn->executeCb;
  conn->executeCb = 0;
  cb(conn, status);
  uvmycPulse(conn);
}

int uvmycIsIdle(uvmyc *conn) {
  return conn->connected && !conn->executeCb && mycIsIdle(&conn->base);
}

int uvmycQueryLimit1000(uvmyc *conn, const char *sql, int sqlLen, 
    uvmycCb cb) {
  int result;
  assert(cb);
  if (!uvmycIsIdle(conn)) {
    return -1;
  }
  conn->executeCb = cb;
  result = mycQueryLimit1000(&conn->base, sql, sqlLen, onExecute);
  if (0 != result) {
    uvmycReset(conn);
    return -1;
  }
  uvmycPulse(conn);
  return 0;
}

int uvmycExecute(uvmyc *conn, const char *sql, int sqlLen, 
    uvmycCb cb) {
  int result;
  assert(cb);
  if (!uvmycIsIdle(conn)) {
    return -1;
  }
  conn->executeCb = cb;
  result = mycExecute(&conn->base, sql, sqlLen, onExecute);
  if (0 != result) {
    uvmycReset(conn);
    return -1;
  }
  uvmycPulse(conn);
  return 0;
}
