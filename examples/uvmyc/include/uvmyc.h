#ifndef __UVMYC_H__
#define __UVMYC_H__
#include "myc.h"

#include <uv.h>

typedef struct uvmyc uvmyc;

#define UVMYC_MAX_HOST_LEN 200
#define UVMYC_RECVBUF_SIZE 4096

typedef void (*uvmycCb)(uvmyc *conn, int status);

#define UVMYC_PRIVATE_FIELDS \
  myc base;\
  uv_loop_t *loop;\
  struct sockaddr_in addr;\
  uv_tcp_t tcp;\
  uv_timer_t timer;\
  uv_connect_t connectReq;\
  uv_write_t writeReq;\
  int needReset:1;\
  int isClosing:1;\
  int isSending:1;\
  int isConnecting:1;\
  int connected:1;\
  uvmycCb idleCb;\
  uvmycCb executeCb;\
  char tcpBuf[UVMYC_RECVBUF_SIZE];\
  char reserved[2048];

struct uvmyc {
  UVMYC_PRIVATE_FIELDS
  void *data;
};

void uvmycInit(uvmyc *conn, unsigned char charset, const char *username,
    const char *password, const char *dbname, const char *host,
    uv_loop_t *loop);
int uvmycStart(uvmyc *conn, uvmycCb idleCb);
int uvmycIsIdle(uvmyc *conn);
int uvmycQueryLimit1000(uvmyc *conn, const char *sql, int sqlLen, 
    uvmycCb cb);
int uvmycExecute(uvmyc *conn, const char *sql, int sqlLen, 
    uvmycCb cb);

#define uvmycGetFieldCount(conn) mycGetFieldCount(&(conn)->base)
#define uvmycGetRowCount(conn) mycGetRowCount(&(conn)->base)
#define uvmycGetRowNumber(conn, row, column) mycGetRowNumber(&(conn)->base, (row), (column))
#define uvmycGetRowString(conn, row, column) mycGetRowString(&(conn)->base, (row), (column))
#define uvmycGetInsertId(conn) mycGetInsertId(&(conn)->base)
#define uvmycGetAffectedRows(conn) mycGetAffectedRows(&(conn)->base)
#define uvmycGetMysqlErrMsg(conn) mycGetMysqlErrMsg(&(conn)->base)
#define uvmycGetMysqlErrCode(conn) mycGetMysqlErrCode(&(conn)->base)

#endif
