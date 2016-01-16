#ifndef __MYC_H__
#define __MYC_H__

#define MYC_MAX_ROW                         1000
#define MYC_MAX_COL                         256
#define MYC_MAX_ROW_BUFSIZE                 (1024 * 20)
#define MYC_MAX_SEND_BUFSIZE                (1024 * 20)

#define MYC_MAX_USERNAME_LEN                100
#define MYC_MAX_PASSWORD_LEN                100
#define MYC_MAX_DBNAME_LEN                  100

#define MYC_MAX_ERR_MSG_LEN                 2048

#ifndef SCRAMBLE_LENGTH
#define SCRAMBLE_LENGTH 20
#endif

typedef struct myc myc;

typedef void (*mycCb)(myc *conn, int status);

#define MYC_PRIVATE_FIELDS \
  char username[MYC_MAX_USERNAME_LEN + 1];\
  char password[MYC_MAX_PASSWORD_LEN + 1];\
  char dbname[MYC_MAX_DBNAME_LEN + 1];\
  int selectState;\
  int fieldIndex;\
  int fieldCount;\
  unsigned long long rowCount;\
  char *rows[MYC_MAX_ROW][MYC_MAX_COL];\
  int resOffset;\
  char resBuf[MYC_MAX_ROW * MYC_MAX_ROW_BUFSIZE];\
  int isSending:1;\
  int logined:1;\
  unsigned short status;\
  unsigned short options;\
  unsigned char charset;\
  unsigned char protocol;\
  unsigned char packetNumber;\
  unsigned long long affectedRows;\
  unsigned long long insertId;\
  int readRowIndex;\
  int payloadReadOffset;\
  int payloadLen;\
  unsigned char seqId;\
  int analyzeOffset;\
  int recvOffset;\
  int analyzeState;\
  int wantPacketType;\
  int wantWriteSize;\
  int mysqlErrCode;\
  char mysqlErrMsg[MYC_MAX_ERR_MSG_LEN + 1];\
  char salt[SCRAMBLE_LENGTH + 1];\
  unsigned char sendBuf[MYC_MAX_SEND_BUFSIZE];\
  unsigned char recvBuf[3 + 1 + MYC_MAX_ROW_BUFSIZE];\
  mycCb executeCb;\
  char reserved[2048];

struct myc {
  MYC_PRIVATE_FIELDS
  void *data;
};

void mycInit(myc *conn, unsigned char charset, const char *username,
    const char *password, const char *dbname);
int mycRead(myc *conn, char *data, int size);
int mycWantWriteSize(myc *conn);
char *mycWantWriteData(myc *conn);
int mycFinishWrite(myc *conn);
int mycIsIdle(myc *conn);
int mycExecuteLimit1000(myc *conn, const char *sql, int sqlLen, mycCb cb);
int mycGetFieldCount(myc *conn);
int mycGetRowCount(myc *conn);
long long mycGetRowNumber(myc *conn, int row, int column);
const char *mycGetRowString(myc *conn, int row, int column);
unsigned long long mycGetInsertId(myc *conn);
unsigned long long mycGetAffectedRows(myc *conn);
const char *mycGetMysqlErrMsg(myc *conn);
int mycGetMysqlErrCode(myc *conn);

#endif
