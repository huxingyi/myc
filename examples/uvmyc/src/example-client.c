#include "uvmyc.h"

#include <stdlib.h>
#include <stdio.h>

#define DBNAME     "au"
#define DBHOST     "127.0.0.1"
#define DBUSER     "root"
#define DBPASSWORD "testsjkmmHAHAHAHA"

static void onExecute(uvmyc *conn, int status) {
  printf("onExecute status:%d\n", status);
  if (0 == status) {
    printf("uvmycGetFieldCount:%d\n", uvmycGetFieldCount(conn));
    printf("uvmycGetRowCount:%d\n", uvmycGetRowCount(conn));
  }
  getchar();
}

static void onIdle(uvmyc *conn, int status) {
  printf("onIdle\n");
  uvmycQueryLimit1000(conn, "SHOW TABLES LIKE 'report'", -1, 
    onExecute);
}

int main(int argc, char *argv[]) {
  uvmyc *conn = (uvmyc *)malloc(sizeof(uvmyc));
  uvmycInit(conn, 33, DBUSER, DBPASSWORD, DBNAME, DBHOST, uv_default_loop());
  uvmycStart(conn, onIdle);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  return 0;
}

