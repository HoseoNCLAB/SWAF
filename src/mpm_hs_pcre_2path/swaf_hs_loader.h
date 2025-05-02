#ifndef __SWAF_HS_LOADER_H__
#define __SWAF_HS_LOADER_H__

#define MAX_PAYLOAD_LEN 8192

int SwafInitHyperscan(const char *json_path);
int SwafConnectPatternSids(void);

#endif

