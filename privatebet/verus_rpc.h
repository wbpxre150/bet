#ifndef __VERUS_RPC_H__
#define __VERUS_RPC_H__

#include "bet.h"
#include "common.h"
#include <curl/curl.h>

/* RPC Configuration Structure */
struct verus_rpc_config {
    char host[256];
    int port;
    char user[128];
    char password[256];
    int timeout;
    int use_ssl;
    char chain[64];
    int enabled;
};

/* RPC Response Structure */
struct verus_rpc_response {
    char *data;
    size_t size;
    long http_code;
    int success;
};

/* RPC Connection Structure */
struct verus_rpc_connection {
    CURL *curl;
    struct curl_slist *headers;
    char auth_header[512];
    char url[512];
    int initialized;
};

/* Global RPC configuration */
extern struct verus_rpc_config rpc_config;
extern struct verus_rpc_connection rpc_conn;

/* RPC Client Functions */
int32_t verus_rpc_init(void);
void verus_rpc_cleanup(void);
int32_t verus_rpc_configure(const char *host, int port, const char *user, 
                           const char *password, const char *chain);
int32_t verus_rpc_load_config(const char *config_file);

/* Core RPC Communication */
int32_t verus_rpc_call(const char *method, cJSON *params, cJSON **result);
int32_t verus_rpc_call_raw(const char *json_request, cJSON **result);

/* High-level RPC Methods */
int32_t verus_rpc_getvdxfid(const char *key_name, char **vdxf_id);
int32_t verus_rpc_getidentity(const char *identity, int confirmations, cJSON **result);
int32_t verus_rpc_updateidentity(cJSON *identity_data, cJSON **result);
int32_t verus_rpc_sendcurrency(const char *from_address, cJSON *outputs, 
                              int minconf, double fee, bool subtractfee, 
                              const char *memo_data, cJSON **result);
int32_t verus_rpc_z_getoperationstatus(cJSON *operation_ids, cJSON **result);
int32_t verus_rpc_getaddressutxos(cJSON *addresses, cJSON **result);
int32_t verus_rpc_getblock(const char *block_hash, int verbosity, cJSON **result);
int32_t verus_rpc_getblockcount(int32_t *block_count);
int32_t verus_rpc_getbalance(const char *address, double *balance);

/* Utility Functions */
int32_t verus_rpc_check_connection(void);
const char *verus_rpc_get_error_message(int32_t error_code);
void verus_rpc_set_timeout(int timeout_seconds);

/* Error Codes */
#define VERUS_RPC_OK                    0
#define VERUS_RPC_ERR_INIT             -1001
#define VERUS_RPC_ERR_CONFIG           -1002
#define VERUS_RPC_ERR_CONNECTION       -1003
#define VERUS_RPC_ERR_HTTP             -1004
#define VERUS_RPC_ERR_JSON_PARSE       -1005
#define VERUS_RPC_ERR_JSON_RPC         -1006
#define VERUS_RPC_ERR_MEMORY           -1007
#define VERUS_RPC_ERR_INVALID_PARAMS   -1008
#define VERUS_RPC_ERR_TIMEOUT          -1009
#define VERUS_RPC_ERR_AUTH             -1010

/* Compatibility macros for existing code */
#define make_command_rpc(argc, argv, result) verus_rpc_call_from_args(argc, argv, result)

/* Helper function for backward compatibility */
int32_t verus_rpc_call_from_args(int argc, char **argv, cJSON **result);

#endif /* __VERUS_RPC_H__ */