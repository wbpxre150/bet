#define _GNU_SOURCE
#include "verus_rpc.h"
#include "bet.h"
#include "err.h"
#include "config.h"
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Global RPC configuration and connection */
struct verus_rpc_config rpc_config = {0};
struct verus_rpc_connection rpc_conn = {0};

/* Static counter for JSON-RPC request IDs */
static int rpc_id_counter = 1;

/* Callback function for writing response data */
static size_t write_response_callback(void *contents, size_t size, size_t nmemb, struct verus_rpc_response *response)
{
    size_t total_size = size * nmemb;
    char *ptr = realloc(response->data, response->size + total_size + 1);
    
    if (!ptr) {
        dlg_error("Failed to allocate memory for RPC response");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = '\0';
    
    return total_size;
}

/* Initialize RPC client */
int32_t verus_rpc_init(void)
{
    if (rpc_conn.initialized) {
        return VERUS_RPC_OK;
    }
    
    /* Initialize libcurl */
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        dlg_error("Failed to initialize libcurl");
        return VERUS_RPC_ERR_INIT;
    }
    
    /* Create curl handle */
    rpc_conn.curl = curl_easy_init();
    if (!rpc_conn.curl) {
        dlg_error("Failed to create curl handle");
        curl_global_cleanup();
        return VERUS_RPC_ERR_INIT;
    }
    
    /* Set default configuration */
    strncpy(rpc_config.host, "127.0.0.1", sizeof(rpc_config.host) - 1);
    rpc_config.port = 27486;
    strncpy(rpc_config.user, "verusrpc", sizeof(rpc_config.user) - 1);
    strncpy(rpc_config.chain, "chips", sizeof(rpc_config.chain) - 1);
    rpc_config.timeout = 30;
    rpc_config.use_ssl = 0;
    rpc_config.enabled = 1;
    
    /* Set up headers */
    rpc_conn.headers = curl_slist_append(rpc_conn.headers, "Content-Type: text/plain");
    rpc_conn.headers = curl_slist_append(rpc_conn.headers, "Accept: application/json");
    
    rpc_conn.initialized = 1;
    dlg_info("Verus RPC client initialized successfully");
    
    /* Load configuration from file */
    verus_rpc_load_config(NULL);
    
    return VERUS_RPC_OK;
}

/* Cleanup RPC client */
void verus_rpc_cleanup(void)
{
    if (!rpc_conn.initialized) {
        return;
    }
    
    if (rpc_conn.headers) {
        curl_slist_free_all(rpc_conn.headers);
        rpc_conn.headers = NULL;
    }
    
    if (rpc_conn.curl) {
        curl_easy_cleanup(rpc_conn.curl);
        rpc_conn.curl = NULL;
    }
    
    curl_global_cleanup();
    rpc_conn.initialized = 0;
    
    dlg_info("Verus RPC client cleaned up");
}

/* Configure RPC connection */
int32_t verus_rpc_configure(const char *host, int port, const char *user, 
                           const char *password, const char *chain)
{
    if (!host || !user || !password || !chain) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    strncpy(rpc_config.host, host, sizeof(rpc_config.host) - 1);
    rpc_config.port = port;
    strncpy(rpc_config.user, user, sizeof(rpc_config.user) - 1);
    strncpy(rpc_config.password, password, sizeof(rpc_config.password) - 1);
    strncpy(rpc_config.chain, chain, sizeof(rpc_config.chain) - 1);
    
    /* Build URL */
    snprintf(rpc_conn.url, sizeof(rpc_conn.url), 
             "http%s://%s:%d/", 
             rpc_config.use_ssl ? "s" : "", 
             rpc_config.host, 
             rpc_config.port);
    
    /* Set HTTP Basic Authentication using USERPWD format */
    char userpwd[512];
    snprintf(userpwd, sizeof(userpwd), "%s:%s", user, password);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_USERPWD, userpwd);
    
    /* Update headers */
    if (rpc_conn.headers) {
        curl_slist_free_all(rpc_conn.headers);
    }
    rpc_conn.headers = curl_slist_append(NULL, "Content-Type: text/plain");
    rpc_conn.headers = curl_slist_append(rpc_conn.headers, "Accept: application/json");
    
    dlg_info("RPC configured for %s:%d with chain=%s", host, port, chain);
    return VERUS_RPC_OK;
}

/* Load RPC configuration from file */
int32_t verus_rpc_load_config(const char *config_file)
{
    struct verus_rpc_ini_config config = {0};
    int32_t retval = VERUS_RPC_OK;

    if (!config_file) {
        /* Use default blockchain config file if none provided */
        extern char *blockchain_config_ini_file;
        config_file = blockchain_config_ini_file;
    }

    /* Load configuration from INI file */
    retval = bet_load_rpc_config_from_file(config_file, &config);
    if (retval != OK) {
        dlg_error("Failed to load RPC config from file: %s", config_file);
        /* Use default configuration as fallback */
        return verus_rpc_configure("127.0.0.1", 27486, "verusrpc", "password", "chips");
    }

    /* Configure RPC with loaded settings if enabled */
    if (config.enabled) {
        retval = verus_rpc_configure(config.host, config.port, config.user, 
                                   config.password, config.chain);
        if (retval != VERUS_RPC_OK) {
            dlg_error("Failed to configure Verus RPC with loaded settings");
        } else {
            dlg_info("Verus RPC loaded from config: %s:%d (chain: %s)", 
                     config.host, config.port, config.chain);
        }
    } else {
        dlg_info("Verus RPC disabled in config file, using CLI fallback");
        rpc_config.enabled = 0;
        retval = VERUS_RPC_OK; /* Not an error if disabled */
    }

    return retval;
}

/* Core RPC call function */
int32_t verus_rpc_call(const char *method, cJSON *params, cJSON **result)
{
    if (!rpc_conn.initialized) {
        if (verus_rpc_init() != VERUS_RPC_OK) {
            return VERUS_RPC_ERR_INIT;
        }
    }
    
    if (!rpc_config.enabled) {
        dlg_error("RPC is disabled and CLI fallback removed");
        return VERUS_RPC_ERR_CONFIG;
    }
    
    /* Build JSON-RPC request */
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "jsonrpc", "1.0");
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddNumberToObject(request, "id", rpc_id_counter++);
    
    if (params) {
        cJSON_AddItemToObject(request, "params", cJSON_Duplicate(params, 1));
    } else {
        cJSON_AddItemToObject(request, "params", cJSON_CreateArray());
    }
    
    char *request_string = cJSON_Print(request);
    if (!request_string) {
        cJSON_Delete(request);
        return VERUS_RPC_ERR_JSON_PARSE;
    }
    
    
    /* Initialize response structure */
    struct verus_rpc_response response = {0};
    
    /* Configure curl */
    curl_easy_setopt(rpc_conn.curl, CURLOPT_URL, rpc_conn.url);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_POSTFIELDS, request_string);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_HTTPHEADER, rpc_conn.headers);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_WRITEFUNCTION, write_response_callback);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_TIMEOUT, rpc_config.timeout);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_NOSIGNAL, 1L);
    
    /* Set authentication for this request */
    char userpwd[512];
    snprintf(userpwd, sizeof(userpwd), "%s:%s", rpc_config.user, rpc_config.password);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(rpc_conn.curl, CURLOPT_USERPWD, userpwd);
    
    /* Perform request */
    CURLcode curl_result = curl_easy_perform(rpc_conn.curl);
    curl_easy_getinfo(rpc_conn.curl, CURLINFO_RESPONSE_CODE, &response.http_code);
    
    /* Cleanup request data */
    free(request_string);
    cJSON_Delete(request);
    
    /* Check for curl errors */
    if (curl_result != CURLE_OK) {
        dlg_error("RPC request failed: %s", curl_easy_strerror(curl_result));
        if (response.data) free(response.data);
        return VERUS_RPC_ERR_CONNECTION;
    }
    
    /* Check HTTP status - Verus RPC server returns HTTP 500 even for valid JSON-RPC responses */
    if (response.http_code != 200 && response.http_code != 500) {
        dlg_error("RPC HTTP error: %ld", response.http_code);
        if (response.data) {
            dlg_error("Response data: %s", response.data);
            free(response.data);
        }
        return VERUS_RPC_ERR_HTTP;
    }
    
    /* Parse JSON response */
    if (!response.data) {
        dlg_error("Empty RPC response");
        return VERUS_RPC_ERR_JSON_PARSE;
    }
    
    cJSON *json_response = cJSON_Parse(response.data);
    if (!json_response) {
        dlg_error("Failed to parse RPC response JSON");
        free(response.data);
        return VERUS_RPC_ERR_JSON_PARSE;
    }
    
    /* Check for JSON-RPC error */
    cJSON *error = cJSON_GetObjectItem(json_response, "error");
    if (error && !is_cJSON_Null(error)) {
        cJSON *error_message = cJSON_GetObjectItem(error, "message");
        if (error_message && is_cJSON_String(error_message)) {
            dlg_error("RPC error: %s", error_message->valuestring);
        }
        free(response.data);
        cJSON_Delete(json_response);
        return VERUS_RPC_ERR_JSON_RPC;
    }
    
    /* Extract result */
    cJSON *rpc_result = cJSON_GetObjectItem(json_response, "result");
    if (rpc_result && result) {
        *result = cJSON_Duplicate(rpc_result, 1);
    } else if (result) {
        *result = NULL;
    }
    
    free(response.data);
    cJSON_Delete(json_response);
    
    dlg_debug("RPC call '%s' completed successfully", method);
    return VERUS_RPC_OK;
}

/* Raw RPC call with JSON string */
int32_t verus_rpc_call_raw(const char *json_request, cJSON **result)
{
    cJSON *request = cJSON_Parse(json_request);
    if (!request) {
        return VERUS_RPC_ERR_JSON_PARSE;
    }
    
    cJSON *method = cJSON_GetObjectItem(request, "method");
    cJSON *params = cJSON_GetObjectItem(request, "params");
    
    if (!method || !is_cJSON_String(method)) {
        cJSON_Delete(request);
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    int32_t ret = verus_rpc_call(method->valuestring, params, result);
    cJSON_Delete(request);
    return ret;
}

/* High-level RPC methods */
int32_t verus_rpc_getvdxfid(const char *key_name, char **vdxf_id)
{
    if (!key_name || !vdxf_id) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(key_name));
    
    cJSON *result = NULL;
    int32_t ret = verus_rpc_call("getvdxfid", params, &result);
    
    if (ret == VERUS_RPC_OK && result) {
        cJSON *vdxfid_item = cJSON_GetObjectItem(result, "vdxfid");
        if (vdxfid_item && is_cJSON_String(vdxfid_item)) {
            *vdxf_id = strdup(vdxfid_item->valuestring);
        } else {
            ret = VERUS_RPC_ERR_JSON_PARSE;
        }
        cJSON_Delete(result);
    }
    
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_getidentity(const char *identity, int confirmations, cJSON **result)
{
    if (!identity) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(identity));
    cJSON_AddItemToArray(params, cJSON_CreateNumber(confirmations));
    
    int32_t ret = verus_rpc_call("getidentity", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_updateidentity(cJSON *identity_data, cJSON **result)
{
    if (!identity_data) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_Duplicate(identity_data, 1));
    
    int32_t ret = verus_rpc_call("updateidentity", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_sendcurrency(const char *from_address, cJSON *outputs, 
                              int minconf, double fee, bool subtractfee, 
                              const char *memo_data, cJSON **result)
{
    if (!from_address || !outputs) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(from_address));
    cJSON_AddItemToArray(params, cJSON_Duplicate(outputs, 1));
    
    /* Add optional parameters */
    cJSON *options = cJSON_CreateObject();
    cJSON_AddNumberToObject(options, "minconf", minconf);
    cJSON_AddNumberToObject(options, "fee", fee);
    cJSON_AddBoolToObject(options, "subtractfee", subtractfee);
    cJSON_AddItemToArray(params, options);
    
    if (memo_data) {
        cJSON_AddItemToArray(params, cJSON_CreateString(memo_data));
    }
    
    int32_t ret = verus_rpc_call("sendcurrency", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_z_getoperationstatus(cJSON *operation_ids, cJSON **result)
{
    if (!operation_ids) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_Duplicate(operation_ids, 1));
    
    int32_t ret = verus_rpc_call("z_getoperationstatus", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_getaddressutxos(cJSON *addresses, cJSON **result)
{
    if (!addresses) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_Duplicate(addresses, 1));
    
    int32_t ret = verus_rpc_call("getaddressutxos", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_getblock(const char *block_hash, int verbosity, cJSON **result)
{
    if (!block_hash) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(block_hash));
    cJSON_AddItemToArray(params, cJSON_CreateNumber(verbosity));
    
    int32_t ret = verus_rpc_call("getblock", params, result);
    cJSON_Delete(params);
    return ret;
}

int32_t verus_rpc_getblockcount(int32_t *block_count)
{
    if (!block_count) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *result = NULL;
    int32_t ret = verus_rpc_call("getblockcount", NULL, &result);
    
    if (ret == VERUS_RPC_OK && result && is_cJSON_Number(result)) {
        *block_count = (int32_t)result->valuedouble;
        cJSON_Delete(result);
    } else {
        ret = VERUS_RPC_ERR_JSON_PARSE;
    }
    
    return ret;
}

int32_t verus_rpc_getbalance(const char *address, double *balance)
{
    if (!address || !balance) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(address));
    
    cJSON *result = NULL;
    int32_t ret = verus_rpc_call("getbalance", params, &result);
    
    if (ret == VERUS_RPC_OK && result && is_cJSON_Number(result)) {
        *balance = result->valuedouble;
        cJSON_Delete(result);
    } else {
        ret = VERUS_RPC_ERR_JSON_PARSE;
    }
    
    cJSON_Delete(params);
    return ret;
}

/* Utility functions */
int32_t verus_rpc_check_connection(void)
{
    cJSON *result = NULL;
    int32_t ret = verus_rpc_call("getblockcount", NULL, &result);
    
    if (result) {
        cJSON_Delete(result);
    }
    
    return ret;
}

const char *verus_rpc_get_error_message(int32_t error_code)
{
    switch (error_code) {
        case VERUS_RPC_OK:
            return "Success";
        case VERUS_RPC_ERR_INIT:
            return "RPC initialization failed";
        case VERUS_RPC_ERR_CONFIG:
            return "RPC configuration error";
        case VERUS_RPC_ERR_CONNECTION:
            return "RPC connection failed";
        case VERUS_RPC_ERR_HTTP:
            return "HTTP error";
        case VERUS_RPC_ERR_JSON_PARSE:
            return "JSON parsing error";
        case VERUS_RPC_ERR_JSON_RPC:
            return "JSON-RPC error";
        case VERUS_RPC_ERR_MEMORY:
            return "Memory allocation error";
        case VERUS_RPC_ERR_INVALID_PARAMS:
            return "Invalid parameters";
        case VERUS_RPC_ERR_TIMEOUT:
            return "Request timeout";
        case VERUS_RPC_ERR_AUTH:
            return "Authentication failed";
        default:
            return "Unknown error";
    }
}

void verus_rpc_set_timeout(int timeout_seconds)
{
    rpc_config.timeout = timeout_seconds;
}

/* Backward compatibility function */
int32_t verus_rpc_call_from_args(int argc, char **argv, cJSON **result)
{
    if (argc < 2 || !argv || !argv[1]) {
        return VERUS_RPC_ERR_INVALID_PARAMS;
    }
    
    /* Skip the CLI path (argv[0]) and get the method (argv[1]) */
    const char *method = argv[1];
    
    /* Build params array from remaining arguments */
    cJSON *params = cJSON_CreateArray();
    for (int i = 2; i < argc; i++) {
        if (argv[i] && strlen(argv[i]) > 0) {
            /* Try to parse as JSON first, if that fails treat as string */
            cJSON *param = cJSON_Parse(argv[i]);
            if (param) {
                cJSON_AddItemToArray(params, param);
            } else {
                cJSON_AddItemToArray(params, cJSON_CreateString(argv[i]));
            }
        }
    }
    
    int32_t ret = verus_rpc_call(method, params, result);
    cJSON_Delete(params);
    
    return ret;
}