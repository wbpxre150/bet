#include "bet.h"

/* RPC Configuration Structure */
struct verus_rpc_ini_config {
    char host[256];
    int port;
    char user[128];
    char password[256];
    int timeout;
    int use_ssl;
    char chain[64];
    int enabled;
};

cJSON *bet_read_json_file(char *file_name);
void bet_parse_dealer_config_ini_file();
void bet_parse_player_config_ini_file();
void bet_parse_cashier_config_ini_file();
void bet_display_cashier_hosted_gui();
int32_t bet_parse_bets();
void bet_parse_blockchain_config_ini_file();
bool bet_is_new_block_set();
int32_t bet_parse_verus_dealer();
int32_t bet_parse_verus_player();

/* RPC Configuration Functions */
int32_t bet_parse_verus_rpc_config();
int32_t bet_load_rpc_config_from_file(const char *config_file, struct verus_rpc_ini_config *config);