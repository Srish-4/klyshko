#define EXTERN
#include "vars.h"

char** kii_endpoints;
#include <fcntl.h>
#include <sys/stat.h>

// Step 1: Define an enumeration for tuple types
typedef enum {
    BIT_GFP,
    BIT_GF2N,
    INPUT_MASK_GFP,
    INPUT_MASK_GF2N,
    INVERSE_TUPLE_GFP,
    INVERSE_TUPLE_GF2N,
    SQUARE_TUPLE_GFP,
    SQUARE_TUPLE_GF2N,
    MULTIPLICATION_TRIPLE_GFP,
    MULTIPLICATION_TRIPLE_GF2N,
    TUPLE_TYPE_COUNT  // Count of types, useful for bounds checking
} TupleType;

// Step 2: Arrays for command arguments and file paths corresponding to the tuple types
const char* arg1ByType[TUPLE_TYPE_COUNT] = {
    "--nbits",      // BIT_GFP
    "--nbits",      // BIT_GF2N
    "--ntriples",   // INPUT_MASK_GFP
    "--ntriples",   // INPUT_MASK_GF2N
    "--ninverses",  // INVERSE_TUPLE_GFP
    "--ninverses",  // INVERSE_TUPLE_GF2N
    "--nsquares",   // SQUARE_TUPLE_GFP
    "--nsquares",   // SQUARE_TUPLE_GF2N
    "--ntriples",   // MULTIPLICATION_TRIPLE_GFP
    "--ntriples"    // MULTIPLICATION_TRIPLE_GF2N
};

const char* arg2FormatByType[TUPLE_TYPE_COUNT] = {
    "0,%s",  // BIT_GFP
    "%s,0",  // BIT_GF2N
    "0,%d",  // INPUT_MASK_GFP (where n/3 is used)
    "%d,0",  // INPUT_MASK_GF2N (where n/3 is used)
    "%s",    // INVERSE_TUPLE_GFP
    "%s",    // INVERSE_TUPLE_GF2N
    "0,%s",  // SQUARE_TUPLE_GFP
    "%s,0",  // SQUARE_TUPLE_GF2N
    "0,%s",  // MULTIPLICATION_TRIPLE_GFP
    "%s,0"   // MULTIPLICATION_TRIPLE_GF2N
};

const char* tupleFileByType[TUPLE_TYPE_COUNT] = {
    "%s-p-128/Bits-p-P%s",      // BIT_GFP
    "%s-2-40/Bits-2-P%s",       // BIT_GF2N
    "%s-p-128/Triples-p-P%s",   // INPUT_MASK_GFP
    "%s-2-40/Triples-2-P%s",    // INPUT_MASK_GF2N
    "%s-p-128/Inverses-p-P%s",  // INVERSE_TUPLE_GFP
    "%s-2-40/Inverses-2-P%s",   // INVERSE_TUPLE_GF2N
    "%s-p-128/Squares-p-P%s",   // SQUARE_TUPLE_GFP
    "%s-2-40/Squares-2-P%s",    // SQUARE_TUPLE_GF2N
    "%s-p-128/Triples-p-P%s",   // MULTIPLICATION_TRIPLE_GFP
    "%s-2-40/Triples-2-P%s"     // MULTIPLICATION_TRIPLE_GF2N
};

// Helper function to convert string to TupleType enum
TupleType getTupleType(const char* tuple_type_str) {
    if (strcmp(tuple_type_str, "BIT_GFP") == 0)
        return BIT_GFP;
    if (strcmp(tuple_type_str, "BIT_GF2N") == 0)
        return BIT_GF2N;
    if (strcmp(tuple_type_str, "INPUT_MASK_GFP") == 0)
        return INPUT_MASK_GFP;
    if (strcmp(tuple_type_str, "INPUT_MASK_GF2N") == 0)
        return INPUT_MASK_GF2N;
    if (strcmp(tuple_type_str, "INVERSE_TUPLE_GFP") == 0)
        return INVERSE_TUPLE_GFP;
    if (strcmp(tuple_type_str, "INVERSE_TUPLE_GF2N") == 0)
        return INVERSE_TUPLE_GF2N;
    if (strcmp(tuple_type_str, "SQUARE_TUPLE_GFP") == 0)
        return SQUARE_TUPLE_GFP;
    if (strcmp(tuple_type_str, "SQUARE_TUPLE_GF2N") == 0)
        return SQUARE_TUPLE_GF2N;
    if (strcmp(tuple_type_str, "MULTIPLICATION_TRIPLE_GFP") == 0)
        return MULTIPLICATION_TRIPLE_GFP;
    if (strcmp(tuple_type_str, "MULTIPLICATION_TRIPLE_GF2N") == 0)
        return MULTIPLICATION_TRIPLE_GF2N;

    // Default case, handle unknown types (could be an error handling mechanism)
    return TUPLE_TYPE_COUNT;
}

void get_random_hex(char* hex_str, int length) {
    const char hex_chars[] = "0123456789abcdef";  // Use lowercase letters
    unsigned char random_bytes[length];

    // Get truly random bytes from the system
    if (getrandom(random_bytes, length, 0) == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < length; i++) {
        hex_str[i] = hex_chars[random_bytes[i] % 16];  // Convert to hex
    }

    hex_str[length] = '\0';  // Null-terminate the string
}

void writeFile(const char* filename, const char* text) {
    // Open the file for writing
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error openin file while writing");
        exit(1);  // Exit if there's an error opening the file
    } else {
        perror("opened successfully");
    }

    // Write the text to the file
    fprintf(file, "%s", text);

    // Close the file
    fclose(file);
}

void create_mac_key_shares(int pc, int pn, char* Player_MAC_Keys_p[], char* Player_MAC_Keys_2[]) {
    const char* fields[] = {"p", "2"};

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        const char* f         = fields[i];
        const char* bit_width = (strcmp(f, "p") == 0) ? "128" : "40";

        char* folder = "Player-Data/";

        char folderPath[256];
        snprintf(folderPath, sizeof(folderPath), "%s%d-%s-%s", folder, pc, f, bit_width);

        printf("Providing parameters for field %s-%s in folder %s\n", f, bit_width, folder);

        // Write MAC key shares for all players
        for (int playerNumber = 0; playerNumber < pc; ++playerNumber) {
            char macKeyShareFile[256];
            snprintf(macKeyShareFile, sizeof(macKeyShareFile), "%s/Player-MAC-Keys-%s-P%d",
                     folderPath, f, playerNumber);

            char* macKeyShare;
            char file_path[256];
            if (f == "p") {
                macKeyShare = Player_MAC_Keys_p[playerNumber];
            } else {
                macKeyShare = Player_MAC_Keys_2[playerNumber];
            }

            printf("%s\n", macKeyShare);

            char dataToWrite[256];

            printf("----- TRYING TO WRITE for MAC key share for player %d written to %s\n",
                   playerNumber, macKeyShareFile);
            snprintf(dataToWrite, sizeof(dataToWrite), "%d %s", pc, macKeyShare);
            writeFile(macKeyShareFile, dataToWrite);

            printf("MAC key share for player %d written to %s\n", playerNumber, macKeyShareFile);
        }
    }
}

int main(int argc, char** argv) {
    printf("Entered the CRG main function.\n\n");

    int ret;
    int other_player_number = 0;
    char* prime             = "198766463529478683931867765928436695041";
    // char* Player_MAC_Keys_p[2] = {"-88222337191559387830816715872691188862",
    //                               "1113507028231509545156335486838233832"};
    // char* Player_MAC_Keys_2[2] = {"f0cf6099e629fd0bda2de3f9515ab722",
    //                               "c347ce3d9e165e4e85221f9da7591d92"};

    char Seed[17];
    char* n = "10000";

    get_random_hex(Seed, 16);
    printf("GENERATED SEED ------- :%s\n", Seed);
    printf("Getting environment variables ...");
    const char* env_names[] = {"KII_TUPLES_PER_JOB", "KII_SHARED_FOLDER", "KII_TUPLE_FILE",
                               "KII_PLAYER_NUMBER",  "KII_PLAYER_COUNT",  "KII_JOB_ID",
                               "KII_TUPLE_TYPE",     "BASE_PORT"};

    char* env_values[sizeof(env_names) / sizeof(env_names[0])];

    // Loop through each environment variable
    for (int i = 0; i < sizeof(env_names) / sizeof(env_names[0]); i++) {
        env_values[i] = getenv(env_names[i]);

        // Check if the environment variable exists and print the appropriate message
        if (env_values[i] == NULL) {
            fprintf(stderr, "Error: Environment variable %s not found.\n", env_names[i]);
        }
    }
    char* tuple_type_str        = env_values[6];
    char* kii_job_id_str        = env_values[5];  // KII_JOB_ID
    char* player_number_str     = env_values[3];  // KII_PLAYER_NUMBER
    char* number_of_players_str = env_values[4];
    char* b_port                = env_values[7];
    // Convert to integers
    kii_job_id_defined = kii_job_id_str;  // Check for NULL
    printf("kii_job_id_defined: %s\n", kii_job_id_defined);
    player_number_defined = player_number_str ? atoi(player_number_str) : 0;
    number_of_players     = number_of_players_str ? atoi(number_of_players_str) : 0;
    base_port             = b_port ? atoi(b_port) : 0;
    // EOC for getting the env variables and storing them inside main fuction

    //

    //***$$$***
    kii_endpoints = (char**)malloc(number_of_players * sizeof(char*));
    for (int i = 0; i < number_of_players; i++) {
        char env_kii_name[35];  // Buffer to hold the variable name
        snprintf(env_kii_name, sizeof(env_kii_name), "KII_PLAYER_ENDPOINT_%d", i);
        kii_endpoints[i] = getenv(env_kii_name);
        if (kii_endpoints[i] != NULL) {
            printf("Player %d endpoint: %s", i, kii_endpoints[i]);
        } else {
            printf("Environment variable %s is not set.\n", env_kii_name);
        }
    }

    printf("ok\n");

    // ***$$$***

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    char** Player_MAC_Keys_p = (char**)malloc(number_of_players * sizeof(char*));
    char** Player_MAC_Keys_2 = (char**)malloc(number_of_players * sizeof(char*));

    // Allocate space for each player's key
    for (int i = 0; i < number_of_players; i++) {
        Player_MAC_Keys_p[i] = (char*)malloc(KEY_LENGTH * sizeof(char));
        Player_MAC_Keys_2[i] = (char*)malloc(KEY_LENGTH * sizeof(char));

        if (Player_MAC_Keys_p[i] == NULL || Player_MAC_Keys_2[i] == NULL) {
            printf("Memory allocation failed for player %d\n", i);
            exit(1);
        }
    }

    printf("Local attestation starts . . .");
    local_attestation(Player_MAC_Keys_p, Player_MAC_Keys_2);
    printf("End of CRG.c local attestation\n");
    printf("******************Player 0:%s\n", Player_MAC_Keys_p[0]);
    printf("Player 0: %s\n", Player_MAC_Keys_2[0]);
    printf("Player 1: %s\n", Player_MAC_Keys_p[1]);
    printf("Player 1: %s\n", Player_MAC_Keys_2[1]);
    printf("Remote attestation starts..\n");
    if (player_number_defined == 0) {
        ssl_client_setup_and_handshake(argv[1], argv[2], argv[3], argv[4], Player_MAC_Keys_p,
                                       Player_MAC_Keys_2, Seed);
    } else if (player_number_defined == number_of_players - 1) {
        ssl_server_setup_and_handshake(argv[1], argv[2], argv[3], argv[4], Player_MAC_Keys_p,
                                       Player_MAC_Keys_2, Seed);
    } else {
        ssl_server_setup_and_handshake(argv[1], argv[2], argv[3], argv[4], Player_MAC_Keys_p,
                                       Player_MAC_Keys_2, Seed);
        ssl_client_setup_and_handshake(argv[1], argv[2], argv[3], argv[4], Player_MAC_Keys_p,
                                       Player_MAC_Keys_2, Seed);
    }

    printf("\n\n\nFINAL FINAL ATTESTATION :\nPlayer 0:%s\n", Player_MAC_Keys_p[0]);
    printf("Player 0: %s\n", Player_MAC_Keys_2[0]);
    printf("Player 1: %s\n", Player_MAC_Keys_p[1]);
    printf("Player 1: %s\n", Player_MAC_Keys_2[1]);
    printf("SEED : %s\n", Seed);
    printf("End of Remote attestation..\n");

    TupleType tuple_type = getTupleType(tuple_type_str);
    if (tuple_type == TUPLE_TYPE_COUNT) {
        fprintf(stderr, "Unknown tuple type: %s\n", tuple_type_str);
        return 1;
    }

    char arg2[256] = {0};
    if (strstr(arg2FormatByType[tuple_type], "%d") != NULL) {
        snprintf(arg2, sizeof(arg2), arg2FormatByType[tuple_type], atoi(n) / 3);
    } else {
        snprintf(arg2, sizeof(arg2), arg2FormatByType[tuple_type], n);
    }
    printf("step 4 complete");

    int player_count  = atoi(number_of_players_str);
    int player_number = atoi(player_number_str);
    create_mac_key_shares(player_count, player_number, Player_MAC_Keys_p, Player_MAC_Keys_2);
    printf("mac key created");

    char* args[] = {
        "../Fake-Offline.x",
        "-d",
        "0",
        "--prime",
        prime,
        "--prngseed",
        Seed,
        arg1ByType[tuple_type],  // The argument part 1 (e.g., --nbits)
        arg2,                    // The argument part 2 (e.g., 0,1000)
        number_of_players_str,   // Player count
        NULL                     // Terminate with NULL
    };

    // Debug print
    for (int i = 0; args[i] != NULL; ++i) {
        printf("%s ", args[i]);  // Print each argument followed by a space
    }
    printf("\n");

    // Step 8: Execute ./Fake-Offline.x using execvp
    execvp(args[0], args);

    // If execvp fails:
    perror("execvp failed");
    // ssl_client_setup_and_handshake(argv[1], argv[2], argv[3], argv[4]);

    // Free allocated memory
    for (int i = 0; i < number_of_players; i++) {
        free(Player_MAC_Keys_p[i]);
        free(Player_MAC_Keys_2[i]);
    }

    // free KII_endpoint
    free(kii_endpoints);
    kii_endpoints = NULL;  // Set the pointer to NULL after freeing
}