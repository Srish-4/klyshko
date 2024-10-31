#!/bin/bash

# Configuration Variables
export KII_TUPLES_PER_JOB="100000"
export KII_SHARED_FOLDER="/kii"
export KII_TUPLE_FILE="/kii/tuples"
export KII_PLAYER_COUNT="2"
export KII_JOB_ID="1920bb26-dsee-dzfw-vdsdsa14fds4"
export KII_TUPLE_TYPE="BIT_GFP"
export KII_PLAYER_ENDPOINT_1="172.18.1.130:5000"
export KII_PLAYER_ENDPOINT_0="172.18.2.129:5000"

# Run make with SGX and RA_TYPE as build variables
make app dcap RA_TYPE=dcap

# Retrieve mr_enclave and mr_signer values from server.sig
output=$(gramine-sgx-sigstruct-view server.sig)
mr_enclave=$(echo "$output" | grep "mr_enclave" | awk '{print $2}')
mr_signer=$(echo "$output" | grep "mr_signer" | awk '{print $2}')

# Check if mr_enclave and mr_signer are correctly retrieved
if [ -z "$mr_enclave" ] || [ -z "$mr_signer" ]; then
    echo "Error: Could not retrieve mr_enclave or mr_signer from server.sig"
    exit 1
fi

# Set RA-TLS environment flags
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1

# Set required RA-TLS verification variables
export RA_TLS_MRSIGNER="$mr_signer"  
export RA_TLS_MRENCLAVE="$mr_enclave"            
export RA_TLS_ISV_SVN="any"
export RA_TLS_ISV_PROD_ID="any"

# Loop through each player in reverse order
for (( i = KII_PLAYER_COUNT - 1; i >= 0; i-- )); do
    echo "Starting server for player $i in the background (logging to player_${i}.log)..."

    # Export player-specific variables and start the player process in the background
    (   
        export KII_PLAYER_NUMBER=$i
        echo "Starting player $i with enclave mr_enclave: $mr_enclave and mr_signer: $mr_signer" > "player_${i}.log"
        gramine-sgx ./server "$mr_enclave" "$mr_signer" 0 0 >> "player_${i}.log" 2>&1
        echo "Player $i session complete." >> "player_${i}.log"
    ) &
done

echo "All player sessions have been started in the background. Check player logs (player_0.log, player_1.log, ...) for output."
