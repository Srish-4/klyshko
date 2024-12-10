#!/bin/bash

if [ -f "kii_0.log" ]; then
    rm "kii_0.log"
    echo "File removed successfully."
else
    echo "File does not exist."
fi

if [ -f "kii_1.log" ]; then
    rm "kii_1.log"
    echo "File removed successfully."
else
    echo "File does not exist."
fi

rm -r Player-Data
mkdir Player-Data
cd Player-Data
mkdir 2-2-40
mkdir 2-p-128
cd ..

# Configuration Variables
export KII_TUPLES_PER_JOB="100000"
export KII_SHARED_FOLDER="/kii"
export KII_TUPLE_FILE="/kii/tuples"
export KII_PLAYER_COUNT="2"
export KII_JOB_ID="1920bb26-dsee-dzfw-vdsdsa14fds4"
export KII_TUPLE_TYPE="BIT_GFP"
export KII_PLAYER_ENDPOINT_1="127.0.0.1:1025"
export KII_PLAYER_ENDPOINT_0="127.0.0.1:1026"
export BASE_PORT="4433"

# Run make with SGX and RA_TYPE as build variables
make app RA_TYPE=dcap

# Retrieve mr_enclave and mr_signer values from server.sig
output=$(gramine-sgx-sigstruct-view server.sig)
mr_enclave=$(echo "$output" | grep "mr_enclave" | awk '{print $2}')
mr_signer=$(echo "$output" | grep "mr_signer" | awk '{print $2}')

echo "mr_enclave: $mr_enclave, mr_signer: $mr_signer, i: $i"

# output=$(gramine-sgx-sigstruct-view server.sig)
# mr_enclave=$(echo "$output" | grep "mr_enclave" | awk '{print $2}')
# mr_signer=$(echo "$output" | grep "mr_signer" | awk '{print $2}')

# Check if mr_enclave and mr_signer are correctly retrieved
if [ -z "$mr_enclave" ] || [ -z "$mr_signer" ]; then
    echo "Error: Could not retrieve mr_enclave or mr_signer from server.sig"
    exit 1
fi

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
        export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
        export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
        export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
        export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
        echo "Starting player $i with enclave mr_enclave: $mr_enclave and mr_signer: $mr_signer" > "player_${i}.log"
        
        # Run the compiled executable for each player
        gramine-sgx ./server "$mr_enclave" "$mr_signer" 0 0 >> "player_${i}.log" 2>&1 &

        ./KII "$mr_enclave" "$mr_signer" 0 0 $i >> "kii_${i}.log" 2>&1 &
        echo "Player $i session complete." >> "player_${i}.log"
    ) &
done

echo "All player sessions have been started in the background. Check player logs (player_0.log, player_1.log, ...) for output."


#./KII 6a37872a70cd68dffe3a2e9df1c9a8c7b4545ba829f999cf807de13475dcaf7f 22266b0bd0169b26a1e2b2c5a3c5b5471b0454bb01d8ec57e76d38cf7ed484f2 0 0 1