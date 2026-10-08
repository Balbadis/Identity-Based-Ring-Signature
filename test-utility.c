/*
 * Copyright 2025 Nunzio Azzarello (https://github.com/Balbadis)
 *
 * Implementation of the first identity-based ring signature scheme of
 * Herranz and Sáez. Builds on the libraries by Mario Di Raimondo
 * (University of Catania).
 *
 * This source code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "lib-ibsr.h"
#include "lib-mesg.h"
#include "lib-misc.h"
#include "lib-timing.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <libgen.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// qui vanno i #define su costanti (livello di sicurezza, ecc...)
#define num_samples 20

#define default_sec_level 128

#define default_ring_length 20
#define default_random_message_length 198
#define default_pbc_pairing_type pbc_pairing_type_a

void info_pairing(pairing_t pairing) {
    if (pairing_is_symmetric(pairing))
        printf("pairing simmetrico\n");
    else
        printf("pairing asimmetrico\n");

    printf("dimensione elementi in G1: %d+1 bit\n",
           pairing_length_in_bytes_x_only_G1(pairing) * 8);
    printf("dimensione elementi in G2: %d+1 bit\n",
           pairing_length_in_bytes_x_only_G2(pairing) * 8);
    printf("dimensione elementi in Gt: %d bit\n",
           pairing_length_in_bytes_GT(pairing) * 8);
    printf("dimensione elementi in Zr: %d bit\n",
           pairing_length_in_bytes_Zr(pairing) * 8);
}

int main(int argc, char *argv[]) {
    // gmp_randstate_t prng;
    // gmp_randinit_default(prng); // init prng !!!
    // gmp_randseed_os_rng(prng, prng_sec_level);

    bool do_bench = false;
    unsigned int ring_length = default_ring_length ;
    size_t message_size = default_random_message_length;
    int sec_level = default_sec_level;
    pbc_pairing_type_t type = default_pbc_pairing_type;
    elapsed_time_t time;
    stats_t stats;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "very-verbose") == 0)
            set_messaging_level(msg_very_verbose);
        else if (strcmp(argv[i], "verbose") == 0)
            set_messaging_level(msg_verbose);
        else if (strcmp(argv[i], "quiet") == 0)
            set_messaging_level(msg_silence);
        else if (strcmp(argv[i], "bench") == 0) {
            do_bench = true;
        }
        else if(strcmp(argv[i], "ring-length") == 0){
            if(i+1 >= argc){
                printf("Argomento mancante! \n");
                exit(1);
            }
            ring_length = atoi(argv[i+1]); // in realtà è come se fosse int, taglia un bit
            i++;
        }
        else if (strcmp(argv[i], "message-size")==0){
            if(i+1>= argc){
                printf("Argomento mancante! \n");
                exit(1);
            }
            message_size = atoi(argv[i+1]);
            i++;
        }
        else if(strcmp(argv[i], "sec-level")==0){
            if(i+1 >= argc){
                printf("Argomento mancante!");
                exit(1);
            }
            sec_level = atoi(argv[i+1]);
            i++;
        }else if (strcmp(argv[i], "type-a")==0){
            printf("\nSelezione curva/pairing di tipo A (SS: "
            "Super-Singolari)\n");
            type = pbc_pairing_type_a;
        }else if (strcmp(argv[i], "type-e")==0){
            printf("\nSelezione curva/pairing di tipo E\n");
            type = pbc_pairing_type_e;
        } else {
            printf("utilizzo: %s [verbose|quiet] [ring-length <n>] [message-size] [bench]"
            " [sec-level] [type-a|type-e]\n",
            basename(argv[0]));
            exit(1);
        }
    }
    if(do_bench) {set_messaging_level(msg_silence);}

    printf("Calibrazione strumenti per il timing... \n");
    calibrate_timing_methods();

    ring_t ring;
    ring_init(ring,ring_length);
    generate_random_ring(ring);

    printf("\nSelezione parametri per curva/pairing con livello di sicurezza a "
    "%d bit ...\n",
    sec_level);
    pbc_param_t params;
    pairing_t pairing;
    perform_oneshot_cpu_time_sampling(time, tu_sec, {
        select_pbc_param_by_security_level(params, type,
                                           sec_level, NULL);
    });
    if (do_bench)
        printf_et(" select_pbc_param_by_security_level: ", time, tu_sec,
                  "\n");
    pairing_init_pbc_param(pairing, params);

    if(get_messaging_level()==msg_very_verbose){
        printf(" \nStampo le informazioni sul pairing:\n");
        info_pairing(pairing);
    }

    ibsr_init_hash_tools(); // fa init del ctx, NON HA BISOGNO DI CLEAR!

    // creo un messaggio casuale
    uint8_t message[message_size];
    printf("\nScelgo un messaggio casuale a %lu-byte...\n", message_size);
    for(int i =0; i<message_size; i++){
        message[i] = (uint8_t) rand();
    }
    if(get_messaging_level()==msg_very_verbose){
        for(int i =0; i<message_size; i++){
            printf(" %hhu ", message[i]);
        }
        printf("\n");
    }


    ibsr_shared_params_t shared_params;
    printf("\nInizializzo i parametri comuni...\n");
    perform_oneshot_cpu_time_sampling(time, tu_sec, {ibsr_init_shared_params(shared_params, pairing , ring);});
    if(do_bench)
        printf_et(" ibsr_init_shared_params: ", time, tu_sec, "\n");

    ibsr_sign_t signature;
    ibsr_sign_init(signature, shared_params);
    ibsr_sign_set_message(signature, message,  message_size);
    unsigned int sender_index = 0;

    printf("\nInizio il processo di firma...\n");
    perform_oneshot_cpu_time_sampling(time, tu_sec , {ibsr_make_sign(signature, shared_params , sender_index );} );
    if(do_bench)
        printf_et(" ibsr_make_sign : ", time, tu_sec, "\n");


    // element_random(signature->sigma); // mette una firma falsa (casuale)
    printf("\nInizio il processo di verifica della firma...\n");
    if(do_bench){
    perform_cpu_time_sampling(stats, NULL, num_samples , tu_sec,
                            {
                                  ibsr_verify_sign(signature, shared_params);
                            },
                            {});
    printf_stats( " cpu time of ibsr_verify_sign ", stats, "");
    } else {
        ibsr_verify_sign(signature, shared_params);
    }


    ibsr_sign_clear(signature, shared_params);
    ibsr_clear_shared_params(shared_params);

    pbc_param_clear(params);
    pairing_clear(pairing);

    ring_clear(ring);

    /*
    entity_t entity;
    uint8_t id[ID_LENGTH];
    generate_random_id(id);
    entity_set_id(entity, id);
    uint8_t digest[SHA256_DIGEST_SIZE];
    perform_hash1_sha256_id(digest,entity );
    for (int i =0; i <SHA256_DIGEST_SIZE; i++){
        printf(" %hhu ", digest[i]);
    }
    printf("\n");
    */



}
