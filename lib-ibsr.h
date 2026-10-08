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
#ifndef LIB_IBSR_H
#define LIB_IBSR_H

#include "lib-mesg.h"
#include "lib-misc.h"
#include <assert.h>
#include <gmp.h>
#include <pbc/pbc_field.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <stdbool.h>
#include <pbc/pbc.h>
#include <nettle/sha3.h>
#include <nettle/nettle-meta.h>

#define ID_LENGTH 32 // in bytes

// Parametri e funzioni per hashing

#define ibsr_hashing_ctx struct sha3_256_ctx
#define ibsr_hashing_init sha3_256_init
#define ibsr_hashing_update sha3_256_update
#define ibsr_hashing_digest sha3_256_digest
#define ibsr_hashing_size SHA3_256_DIGEST_SIZE

// numero massimo di iterazioni per evitare cicli infiniti

#define default_max_iterations 1000

struct entity_struct{
	uint8_t id[ID_LENGTH];
};
typedef struct entity_struct entity_t[1]; // non posso chiamarlo: id_t
void entity_set_id(entity_t entity, const uint8_t value[ID_LENGTH]);
void generate_random_id(uint8_t rop[ID_LENGTH]);
// void perform_hash1_sha256_id(uint8_t digest[ibsr_hashing_size],entity_t entity);

struct ring_struct {
	unsigned int length;
	unsigned int index;
	entity_t* entities;
};
typedef struct ring_struct* ring_ptr;
typedef struct ring_struct ring_t[1];
void ring_init(ring_t ring, unsigned int ring_length);
void ring_clear(ring_t ring);
unsigned int ring_add_id(ring_t ring, const uint8_t value[ID_LENGTH]);
void generate_random_ring(ring_t ring);
void print_ring(ring_t ring);

struct ibsr_shared_params_struct{
	pairing_ptr pairing;
	element_t pairing_pp_el; // il valore che viene assegnato a pairing_pp per fare pairing con pre-computazione
	// ATTENZIONE !!! Si aggiunge qui pairing_pp_el perché, soltanto nel caso di curve type-e, utilizzare pairing_pp dopo aver fatto il clear dell'elemento che gli da' valore (pairing_pp_el) da' errore di segmentazione
	// Guarda ibsr_init_shared_params in lib-utility.c, ln. 36
	pairing_pp_t pairing_pp;
	ring_ptr ring;
	element_t pk;
	pairing_pp_t pk_pp;
	element_t* user_pks;
	element_pp_t* user_pks_pp;

	// Privato!
	element_t mk;
};
typedef struct ibsr_shared_params_struct ibsr_shared_params_t[1];
void ibsr_init_shared_params(ibsr_shared_params_t params, pairing_ptr pairing, ring_ptr ring);
void ibsr_clear_shared_params(ibsr_shared_params_t params);

struct ibsr_sign_struct{
	uint8_t* message;
	size_t message_size;
	element_t* R;
	element_t* h;
	element_t sigma;
};
typedef struct ibsr_sign_struct ibsr_sign_t[1];
// Manca init per la pk!
void ibsr_sign_init(ibsr_sign_t sign, const ibsr_shared_params_t params);
void ibsr_sign_set_message(ibsr_sign_t signature, uint8_t* message, size_t message_size);
void ibsr_sign_clear(ibsr_sign_t sign, const ibsr_shared_params_t params);


/*
void init_generate_master_key(pairing_t pairing);
void clear_mk();
void init_gen_pp(pairing_t pairing);
void clear_pp();
*/

void ibsr_init_hash_tools();
void ibsr_make_sign(ibsr_sign_t signature, ibsr_shared_params_t params, const unsigned int sender_index);
void ibsr_verify_sign(ibsr_sign_t signature, ibsr_shared_params_t params);





#endif  /* LIB_IBSR_H*/
