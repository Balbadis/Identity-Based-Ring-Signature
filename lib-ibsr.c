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
#include <pbc/pbc_field.h>
#include <pbc/pbc_pairing.h>
#include <stdint.h>


// ctx per hashing
ibsr_hashing_ctx ctx;

void ibsr_init_hash_tools(){
	ibsr_hashing_init(&ctx);
}

void __compute_user_pk_raw(uint8_t* user_pk_raw, entity_t entity){
	ibsr_hashing_update(&ctx,ID_LENGTH,entity->id);
	ibsr_hashing_digest(&ctx,user_pk_raw);
}

//ibsr shared params
void ibsr_init_shared_params(ibsr_shared_params_t params, pairing_ptr pairing, ring_ptr ring){
	if(!pairing_is_symmetric(pairing)){
		printf("Errore: il pairing non e' simmetrico.");
		exit(1);
	}

	params->pairing = pairing;
	params->ring = ring;

	pmesg(msg_verbose, "	Scelgo casualmente la mk e un generatore di G1, poi calcolo la pk...");
	element_init_Zr(params->mk, pairing);
	element_random(params->mk);


	// element_t temp; //VECCHIO PAIRING_PP_EL CHE ESISTEVA SOLTANTO ALL'INTERNO DI QUESTO SCOPE, FARE CIO' DAVA ERRORE IN PAIRING_PP_APPLY ALL'INTERNO DELLA FN __ibsr_generate_others_Ri_hi (ln.259)
	element_init_G1(params->pairing_pp_el, pairing);
	element_random(params->pairing_pp_el);
	pairing_pp_init(params->pairing_pp, params->pairing_pp_el, pairing);
	element_init_G1(params->pk, params->pairing); // la pk (=Y) viene utilizzata, insieme a -Y, soltanto per i pairing, bisognerebbe utilizzare pairing_pp_t per performance migliori?
	element_pow_zn(params->pk, params->pairing_pp_el, params->mk);
	pairing_pp_init(params->pk_pp, params->pk, pairing);
	// element_clear(temp); //vecchio clear del temp

	pmesg(msg_verbose, "	Calcolo le pk degli utenti (hashing)..."); // il processo piu' lento !!!
	params->user_pks = (element_t*) malloc(sizeof(element_t) * ring->length);
	params->user_pks_pp = (element_pp_t*) malloc(sizeof(element_pp_t) * ring->length);
	uint8_t user_pk_raw[ibsr_hashing_size];
	for(unsigned int i = 0; i < ring->length; i++){
		element_init_G1(params->user_pks[i], pairing );
		__compute_user_pk_raw(user_pk_raw, ring->entities[i]);
		element_from_hash(params->user_pks[i], user_pk_raw, ibsr_hashing_size);
		element_pp_init(params->user_pks_pp[i], params->user_pks[i]);
	}

}

void ibsr_clear_shared_params(ibsr_shared_params_t params){
	element_clear(params->pairing_pp_el);
	pairing_pp_clear(params->pairing_pp);
	element_clear(params->pk);
	pairing_pp_clear(params->pk_pp);
	element_clear(params->mk);

	for(unsigned int i = 0; i < params->ring->length; i++){
		element_clear(params->user_pks[i]);
		element_pp_clear(params->user_pks_pp[i]);
	}
	free(params->user_pks);
	free(params->user_pks_pp);
}

// funzioni di init, set e print per entity (id) e ring

void entity_set_id(entity_t entity, const uint8_t value[ID_LENGTH]){
	for(int i = 0; i <ID_LENGTH; i++){
		entity->id[i] = value[i];
	}
}

void __print_id_very_verbose(uint8_t id[ID_LENGTH], const bool use_index, const unsigned int index){
	if(use_index){
		printf("   Valore dell'id %u-esimo : ", index);
	} else {
		printf("   Valore dell'id: ");
	}

	for(int i=0; i < ID_LENGTH; i++){
		printf("%hhu ", id[i]);
	}
	printf("\n");
}

void ring_init(ring_t ring, const unsigned int ring_length){
	assert(ring);
	ring->entities = (entity_t*) malloc(sizeof(entity_t) * ring_length);
	ring->length = ring_length;
	ring->index = 0;
}

void ring_clear(ring_t ring){
	assert(ring);
	free(ring->entities);
}

unsigned int ring_add_id(ring_t ring, const uint8_t value[ID_LENGTH]){
	if(ring->index == ring->length){
		printf("No more space in the ring. \n");
		exit(1);
	}else{
		entity_set_id(ring->entities[ring->index], value);
		ring->index++;
	}
	return ring -> index;
}

void __print_ring_very_verbose(ring_t ring){
	if(get_messaging_level()!=msg_very_verbose){
		return;
	}
	printf("   Stampo il ring: \n");
	for(int i=0; i<ring->length; i++){
		__print_id_very_verbose(ring->entities[i]->id, true, i);
	}
}

// init della sign structure

void ibsr_sign_init(ibsr_sign_t signature, const ibsr_shared_params_t params){
	signature->R = (element_t*) malloc(sizeof(element_t) * params->ring->length);
	for(unsigned int i = 0; i < params->ring->length; i++){
		element_init_GT(signature->R[i], params->pairing );
	}

	signature->h = (element_t*) malloc(sizeof(element_t) * params->ring->length);
	for(unsigned int i = 0; i < params->ring->length; i ++){
		element_init_Zr(signature->h[i],params->pairing);
	}

	element_init_G1(signature->sigma, params->pairing);
}

void ibsr_sign_clear(ibsr_sign_t signature, const ibsr_shared_params_t params){
	for(unsigned int i = 0; i < params->ring->length; i++){
		element_clear(signature->R[i]);
	}
	free(signature->R);

	for(unsigned int i = 0; i < params->ring->length; i++){
		element_clear(signature->h[i]);
	}
	free(signature->h);

	element_clear(signature->sigma);
}

// generazione di ring casuali

void generate_random_id(uint8_t rop[ID_LENGTH]){
	for(int i=0; i <ID_LENGTH; i++){
		rop[i] = (uint8_t) rand();
	}
}

void generate_random_ring(ring_t ring){
	if(ring->length == 0){
		printf("Tried to generate ring of length 0 \n");
		exit(1);
	}
	if(ring->index != 0){
		pmesg(msg_verbose, "Sto sovrascrivendo un ring...");
	} else {
		srand(time(NULL)); // Usiamo qui il clock soltanto per generare ring di testing
	}
	uint8_t temp[ID_LENGTH];
	ring->index = 0;
	for(unsigned int i = 0; i < ring->length; i++){
		generate_random_id(temp);
		ring_add_id(ring, temp);
	}
	__print_ring_very_verbose(ring);
}

// Print per array di elements che salta un elemento dell'array (non ancora inizializzato o settato).

void __print_array_very_verbose(element_t* array, unsigned int ring_length, unsigned int index_to_skip){
	if(get_messaging_level() != msg_very_verbose){
		return;
	}
	printf("   Stampo il valore dell'array : \n");
	for(unsigned int i = 0; i <ring_length; i++)
	{
		if(i != index_to_skip){
			element_printf("   L'elemento %u -esimo e': %B \n", i, array[i]);
		} else {
			printf("   L'elemento %u -esimo viene saltato. \n", i);
		}
	}
}

// Genera un vettore random di elementi in G1 (nell'articolo "A"). bisogna fare il malloc dell'array PRIMA !!!

void __init_and_generate_random_vector_G1(element_t* array, ibsr_shared_params_t params, unsigned int index_to_skip){
	for(unsigned int i = 0; i < params->ring->length; i++){
		element_init_G1(array[i], params->pairing);
	}
	bool Ai_gen_success = false;
	unsigned int i = 0;
	unsigned int j;
	pmesg(msg_verbose, "	Genero casualmente i valori in A...");
	do {
		if(i == index_to_skip) {
			i++;
			continue;
		}
		j = 0;
		element_random(array[i]);
		Ai_gen_success = true;
		for(j=0; j < i; j++){
			if(element_cmp(array[i], array[j])==0){
				Ai_gen_success = false;
				break;
			}
		}
		if(Ai_gen_success){
			i++;
		}
	}while(i < params->ring->length);
	__print_array_very_verbose(array, params->ring->length, index_to_skip);
}

// bisogna fare il free del puntatore DOPO (se e' dinamico) !!!
void __array_clear_G1(element_t* array, unsigned int ring_length){
	for (unsigned int i=0; i<ring_length; i++ ) {
		element_clear(array[i]);
	}
}

// Calcolo R e h

void ibsr_sign_set_message(ibsr_sign_t signature, uint8_t* message, size_t message_size){
	signature->message = message;
	signature->message_size = message_size;
}

void __update_hash_ring_and_message(ibsr_hashing_ctx* hash_ctx_ptr, ring_t ring, uint8_t* message, size_t message_size)
	{
	for(unsigned int i = 0; i < ring ->length; i++){
		ibsr_hashing_update(hash_ctx_ptr, ID_LENGTH, ring->entities[i]->id);
	}
	ibsr_hashing_update(hash_ctx_ptr, message_size, message);
}

void __ibsr_generate_others_Ri_hi(ibsr_sign_t signature, element_t partial_sum_A, ibsr_shared_params_t params, unsigned int sender_index){
	element_t array_temp_G1[params->ring->length]; // = A
	__init_and_generate_random_vector_G1(array_temp_G1, params, sender_index);

	pmesg(msg_verbose,"	Calcolo i valori in R (tranne quello relativo a chi firma!) tramite pairing...");
	for(unsigned int i = 0; i < params->ring->length; i++){
		if(i != sender_index){

			// ATTENZIONE !!!
			// QUESTO DAVA ERRORE SE USATO CON PAIRING DI TYPE-E FACENDO IL CLEAR DELL'ELEMENT CHE DA' IL VALORE A PAIRING_PP
			pairing_pp_apply(signature->R[i], array_temp_G1[i] , params->pairing_pp );  // R_i = e(A,p)
		}
	}
	__print_array_very_verbose(signature->R, params->ring->length, sender_index);

	pmesg(msg_verbose, "	Calcolo i valori in h (tranne quello relativo a chi firma!) tramite hashing...");
	size_t element_GT_length_uint8 = pairing_length_in_bytes_GT(params->pairing);

	ibsr_hashing_ctx ctx_aux;
	ibsr_hashing_init(&ctx_aux);
	__update_hash_ring_and_message(&ctx, params->ring, signature->message, signature->message_size);
	ctx_aux = ctx;

	uint8_t R_i_raw[element_GT_length_uint8];
	uint8_t h_i_raw[ibsr_hashing_size];
	for(unsigned int i=0; i<params->ring->length; i++){
		if(i != sender_index){
			element_to_bytes(R_i_raw, signature->R[i]);
			ctx = ctx_aux;
			ibsr_hashing_update(&ctx, element_GT_length_uint8, R_i_raw);
			ibsr_hashing_digest(&ctx, h_i_raw);
			element_from_hash(signature->h[i], h_i_raw, ibsr_hashing_size);
		}
	}
	__print_array_very_verbose(signature->h, params->ring->length , sender_index );

	element_set0(partial_sum_A);
	for(unsigned int i = 0; i < params->ring->length; i++){
		if(i != sender_index){
			element_add(partial_sum_A, partial_sum_A, array_temp_G1[i]);
		}
	}
	__array_clear_G1(array_temp_G1, params->ring->length);
}

void __ibsr_generate_user_Ri_hi(ibsr_sign_t signature, element_t partial_sum_A, ibsr_shared_params_t params, const unsigned int sender_index){
	// Calcolo il fattore e(-pk, \sum(h_i user_pk_i))
	pmesg(msg_verbose, "	Calcolo il valore di fact2 = e(pk, -/sum_i h_i user_pk_i)...");
	element_t fact2;
	element_init_GT(fact2, params->pairing);

	element_t temp;
	element_init_G1(temp, params->pairing);

	element_t sum_temp;
	element_init_G1(sum_temp, params->pairing);
	element_set0(sum_temp);
	// sum_temp = \sum_(i!=s) h_i user_pks_i
	for(unsigned int i=0; i < params->ring->length; i++){
		if(i != sender_index){
			element_pp_pow_zn(temp, signature->h[i], params->user_pks_pp[i]);
			element_add(sum_temp, sum_temp, temp);
		}
	}

	element_neg(sum_temp,sum_temp);
	pairing_pp_apply(fact2, sum_temp, params->pk_pp);
	// element_pairing(fact2, temp, sum_temp);
	element_clear(sum_temp);
	pmesg_element(msg_very_verbose, "	valore di e(pk, -/sum_i h_i user_pk_i)", fact2);

	pmesg(msg_verbose, "	Cerco un valore casuale A_s che renda R_s ( = fact1 * fact2 ) accettabile...");
	bool success_flag;
	int n_iter = 0;
	element_t fact1;
	element_init_GT(fact1, params->pairing);
	do{
		element_random(temp); // ora temp = A_s
		//Calcolo il fattore e(A_s,P)
		pairing_pp_apply(fact1, temp, params->pairing_pp);
		pmesg(msg_very_verbose, "		Iterazione %d : calcolo fact1 = e(A_s,pp)...", n_iter + 1);
		element_mul(signature->R[sender_index], fact1, fact2);
		// check se R[sender_index] e' valido
		success_flag = true;
		if(element_is1(signature->R[sender_index])){
			success_flag = false;
			continue;
		}
		for(unsigned int i = 0; i < params->ring->length; i++){
			if(i == sender_index){
				continue;
			}
			if(element_cmp(signature->R[sender_index],signature->R[i])==0){
				success_flag = false;
				break;
			}
		}
		n_iter++;
	}while(!success_flag && n_iter<default_max_iterations);
	if(n_iter == default_max_iterations){
		printf("Errore: superato il numero massimo di iterazioni per generare R_s \n");
		exit(1);
	}
	pmesg_element(msg_very_verbose, "	valore di fact1 = e(A,pp) accettato",fact1);
	pmesg_element(msg_very_verbose, "	valore di R_s accettato", signature->R[sender_index]);

	element_clear(fact1);
	element_clear(fact2);

	pmesg(msg_verbose, "	Calcolo h_s = hash(ring, message, R_s)..."); // qui si potrebbe usare la funzione __update_hash_ring_and_message
	uint8_t* Rs_raw;
	uint8_t* hs_raw;
	Rs_raw = (uint8_t*) malloc(sizeof(uint8_t) * pairing_length_in_bytes_GT(params->pairing));
	hs_raw = (uint8_t*) malloc(sizeof(uint8_t) * ibsr_hashing_size);
	element_to_bytes(Rs_raw, signature->R[sender_index]);
	for(int j=0; j<params->ring->length; j++){
		ibsr_hashing_update(&ctx, ID_LENGTH, params->ring->entities[j]->id);
	}
	ibsr_hashing_update(&ctx, signature->message_size, signature->message);
	ibsr_hashing_update(&ctx, pairing_length_in_bytes_GT(params->pairing), Rs_raw);
	ibsr_hashing_digest(&ctx, hs_raw);
	element_from_hash(signature->h[sender_index], hs_raw, ibsr_hashing_size);
	free(Rs_raw);
	free(hs_raw);

	element_t sender_sk;
	element_init_G1(sender_sk,params->pairing);
	element_pp_pow_zn(sender_sk, params->mk, params->user_pks_pp[sender_index]); // questo dovrebbe essere fatto da un ente certicato esterno, che invia (in maniera sicura) la user_sk
	element_pow_zn(signature->sigma, sender_sk, signature->h[sender_index]); // = h_s * pk_s (Z_q * ecc)
	element_add(signature->sigma, signature->sigma, temp); // temp ha ancora il valore A_s !!!
	element_add(signature->sigma, signature->sigma, partial_sum_A);
	pmesg_element(msg_very_verbose, "	Valore di sigma ottenuto: ", signature->sigma);
	element_clear(sender_sk);
	element_clear(temp);
}

void ibsr_make_sign(ibsr_sign_t signature, ibsr_shared_params_t params, const unsigned int sender_index){
	element_t partial_sum_A;
	element_init_G1(partial_sum_A, params->pairing);
	__ibsr_generate_others_Ri_hi(signature, partial_sum_A, params, sender_index );
	__ibsr_generate_user_Ri_hi(signature, partial_sum_A, params, sender_index) ;
	element_clear(partial_sum_A);
}



bool verify_user_pks(ibsr_shared_params_t params){
	uint8_t user_pk_raw[ibsr_hashing_size];
	element_t temp;
	element_init_G1(temp, params->pairing);
	for(unsigned int i = 0; i < params->ring->length; i++){
		__compute_user_pk_raw(user_pk_raw, params->ring->entities[i]);
		element_from_hash(temp, user_pk_raw , ibsr_hashing_size );
		if(element_cmp(temp, params->user_pks[i])!=0){
			return false;
		}
	}
	element_clear(temp);
	return true;
}

bool verify_sigma(ibsr_sign_t signature, ibsr_shared_params_t params){
	// OTTIMIZZAZIONE!!! Nel calcolo del prodotto "infame" potrebbe essere meglio fare Y=pk pairing_pp e vedere la somma come prodotto e i prodotti esterni come esponenziazioni sul pairing !!!
	element_t prod_temp_GT, temp_GT;
	element_init_GT(temp_GT, params->pairing);
	element_init_GT(prod_temp_GT, params->pairing);

	element_set1(prod_temp_GT);

	element_t temp_G1, sum_temp_G1;
	element_init_G1(temp_G1, params->pairing);
	element_init_G1(sum_temp_G1, params->pairing);

	element_set0(sum_temp_G1);

	for(unsigned int i=0; i<params->ring->length; i++){
		element_mul(prod_temp_GT, prod_temp_GT, signature->R[i]); // prodotto di tutti gli R_i

		element_pp_pow_zn(temp_G1, signature->h[i], params->user_pks_pp[i]); // h_i pk_i (h_i in Z_r, pk_i in G1)
		element_add(sum_temp_G1, sum_temp_G1, temp_G1);  // somma di TUTTI i valori h_i pk_i
	}
	pairing_pp_apply(temp_GT, sum_temp_G1, params->pk_pp); // e(pk, /sum...)
	element_mul(temp_GT, prod_temp_GT, temp_GT);

	// riciclo prod_temp_GT
# define pairing_sigma_pp prod_temp_GT
	// pmesg_element(msg_verbose, "pairing_sigma_pp prima di riscriverlo", pairing_sigma_pp);
	pairing_pp_apply(pairing_sigma_pp, signature->sigma , params->pairing_pp);
	pmesg(msg_very_verbose,"	Verifico che valga l'equivalenza...");
	pmesg_element(msg_very_verbose, "	primo membro" , pairing_sigma_pp );
	pmesg_element(msg_very_verbose, "	secondo membro" , temp_GT );
	bool return_value;
	/*
	if(element_cmp(temp_GT, pairing_sigma_pp )==0){ // si poteva fare senza if, cosi sono più sicuro
		return_value = true;
	} else {
		return_value = false;
	}

	*/
	return_value = !element_cmp(temp_GT, pairing_sigma_pp);
	element_clear(temp_GT);
	element_clear(prod_temp_GT);
	element_clear(temp_G1);
	element_clear(sum_temp_G1);
	return return_value;
}

unsigned int __verify_hi(ibsr_sign_t signature, ibsr_shared_params_t params){
	__update_hash_ring_and_message(&ctx, params->ring, signature->message, signature->message_size);
	ibsr_hashing_ctx ctx_aux;
	ctx_aux = ctx;
	uint8_t Ri_raw[pairing_length_in_bytes_GT(params->pairing)];
	uint8_t hi_raw[ibsr_hashing_size];
	element_t temp;
	element_init_Zr(temp, params->pairing);
	for(unsigned int i=0; i < params->ring->length; i++){
		ctx = ctx_aux;
		element_to_bytes(Ri_raw, signature->R[i]);
		ibsr_hashing_update(&ctx, pairing_length_in_bytes_GT(params->pairing), Ri_raw);
		ibsr_hashing_digest(&ctx, hi_raw);
		element_from_hash(temp, hi_raw, ibsr_hashing_size);
		if(element_cmp(temp,signature->h[i])){
			return i;
		}
	}
	element_clear(temp);
	return params->ring->length;
}

void ibsr_verify_sign(ibsr_sign_t signature, ibsr_shared_params_t params){
	/*
	// verifica delle chiavi pubbliche, molto lenta come nella generazione delle chiavi pubbliche
	if(!verify_user_pks(params)){
		printf("Errore nella verifica delle chiavi pubbliche degli utenti! \n");
		exit(1);
	}
	*/
	unsigned int temp = __verify_hi(signature, params );
	if( temp != params->ring->length){
		printf("Il valore di h_i %u-esimo e' errato! \n",  temp);
		exit(1);
	}else{
		pmesg(msg_verbose, "	Valori h_i corretti!");
	}

	if(verify_sigma(signature,params)){
		pmesg(msg_verbose, "	Firma autenticata con successo!");
	}else{
		printf("La firma non è valida! \n");
		exit(1);
	}
}





