# IBSR: Identity-Based Signature Ring scheme in C

IBSR is a C library implementing the identity-based ring signature scheme
presented by Javier Herranz and Germán Sáez in
*"New Identity-Based Ring Signature Schemes"* ,
in the version where a single user computes the signature on behalf of the
ring they belong to (first scheme of the paper). The library relies on
[PBC](https://crypto.stanford.edu/pbc/) for (symmetric) pairings on elliptic
curves and on [Nettle](https://www.lysator.liu.se/~nisse/nettle/) for hashing.

> **Disclaimer:** educational implementation. It is not constant-time, has not
> been audited, and must not be used to protect real data. 

## What is a ring signature?

A ring signature lets one member of a set of users (the *ring*) sign a message
on behalf of the whole ring, without revealing which member signed. A verifier
can check that *someone in the ring* produced the signature, but not who.
Think of a hospital's stamp: it proves that a document comes from the
hospital, not from the person who used the stamp.

In the identity-based setting the ring is just a list of identities and public
keys are derived from them, so no certificates are needed.

## Features

IBSR can:

- generate rings of users (identities), including random ones
- sign arbitrary messages on behalf of a ring
- verify signatures

A test program, `test-utility.c`, is provided for testing and benchmarking.

## Dependencies

- PBC (pairing-based cryptography library)
- Nettle (SHA3-256)
- GMP

On Arch/EndeavourOS: `sudo pacman -S gmp nettle` 
                     `yay -S pbc`

## Build

```
make
```


## Using the library

Every structure must be initialized and then cleared when no longer needed,
using the corresponding functions. Initialization order: ring and pairing
(PBC), common parameters, signature.

A minimal signing example:

```c
ring_t ring;
ring_init(ring, 5);          // initialize an (empty) ring of 5 users
generate_random_ring(ring);  // fill the ring with random identities

// ... instantiate the PBC pairing here ...

ibsr_init_hash_tools();      // init the hash context used internally

ibsr_shared_params params;   // common parameters of the scheme
ibsr_init_shared_params(params, pairing, ring);
                             // the master key is chosen at random here

ibsr_sign_t sign;            // signature structure
ibsr_sign_init(sign, params);
ibsr_sign_set_message(sign, "TEST MESSAGE", 12);
                             // the message length must be passed explicitly

int sender_index = 0;
ibsr_make_sign(sign, params, sender_index);
                             // signs as the ring member with index sender_index
ibsr_verify_sign(sign, params);

// ... clear all structures ...
```

## Test program

After building, `test-utility` accepts the following arguments:

| Option | Description |
|---|---|
| `quiet` / `verbose` / `very-verbose` | Debug message level. **Warning:** use `very-verbose` only with very small rings, since it prints almost every computed value. |
| `bench` | Benchmark mode. Automatically sets the message level to `quiet` so that printing does not distort the timings. |
| `ring-length <n>` | Number of users in the randomly generated test ring. Default: 20. |
| `message-size <n>` | Size in bytes of the randomly generated test message. Default: 198. |
| `sec-level <n>` | Target security level, taken as the security of the discrete logarithm on the curve (half the bit size of G1). Default: 128. |
| `type-a` / `type-e` | Pairing type. The scheme only admits symmetric pairings. Default: `type-a`. |

For meaningful benchmark numbers, compile with optimizations (no debug flags).

Example output:

```
Calibrazione strumenti per il timing... 

Selezione parametri per curva/pairing con livello di sicurezza a 128 bit ...

Scelgo un messaggio casuale a 198-byte...

Inizializzo i parametri comuni...
        Scelgo casualmente la mk e un generatore di G1, poi calcolo la pk...
*** PBC asserts enabled: potential performance penalties ***
        Calcolo le pk degli utenti (hashing)...

Inizio il processo di firma...
        Genero casualmente i valori in A...
        Calcolo i valori in R (tranne quello relativo a chi firma!) tramite pairing...
        Calcolo i valori in h (tranne quello relativo a chi firma!) tramite hashing...
        Calcolo il valore di fact2 = e(pk, -/sum_i h_i user_pk_i)...
        Cerco un valore casuale A_s che renda R_s ( = fact1 * fact2 ) accettabile...
        Calcolo h_s = hash(ring, message, R_s)...

Inizio il processo di verifica della firma...
        Valori h_i corretti!
        Firma autenticata con successo!
```

## Benchmarks

Machine: [i5-12400F], pairing type: [type-a], security
level: [128].
Init refers to the initialization of the parameters of the whole ring.

| Ring size | Init (s) | Sign (ms) | Verify (ms) |
|---|---|---|
| 20 | 0.75 | 143 | 16 |
| 100 | 3.72 | 690 | 59 |

The benchmarks confirm that the complexity is somewhat linear in the size of the ring.
## Notes

### Hashing

SHA3-256 is used. Currently the only way to change the hash function is to
change the corresponding macros in the header.

### Possible optimization

Ideas that might speed up the code:

- When computing the signer's component of R and the verification value
  (paper, p. 31, step 3 of the pseudocode; and p. 32), the summation could be
  moved outside the pairing as a product. The public key Y (and its opposite)
  could then be handled as `pairing_pp_t` rather than `element_t`, allowing
  several pairings with precomputation.

### Memory leaks

Valgrind reports no leaks with `type-a` pairings. With `type-e`, it reports a
leak that seems to originate from PBC's `select_pbc_param_by_security_level`.

### Unexpected behavior in PBC (resolved)

When computing a pairing with precomputation, PBC provides the type
`pairing_pp_t`, initialized from an `element_t` whose value it copies.
Behavior differs by pairing type: with `type-a`, the `element_t` can be
cleared and `pairing_pp_t` used afterwards; with `type-e`, doing the same can
produce a null pairing value or a segmentation fault.

## License and credits

Copyright [2026] Nunzio Azzarello ([github.com/Balbadis](https://github.com/Balbadis)).
Released under the GNU General Public License, version 3 or later (see
`LICENSE`).

This project builds on the libraries by Mario Di Raimondo
(Copyright 2016, University of Catania), also distributed under the GNU GPL
v3 or later.

## Reference

J. Herranz, G. Sáez. *New Identity-Based Ring Signature Schemes.*
In: Information and Communications Security (ICICS 2004),
Lecture Notes in Computer Science, vol. 3269, Springer, 2004, pp. [27-39].
