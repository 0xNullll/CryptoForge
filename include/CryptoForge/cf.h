/*
 * CryptoForge - cf.h / Main API Public Header
 * Copyright (C) 2026 0xNullll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#ifndef CF_H
#define CF_H

/*
 * cf_flags.h
 *
 * Defines all flags used by the CryptoForge API layer. These include
 * descriptors for sizes, algorithm selections, and other configuration
 * options. Most API calls require including this file for flexible and
 * consistent function usage.
 */
#include <CryptoForge/cf_flags.h>

/*
 * cf_hash.h
 *
 * High-level hash API functions. Supported algorithms:
 *   - MD5
 *   - SHA-1
 *   - SHA-2 (224/256/384/512)
 *   - SHA-3 (224/256/384/512)
 *   - SHAKE / rawSHAKE / cSHAKE
 *
 * Provides memory-safe functions for hashing arbitrary data.
 */
#include <CryptoForge/cf_hash.h>

/*
 * cf_mac.h
 *
 * Message Authentication Code (MAC) implementations:
 *   - HMAC
 *   - KMAC / KMAC-XOF
 *   - Poly1305
 *   - CMAC
 *   - GMAC
 *
 * Ensures message integrity and authenticity.
 */
#include <CryptoForge/cf_mac.h>

/*
 * cf_kdf.h
 *
 * Key Derivation Functions (KDFs):
 *   - HKDF2
 *   - PBKDF2
 *   - KMAC-XOF (usable as a KDF)
 *
 * Derives secure keys from passwords or other secrets.
 */
#include <CryptoForge/cf_kdf.h>

/*
 * cf_cipher.h
 *
 * Symmetric cipher implementations:
 *   - AES (128/192/256) modes: ECB, CBC, CFB8, CFB128, OFB, CTR
 *   - ChaCha (8/12/20) key sizes: 128/256
 *   - XChaCha (8/12/20) key size: 256
 *
 * Provides encryption and decryption with memory safety.
 */
#include <CryptoForge/cf_cipher.h>

/*
 * cf_aead.h
 *
 * Authenticated encryption with associated data (AEAD):
 *   - AES-GCM (128/192/256)
 *   - ChaCha20-Poly1305
 *   - XChaCha20-Poly1305 (256-bit keys)
 *
 * Combines confidentiality and integrity in a single operation.
 */
#include <CryptoForge/cf_aead.h>

/*
 * cf_enc.h
 *
 * Encoding and decoding utilities:
 *   - Base16 (lower/upper)
 *   - Base32 (with/without padding)
 *   - Base58
 *   - Base64 (standard, no-pad, URL-safe)
 *   - Base85 (ASCII85, Extended ASCII85, optional 'y')
 *     - Optional subflag for Base85 to remove whitespace
 *
 * Converts binary data to textual representations and back.
 */
#include <CryptoForge/cf_enc.h>

/* Utility headers */
// #include "../utils/mem.h"
#include <CryptoForge/cf_status.h>
#include <CryptoForge/cf_defs.h>
// #include "../utils/misc.h"

/* Configuration header */
// #include "../config/crypto_config.h"

#endif // CF_H