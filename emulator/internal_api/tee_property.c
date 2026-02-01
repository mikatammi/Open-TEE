/*****************************************************************************
** Copyright (C) 2026 Mika Tammi                                            **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

/* Implementation of Property Access Functions from TEE Internal Core API Specification v1.4.
 *
 * Description of the design: There are statically coded lookup tables for each of the property
 * sets. This kind of table maps the strings of the properties to a type and corresponding getter
 * function pointer. The string is matched from one of the tables, and then the function behind the
 * pointer actually sets the value user requested. */

#include "tee_property.h"
#include "tee_panic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This relies on glibc's endian.h, some other libc implementations like those on BSDs or Android
 * might need sys/endian.h */
#include <endian.h>

#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>

#include <unistd.h>

enum OT_TEE_PropType {
	OT_TEE_PROPTYPE_STRING,
	OT_TEE_PROPTYPE_BINARY,
	OT_TEE_PROPTYPE_INTEGER,
	OT_TEE_PROPTYPE_BOOLEAN,
	OT_TEE_PROPTYPE_UUID,
	OT_TEE_PROPTYPE_IDENTITY,
};

struct OT_TEE_Property {
	const char *name;
	enum OT_TEE_PropType type;
	union {
		TEE_Result (*string)(char *buf, size_t *len);
		TEE_Result (*binary)(void *buf, size_t *len);
		TEE_Result (*integer)(uint64_t *);
		TEE_Result (*boolean)(bool *);
		TEE_Result (*uuid)(TEE_UUID *);
		TEE_Result (*identity)(TEE_Identity *);
	} f;
};

static TEE_Result update_len_then_strncpy(char *dest, size_t *dest_len, const char *src,
					  const size_t src_len)
{
	const size_t orig_len = *dest_len;

	*dest_len = src_len;
	if (orig_len < *dest_len)
		return TEE_ERROR_SHORT_BUFFER;

	strncpy(dest, src, orig_len);

	return TEE_SUCCESS;
}

static TEE_Result not_implemented_string(char *buf, size_t *len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result not_implemented_binary(void *buf, size_t *len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result not_implemented_integer(uint64_t *i) { return TEE_ERROR_NOT_IMPLEMENTED; }

static TEE_Result not_implemented_boolean(bool *b) { return TEE_ERROR_NOT_IMPLEMENTED; }

static TEE_Result not_implemented_uuid(TEE_UUID *uuid) { return TEE_ERROR_NOT_IMPLEMENTED; }

static TEE_Result not_implemented_identity(TEE_Identity *identity)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result gpd_ta_endian(uint64_t *endian)
{
	/* This relies on glibc's endian.h */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	*endian = 0;
	return TEE_SUCCESS;
#elif __BYTE_ORDER == __BIG_ENDIAN
	*endian = 1;
	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

static TEE_Result gpd_ta_doesNotCloseHandleOnCorruptObject(bool *b)
{
	/* TODO: Implement properly when those TODOs from opentee_manager_storage_api.c around
	 * places returning TEE_ERROR_CORRUPT_OBJECT have been done. There are TODOs for deleting
	 * and closing object if it is corrupt. Currently it does neither delete or close the
	 * object. */
	*b = false;
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result gpd_client_identity(TEE_Identity *identity)
{
	/* TODO: Implement properly, libtee/src/tee_client_api.c requires this to be LOGIN_PUBLIC
	 * for now, however this is only for client side connections, TAs can also connect to TAs.
	 */
	/* TODO: With TA -> TA connections, this should be TEE_LOGIN_TRUSTED_APP */
	identity->login = TEE_LOGIN_PUBLIC;
	const TEE_UUID uuid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
	identity->uuid = uuid;

	return TEE_SUCCESS;
}

static TEE_Result gpd_client_endian(uint64_t *endian)
{
	/* Assume Client is going to have the same endianness than TA for now. If it is really going
	 * to be different some day, then proper implementation should be to change the client
	 * protocol in libtee, so that the client reports its endianness while setting up the
	 * connection. */
	return gpd_ta_endian(endian);
}

static TEE_Result gpd_client_pathHash(void *buf, size_t *len)
{
	/* TODO: Implement properly later, now need just some binary function for testing */
	const size_t min_size = 256 / 8;
	const size_t orig_len = *len;

	*len = min_size;
	if (orig_len < min_size)
		return TEE_ERROR_SHORT_BUFFER;

	for (size_t i = 0; i < min_size; ++i) {
		((unsigned char *)buf)[i] = (unsigned char)i;
	}

	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_apiversion(char *buf, size_t *len)
{
	/* Setting this to version 1.1 for now */
	const char *apiversion = "1.1";
	return update_len_then_strncpy(buf, len, apiversion, sizeof(apiversion));
}

static TEE_Result gpd_tee_internalCore_version(uint64_t *i)
{
	/* Setting this to version 1.1 for now */
	*i = 0x01010000;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_description(char *buf, size_t *len)
{
	const char *description = "Open-TEE";
	return update_len_then_strncpy(buf, len, description, sizeof(description));
}

static TEE_Result gpd_tee_deviceID(TEE_UUID *u)
{
	const TEE_UUID uuid = {gethostid(), 0, 0, {'O', 'P', 'E', 'N', '-', 'T', 'E', 'E'}};
	*u = uuid;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_name(char *buf, size_t *len)
{
	/* Empty string, libtee does not use the TEEC_InitalizeContext's name-argument in any way */
	if (*len > 0)
		/* If there is space in buffer, insert terminating NULL character just in case */
		buf[0] = '\0';
	*len = 0;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_arith_maxBigIntSize(uint64_t *i)
{
	*i = MBEDTLS_MPI_MAX_BITS;
	return TEE_SUCCESS;
}

/* NOTE: For these cryptography related properties, false is currently the correct result, even
 * though the TEE_IsAlgorithmSupported function is not implemented yet. TEE Internal Core API
 * Specification v1.4 section 6.10.3 Optional Cryptographic Elements specifies these groups. */
static TEE_Result gpd_tee_cryptography_ecc(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_nist(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_bsi_r(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_bsi_t(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_ietf(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_octa(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_sec(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_falcon(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_NISTpqc_crystals(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_SLHDSA(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_statefulVerification(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_statefulSignatures(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_FrodoKEM(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_NTRU(bool *b)
{
	/* TODO: Use TEE_IsAlgorithmSupported here */
	*b = false;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_cryptography_maxRetainedData(uint64_t *i)
{
	/* TODO: The amount of extra data, in bytes, that a call to TEE_CipherUpdate will return
	 * beyond that provided. Check if it is possible to get this information from mbedTLS. */
	*i = 0;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedStorage_private_rollbackProtection(uint64_t *i)
{
	*i = 100;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedStorage_perso_rollbackProtection(uint64_t *i)
{
	*i = 100;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedStorage_protected_rollbackProtection(uint64_t *i)
{
	*i = 10000;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedStorage_antiRollback_protectionLevel(uint64_t *i)
{
	*i = 100;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedStorage_rollbackDetection_protectionLevel(uint64_t *i)
{
	*i = 100;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedos_implementation_version(char *buf, size_t *len)
{
	const char *v = "0.1";
	return update_len_then_strncpy(buf, len, v, sizeof(v));
}

static TEE_Result gpd_tee_trustedos_implementation_binaryversion(void *buf, size_t *len)
{
	const size_t orig_len = *len;
	const char v[] = {0x00, 0x00, 0x01, 0x00};

	*len = sizeof(v);
	if (orig_len < *len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(buf, v, sizeof(v));

	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_trustedos_manufacturer(char *buf, size_t *len)
{
	const char *v = "The Open-TEE Project";
	return update_len_then_strncpy(buf, len, v, sizeof(v));
}

static TEE_Result gpd_tee_firmware_implementation_version(char *buf, size_t *len)
{
	const char *v = "0.1";
	return update_len_then_strncpy(buf, len, v, sizeof(v));
}

static TEE_Result gpd_tee_firmware_implementation_binaryversion(void *buf, size_t *len)
{
	const size_t orig_len = *len;
	const char v[] = {0x00, 0x00, 0x01, 0x00};

	*len = sizeof(v);
	if (orig_len < *len)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(buf, v, sizeof(v));

	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_firmware_manufacturer(char *buf, size_t *len)
{
	const char *v = "The Open-TEE Project";
	return update_len_then_strncpy(buf, len, v, sizeof(v));
}

static TEE_Result gpd_tee_event_maxSources(uint64_t *i)
{
	/* TODO: Implement this when implementing Event API, 0 is correct for now as not even
	 * implementation of the API exists yet. */
	*i = 0;
	return TEE_SUCCESS;
}

static TEE_Result gpd_tee_maskState(bool *b)
{
	/* TODO: Implement TEE_MaskPanics properly. */
	*b = false;
	return TEE_SUCCESS;
}

struct OT_TEE_Property TA_Properties[] = {
    {"gpd.ta.appID", OT_TEE_PROPTYPE_UUID, .f.uuid = &not_implemented_uuid},
    {"gpd.ta.singleInstance", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &not_implemented_boolean},
    {"gpd.ta.multiSession", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &not_implemented_boolean},
    {"gpd.ta.instanceKeepAlive", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &not_implemented_boolean},
    {"gpd.ta.dataSize", OT_TEE_PROPTYPE_INTEGER, .f.integer = &not_implemented_integer},
    {"gpd.ta.stackSize", OT_TEE_PROPTYPE_INTEGER, .f.integer = &not_implemented_integer},
    {"gpd.ta.version", OT_TEE_PROPTYPE_STRING, .f.string = &not_implemented_string},
    {"gpd.ta.description", OT_TEE_PROPTYPE_STRING, .f.string = &not_implemented_string},
    {"gpd.ta.endian", OT_TEE_PROPTYPE_INTEGER, .f.integer = &gpd_ta_endian},
    {"gpd.ta.doesNotCloseHandleOnCorruptObject", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_ta_doesNotCloseHandleOnCorruptObject},
};

const size_t TA_Properties_Count = sizeof(TA_Properties) / sizeof(struct OT_TEE_Property);

struct OT_TEE_Property Client_Properties[] = {
    {"gpd.client.identity", OT_TEE_PROPTYPE_IDENTITY, .f.identity = &gpd_client_identity},
    {"gpd.client.endian", OT_TEE_PROPTYPE_INTEGER, .f.integer = &gpd_client_endian},
    {"gpd.client.pathHash", OT_TEE_PROPTYPE_BINARY, .f.binary = &gpd_client_pathHash},
    {"gpd.client.path", OT_TEE_PROPTYPE_BINARY, .f.binary = &not_implemented_binary},
};

const size_t Client_Properties_Count = sizeof(Client_Properties) / sizeof(struct OT_TEE_Property);

struct OT_TEE_Property Implementation_Properties[] = {
    {"gpd.tee.apiversion", OT_TEE_PROPTYPE_STRING, .f.string = &gpd_tee_apiversion},
    {"gpd.tee.internalCore.version", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_internalCore_version},
    {"gpd.tee.description", OT_TEE_PROPTYPE_STRING, .f.string = &gpd_tee_description},
    {"gpd.tee.deviceID", OT_TEE_PROPTYPE_UUID, .f.uuid = &gpd_tee_deviceID},
    {"gpd.tee.name", OT_TEE_PROPTYPE_STRING, .f.string = &gpd_tee_name},
    {"gpd.tee.implementationStackHash", OT_TEE_PROPTYPE_BINARY,
     .f.binary = &not_implemented_binary},
    {"gpd.tee.implementationStack", OT_TEE_PROPTYPE_BINARY, .f.binary = &not_implemented_binary},
    {"gpd.tee.systemTime.protectionLevel", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &not_implemented_integer},
    {"gpd.tee.TAPersistentTime.protectionLevel", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &not_implemented_integer},
    {"gpd.tee.arith.maxBigIntSize", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_arith_maxBigIntSize},
    {"gpd.tee.cryptography.ecc", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_ecc},
    {"gpd.tee.cryptography.nist", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_nist},
    {"gpd.tee.cryptography.bsi-r", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_bsi_r},
    {"gpd.tee.cryptography.bsi-t", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_bsi_t},
    {"gpd.tee.cryptography.ietf", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_ietf},
    {"gpd.tee.cryptography.octa", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_octa},
    {"gpd.tee.cryptography.sec", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_sec},
    {"gpd.tee.cryptography.falcon", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_falcon},
    {"gpd.tee.cryptography.NISTpqc.crystals", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_NISTpqc_crystals},
    {"gpd.tee.cryptography.NISTpqc.SLHDSA", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_SLHDSA},
    {"gpd.tee.cryptography.statefulVerification", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_statefulVerification},
    {"gpd.tee.cryptography.statefulSignatures", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_statefulSignatures},
    {"gpd.tee.cryptography.FrodoKEM", OT_TEE_PROPTYPE_BOOLEAN,
     .f.boolean = &gpd_tee_cryptography_FrodoKEM},
    {"gpd.tee.cryptography.NTRU", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_cryptography_NTRU},
    {"gpd.tee.cryptography.maxRetainedData", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_cryptography_maxRetainedData},
    {"gpd.tee.trustedStorage.private.rollbackProtection", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_trustedStorage_private_rollbackProtection},
    {"gpd.tee.trustedStorage.perso.rollbackProtection", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_trustedStorage_perso_rollbackProtection},
    {"gpd.tee.trustedStorage.protected.rollbackProtection", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_trustedStorage_protected_rollbackProtection},
    {"gpd.tee.trustedStorage.antiRollback.protectionLevel", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_trustedStorage_antiRollback_protectionLevel},
    {"gpd.tee.trustedStorage.rollbackDetection.protectionLevel", OT_TEE_PROPTYPE_INTEGER,
     .f.integer = &gpd_tee_trustedStorage_rollbackDetection_protectionLevel},
    {"gpd.tee.trustedos.implementation.version", OT_TEE_PROPTYPE_STRING,
     .f.string = &gpd_tee_trustedos_implementation_version},
    {"gpd.tee.trustedos.implementation.binaryversion", OT_TEE_PROPTYPE_BINARY,
     .f.binary = &gpd_tee_trustedos_implementation_binaryversion},
    {"gpd.tee.trustedos.manufacturer", OT_TEE_PROPTYPE_STRING,
     .f.string = &gpd_tee_trustedos_manufacturer},
    {"gpd.tee.firmware.implementation.version", OT_TEE_PROPTYPE_STRING,
     .f.string = &gpd_tee_firmware_implementation_version},
    {"gpd.tee.firmware.implementation.binaryversion", OT_TEE_PROPTYPE_BINARY,
     .f.binary = &gpd_tee_firmware_implementation_binaryversion},
    {"gpd.tee.firmware.manufacturer", OT_TEE_PROPTYPE_STRING,
     .f.string = &gpd_tee_firmware_manufacturer},
    {"gpd.tee.event.maxSources", OT_TEE_PROPTYPE_INTEGER, .f.integer = &gpd_tee_event_maxSources},
    {"gpd.tee.maskState", OT_TEE_PROPTYPE_BOOLEAN, .f.boolean = &gpd_tee_maskState},
};

const size_t Implementation_Properties_Count =
    sizeof(Implementation_Properties) / sizeof(struct OT_TEE_Property);

struct OT_TEE_PropSetHandle {
	TEE_PropSetHandle propset;
	size_t index;
};

static TEE_Result find_property(struct OT_TEE_Property **p, TEE_PropSetHandle propsetOrEnumerator,
				const char *name)
{
	bool is_enumerator = false;
	TEE_PropSetHandle source = NULL;
	struct OT_TEE_Property *props = NULL;
	size_t props_len = 0;

	if (p == NULL || propsetOrEnumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	is_enumerator = propsetOrEnumerator != TEE_PROPSET_CURRENT_TA &&
			propsetOrEnumerator != TEE_PROPSET_CURRENT_CLIENT &&
			propsetOrEnumerator != TEE_PROPSET_TEE_IMPLEMENTATION;

	source = is_enumerator ? propsetOrEnumerator->propset : propsetOrEnumerator;

	if (source != TEE_PROPSET_CURRENT_TA && source != TEE_PROPSET_CURRENT_CLIENT &&
	    source != TEE_PROPSET_TEE_IMPLEMENTATION)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	props = source == TEE_PROPSET_CURRENT_TA	   ? TA_Properties
		: source == TEE_PROPSET_CURRENT_CLIENT	   ? Client_Properties
		: source == TEE_PROPSET_TEE_IMPLEMENTATION ? Implementation_Properties
							   : NULL;
	props_len = source == TEE_PROPSET_CURRENT_TA	       ? TA_Properties_Count
		    : source == TEE_PROPSET_CURRENT_CLIENT     ? Client_Properties_Count
		    : source == TEE_PROPSET_TEE_IMPLEMENTATION ? Implementation_Properties_Count
							       : 0;

	if (is_enumerator) {
		if (propsetOrEnumerator->index >= props_len)
			return TEE_ERROR_ITEM_NOT_FOUND;
		*p = &(props[propsetOrEnumerator->index]);
		return TEE_SUCCESS;
	} else {
		if (name == NULL)
			return TEE_ERROR_ITEM_NOT_FOUND;
		for (size_t i = 0; i < props_len; ++i) {
			if (strcmp(props[i].name, name) == 0) {
				*p = &(props[i]);
				return TEE_SUCCESS;
			}
		}
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result OT_UUIDAsString(char *buf, size_t *len, TEE_UUID u)
{
	TEE_Result ret;
	const char *fmt = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x";
	const size_t uuid_string_len = 37;
	const size_t orig_len = *len;

	*len = uuid_string_len;

	if (orig_len < uuid_string_len)
		return TEE_ERROR_SHORT_BUFFER;

	ret = snprintf(buf, orig_len, fmt, u.timeLow, u.timeMid, u.timeHiAndVersion,
		       u.clockSeqAndNode[0], u.clockSeqAndNode[1], u.clockSeqAndNode[2],
		       u.clockSeqAndNode[3], u.clockSeqAndNode[4], u.clockSeqAndNode[5],
		       u.clockSeqAndNode[6], u.clockSeqAndNode[7]);
	if (ret < 0)
		TEE_Panic(TEE_ERROR_GENERIC);

	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				   char *valueBuffer, size_t *valueBufferLen)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (valueBuffer == NULL || valueBufferLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type == OT_TEE_PROPTYPE_STRING)
		return p->f.string(valueBuffer, valueBufferLen);
	else if (p->type == OT_TEE_PROPTYPE_BINARY) {
		size_t tmp_buf_len = 1;
		char *tmp_buf = calloc(1, tmp_buf_len);
		if (tmp_buf == NULL)
			TEE_Panic(TEE_ERROR_OUT_OF_MEMORY);

		// Try to get binary into temporary buffer. If it does not fit,
		// the tmp_buf_len should now contain the amount of bytes to
		// allocate.
		ret = p->f.binary(tmp_buf, &tmp_buf_len);
		if (ret == TEE_ERROR_SHORT_BUFFER) {
			// Try to realloc
			char *new_tmp_buf = realloc(tmp_buf, tmp_buf_len);
			if (new_tmp_buf == NULL)
				goto err_binary;
			tmp_buf = new_tmp_buf;

			// Try to get binary into temporary buffer again
			ret = p->f.binary(tmp_buf, &tmp_buf_len);
			if (ret != TEE_SUCCESS)
				goto err_binary;
		} else if (ret != TEE_SUCCESS)
			goto err_binary;

		ret = mbedtls_base64_encode(valueBuffer, *valueBufferLen, valueBufferLen, tmp_buf,
					    tmp_buf_len);
		if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
			ret = TEE_ERROR_SHORT_BUFFER;
	err_binary:
		free(tmp_buf);
		return ret;
	} else if (p->type == OT_TEE_PROPTYPE_INTEGER) {
		uint64_t val;
		size_t orig_len = *valueBufferLen;
		// 20 bytes is enough to represent largest uint64_t number as a string.
		char tmp_buf[22];

		ret = p->f.integer(&val);
		if (ret != TEE_SUCCESS)
			return ret;

		ret = snprintf(tmp_buf, sizeof(tmp_buf), "%lu", val);
		if (ret < 0)
			TEE_Panic(TEE_ERROR_GENERIC);

		*valueBufferLen = strnlen(tmp_buf, sizeof(tmp_buf)) + 1;
		if (orig_len < *valueBufferLen)
			return TEE_ERROR_SHORT_BUFFER;
		strncpy(valueBuffer, tmp_buf, orig_len);

		return TEE_SUCCESS;
	} else if (p->type == OT_TEE_PROPTYPE_BOOLEAN) {
		bool val;
		const char *false_as_string = "false";
		const char *true_as_string = "true";
		const size_t orig_len = *valueBufferLen;

		ret = p->f.boolean(&val);
		if (ret != TEE_SUCCESS)
			return ret;

		const char *val_as_string = val ? true_as_string : false_as_string;
		*valueBufferLen = strlen(val_as_string) + 1;

		if (orig_len < *valueBufferLen)
			return TEE_ERROR_SHORT_BUFFER;

		strncpy(valueBuffer, val_as_string, orig_len);

		return TEE_SUCCESS;
	} else if (p->type == OT_TEE_PROPTYPE_UUID) {
		TEE_UUID u;

		ret = p->f.uuid(&u);
		if (ret != TEE_SUCCESS)
			return ret;

		ret = OT_UUIDAsString(valueBuffer, valueBufferLen, u);

		return ret;
	} else if (p->type == OT_TEE_PROPTYPE_IDENTITY) {
		TEE_Identity identity;
		const char *fmt = "%u:%s";
		size_t uuid_string_len = 37;
		char uuid_str[uuid_string_len];

		/* tmp_buf_len = uuid_string_len + ':' + length of maximum uint32 string */
		size_t tmp_buf_len = uuid_string_len + 1 + 10;
		char tmp_buf[tmp_buf_len];

		const size_t orig_len = *valueBufferLen;

		ret = p->f.identity(&identity);
		if (ret != TEE_SUCCESS)
			return ret;

		ret = OT_UUIDAsString(uuid_str, &uuid_string_len, identity.uuid);
		if (ret != TEE_SUCCESS)
			return ret;

		ret = snprintf(tmp_buf, tmp_buf_len, fmt, identity.login, uuid_str);
		if (ret < 0)
			TEE_Panic(TEE_ERROR_GENERIC);

		*valueBufferLen = strnlen(tmp_buf, tmp_buf_len) + 1;
		if (orig_len < *valueBufferLen)
			return TEE_ERROR_SHORT_BUFFER;

		strncpy(valueBuffer, tmp_buf, orig_len);

		return TEE_SUCCESS;
	}
	TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				 bool *value)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (value == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type != OT_TEE_PROPTYPE_BOOLEAN)
		return TEE_ERROR_BAD_FORMAT;

	return p->f.boolean(value);
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				uint32_t *value)
{
	TEE_Result ret;
	uint64_t value64 = 0;

	if (value == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = TEE_GetPropertyAsU64(propsetOrEnumerator, name, &value64);
	if (ret != TEE_SUCCESS)
		return ret;

	*value = (uint32_t)value64;
	if (value64 > UINT32_MAX)
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU64(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				uint64_t *value)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (value == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type != OT_TEE_PROPTYPE_INTEGER)
		return TEE_ERROR_BAD_FORMAT;

	return p->f.integer(value);
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator, const char *name,
					void *valueBuffer, size_t *valueBufferLen)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (valueBuffer == NULL || valueBufferLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type != OT_TEE_PROPTYPE_BINARY)
		return TEE_ERROR_BAD_FORMAT;

	return p->f.binary(valueBuffer, valueBufferLen);
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				 TEE_UUID *value)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (value == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type != OT_TEE_PROPTYPE_UUID)
		return TEE_ERROR_BAD_FORMAT;

	return p->f.uuid(value);
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator, const char *name,
				     TEE_Identity *value)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;

	if (value == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, propsetOrEnumerator, name);
	if (ret != TEE_SUCCESS)
		return ret;
	if (p->type != OT_TEE_PROPTYPE_IDENTITY)
		return TEE_ERROR_BAD_FORMAT;

	return p->f.identity(value);
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
	struct OT_TEE_PropSetHandle *p = NULL;

	if (enumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	p = calloc(1, sizeof(struct OT_TEE_PropSetHandle));
	if (p == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	*enumerator = p;

	return TEE_SUCCESS;
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
	if (enumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	free(enumerator);
}

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator, TEE_PropSetHandle propSet)
{
	if (enumerator == NULL ||
	    (propSet != TEE_PROPSET_CURRENT_TA && propSet != TEE_PROPSET_CURRENT_CLIENT &&
	     propSet != TEE_PROPSET_TEE_IMPLEMENTATION))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	enumerator->propset = propSet;
	enumerator->index = 0;
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
	if (enumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
	memset(enumerator, 0, sizeof(struct OT_TEE_PropSetHandle));
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer,
			       size_t *nameBufferLen)
{
	TEE_Result ret;
	struct OT_TEE_Property *p = NULL;
	size_t orig_len = 0;

	if (nameBuffer == NULL || nameBufferLen == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = find_property(&p, enumerator, NULL);
	if (ret != TEE_SUCCESS)
		return ret;

	orig_len = *nameBufferLen;
	*nameBufferLen = strlen(p->name) + 1;
	if (*nameBufferLen > orig_len)
		return TEE_ERROR_SHORT_BUFFER;

	strncpy(nameBuffer, p->name, orig_len);

	return TEE_SUCCESS;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
	size_t count = 0;

	if (enumerator == NULL)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (enumerator->propset == TEE_PROPSET_CURRENT_TA)
		count = TA_Properties_Count;
	else if (enumerator->propset == TEE_PROPSET_CURRENT_CLIENT)
		count = Client_Properties_Count;
	else if (enumerator->propset == TEE_PROPSET_TEE_IMPLEMENTATION)
		count = Implementation_Properties_Count;
	else
		return TEE_ERROR_ITEM_NOT_FOUND;

	++enumerator->index;

	if (enumerator->index >= count)
		return TEE_ERROR_ITEM_NOT_FOUND;

	return TEE_SUCCESS;
}
