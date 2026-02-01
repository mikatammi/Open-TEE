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

#include "tee_internal_api.h"
#include "tee_logging.h"

TEE_Result TA_EXPORT TA_CreateEntryPoint(void) { return TEE_SUCCESS; }

void TA_EXPORT TA_DestroyEntryPoint(void) {}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
					      void **sessionContext)
{
	paramTypes = paramTypes;
	params = params;
	sessionContext = sessionContext;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) { sessionContext = sessionContext; }

struct Property {
	TEE_PropSetHandle propset;
	const char *name;
};

const struct Property StringTestcases[] = {
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.description"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.name"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedos.implementation.version"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedos.manufacturer"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.firmware.implementation.version"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.firmware.manufacturer"},
};

const size_t StringTestcaseCount = sizeof(StringTestcases) / sizeof(struct Property);

TEE_Result RunStringTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bin_buf_size = 64;
	char bin_buf[bin_buf_size];
	size_t tmp_buf_size = 512;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsString(p->propset, p->name, bin_buf, &bin_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s", p->name, bin_buf);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunStringTests()
{
	bool fail = false;
	for (size_t i = 0; i < StringTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunStringTest(&StringTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

const struct Property BinaryTestcases[] = {
    {TEE_PROPSET_CURRENT_CLIENT, "gpd.client.pathHash"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedos.implementation.binaryversion"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.firmware.implementation.binaryversion"},
};

const size_t BinaryTestcaseCount = sizeof(BinaryTestcases) / sizeof(struct Property);

TEE_Result RunBinaryTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bin_buf_size = 64;
	char bin_buf[bin_buf_size];
	size_t tmp_buf_size = 512;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsBinaryBlock(p->propset, p->name, bin_buf, &bin_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsBinary: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: Not printed", p->name);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunBinaryTests()
{
	bool fail = false;
	for (size_t i = 0; i < BinaryTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunBinaryTest(&BinaryTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

const struct Property IntegerTestcases[] = {
    {TEE_PROPSET_CURRENT_TA, "gpd.ta.endian"},
    {TEE_PROPSET_CURRENT_CLIENT, "gpd.client.endian"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.internalCore.version"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.arith.maxBigIntSize"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.maxRetainedData"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedStorage.private.rollbackProtection"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedStorage.perso.rollbackProtection"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedStorage.protected.rollbackProtection"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedStorage.antiRollback.protectionLevel"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.trustedStorage.rollbackDetection.protectionLevel"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.event.maxSources"},
};

const size_t IntegerTestcaseCount = sizeof(IntegerTestcases) / sizeof(struct Property);

TEE_Result RunIntegerTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t value = 0;
	size_t tmp_buf_size = 32;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsU32(p->propset, p->name, &value);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsU32: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %u", p->name, value);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunIntegerTests()
{
	bool fail = false;
	for (size_t i = 0; i < IntegerTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunIntegerTest(&IntegerTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

const struct Property BooleanTestcases[] = {
    /* {TEE_PROPSET_CURRENT_TA, "gpd.ta.doesNotCloseHandleOnCorruptObject"}, */
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.ecc"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.nist"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.bsi-r"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.bsi-t"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.ietf"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.octa"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.sec"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.falcon"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.NISTpqc.crystals"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.NISTpqc.SLHDSA"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.statefulVerification"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.statefulSignatures"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.FrodoKEM"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.NTRU"},
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.maskState"},
};

const size_t BooleanTestcaseCount = sizeof(BooleanTestcases) / sizeof(struct Property);

TEE_Result RunBooleanTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	bool value = 0;
	size_t tmp_buf_size = 32;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsBool(p->propset, p->name, &value);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsBool: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %u", p->name, value);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunBooleanTests()
{
	bool fail = false;
	for (size_t i = 0; i < BooleanTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunBooleanTest(&BooleanTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

const struct Property UUIDTestcases[] = {
    {TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.deviceID"},
};

const size_t UUIDTestcaseCount = sizeof(UUIDTestcases) / sizeof(struct Property);

TEE_Result RunUUIDTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_UUID value = {0};
	size_t tmp_buf_size = 64;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsUUID(p->propset, p->name, &value);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsUUID: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR,
	       "Name %s -> Returned value: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	       p->name, value.timeLow, value.timeMid, value.timeHiAndVersion,
	       value.clockSeqAndNode[0], value.clockSeqAndNode[1], value.clockSeqAndNode[2],
	       value.clockSeqAndNode[3], value.clockSeqAndNode[4], value.clockSeqAndNode[5],
	       value.clockSeqAndNode[6], value.clockSeqAndNode[7]);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunUUIDTests()
{
	bool fail = false;
	for (size_t i = 0; i < UUIDTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunUUIDTest(&UUIDTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

const struct Property IdentityTestcases[] = {
    {TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity"},
};

const size_t IdentityTestcaseCount = sizeof(IdentityTestcases) / sizeof(struct Property);

TEE_Result RunIdentityTest(const struct Property *p)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_Identity value = {0};
	size_t tmp_buf_size = 64;
	char tmp_buf[tmp_buf_size];

	ret = TEE_GetPropertyAsIdentity(p->propset, p->name, &value);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsIdentity: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR,
	       "Name %s -> Returned value: %u:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	       p->name, value.login, value.uuid.timeLow, value.uuid.timeMid,
	       value.uuid.timeHiAndVersion, value.uuid.clockSeqAndNode[0],
	       value.uuid.clockSeqAndNode[1], value.uuid.clockSeqAndNode[2],
	       value.uuid.clockSeqAndNode[3], value.uuid.clockSeqAndNode[4],
	       value.uuid.clockSeqAndNode[5], value.uuid.clockSeqAndNode[6],
	       value.uuid.clockSeqAndNode[7]);

	ret = TEE_GetPropertyAsString(p->propset, p->name, tmp_buf, &tmp_buf_size);
	if (ret != TEE_SUCCESS) {
		OT_LOG(LOG_ERR, "Error while calling TEE_GetPropertyAsString: %u", ret);
		return ret;
	}

	OT_LOG(LOG_ERR, "Name %s -> Returned value: %s  size: %zu", p->name, tmp_buf, tmp_buf_size);

	return TEE_SUCCESS;
}

TEE_Result RunIdentityTests()
{
	bool fail = false;
	for (size_t i = 0; i < IdentityTestcaseCount; ++i) {
		if (TEE_SUCCESS != RunIdentityTest(&IdentityTestcases[i]))
			fail = true;
	}

	return fail ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

TEE_Result Test_Enumerate(TEE_PropSetHandle propset)
{
	TEE_PropSetHandle enumerator = NULL;
	TEE_Result ret;

	ret = TEE_AllocatePropertyEnumerator(&enumerator);
	if (ret != TEE_SUCCESS)
		return ret;

	for (TEE_StartPropertyEnumerator(enumerator, propset); ret == TEE_SUCCESS;
	     ret = TEE_GetNextProperty(enumerator)) {
		size_t nameBufferLen = 256;
		char nameBuffer[nameBufferLen];
		ret = TEE_GetPropertyName(enumerator, nameBuffer, &nameBufferLen);
		if (ret != TEE_SUCCESS)
			goto err;
		OT_LOG(LOG_ERR, "TEE_GetPropertyName -> %s", nameBuffer);
	}

	if (ret == TEE_ERROR_ITEM_NOT_FOUND)
		ret = TEE_SUCCESS;
err:
	TEE_FreePropertyEnumerator(enumerator);
	return ret;
}

TEE_Result RunEnumerationTests()
{
	TEE_Result ret;

	ret = Test_Enumerate(TEE_PROPSET_CURRENT_TA);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = Test_Enumerate(TEE_PROPSET_CURRENT_CLIENT);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = Test_Enumerate(TEE_PROPSET_TEE_IMPLEMENTATION);
	return ret;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	sessionContext = sessionContext;
	paramTypes = paramTypes;
	params = params;

	if (commandID == 1) {
		TEE_Result ret;
		/* TODO: Use Property Access functions to get property values from the API */
		/* TODO: Test every kind */
		/* String */
		ret = RunStringTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* Binary */
		ret = RunBinaryTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* Integer */
		ret = RunIntegerTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* Boolean */
		ret = RunBooleanTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* UUID */
		ret = RunUUIDTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* Identity */
		ret = RunIdentityTests();
		if (ret != TEE_SUCCESS)
			return ret;

		/* Enumeration tests */
		ret = RunEnumerationTests();

		return ret;
	}

	return TEE_SUCCESS;
}
