/*****************************************************************************
** SPDX-FileCopyrightText: 2026 Mika Tammi                                  **
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

#ifdef TA_PLUGIN

#include "property_test_ctl.h"
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(PROPERTY_TEST_TA_UUID, 4096, /* dataSize */
		  512,			       /* stackSize */
		  0,			       /* singletonInstance */
		  0,			       /* multiSession */
		  0)			       /* instanceKeepAlive */

#endif
