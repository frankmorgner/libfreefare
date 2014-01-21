/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#include "freefare_internal.h"

#define NXP_MANUFACTURER_CODE 0x04

struct supported_tag supported_tags[] = {
    { CLASSIC_1K,   "Mifare Classic 1k",            0x08, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x28, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x68, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Infineon Mifare Classic 1k",   0x88, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k",            0x18, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k (Emulated)", 0x38, 0, 0, { 0x00 }, NULL },
    { DESFIRE,      "Mifare DESFire",               0x20, 5, 4, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }, NULL},
    { ULTRALIGHT_C, "Mifare UltraLightC",           0x00, 0, 0, { 0x00 }, is_mifare_ultralightc_on_reader },
    { ULTRALIGHT,   "Mifare UltraLight",            0x00, 0, 0, { 0x00 }, NULL },
};

#define FREEFARE_FLAG_MASK_READER_ALL (FREEFARE_FLAG_READER_LIBNFC)
#define FREEFARE_FLAG_MASK_GLOBAL_INHERIT (FREEFARE_FLAG_DISABLE_ISO14443_4)

#define DEFAULT_READER_LIST_LENGTH 16

static FreefareContext implicit_context = NULL;

static MifareTag *_freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type, struct freefare_enumeration_state *state);
static int _reader_device_store(struct freefare_context *ctx, struct freefare_reader_device *reader_device);
static void _reader_device_close(struct freefare_reader_device *device);
static void _reader_device_down(struct freefare_context *ctx, int slot);

static FreefareContext freefare_implicit_context(void)
{
    if(implicit_context) {
	return implicit_context;
    }

    return implicit_context = freefare_init(0);
}

/*
 * Legacy function to automagically allocate a new MifareTag
 * given a device and target info
 */
MifareTag
freefare_tag_new (nfc_device *device, nfc_iso14443a_info nai)
{
    FreefareContext ctx = freefare_implicit_context();
    return freefare_tag_new_ex(ctx, (ctx->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT) | FREEFARE_FLAG_READER_LIBNFC, FREEFARE_TAG_LIBNFC(device, nai));
}

/*
 * Automagically allocate a MifareTag given a device and target info.
 */
MifareTag
freefare_tag_new_ex (FreefareContext ctx, FreefareFlags flags, FreefareReaderTag reader_tag)
{
    bool found = false;
    struct supported_tag *tag_info;
    MifareTag tag;

    if(!ctx) {
	return NULL;
    }
    /*
     * TODO Make this generic for all reader types, and include it into the
     * library context management, for now just hard code a legacy libnfc path
     */
    if(!(flags & FREEFARE_FLAG_READER_LIBNFC)) {
	return NULL;
    }

    nfc_device *device = reader_tag.libnfc.device;
    nfc_iso14443a_info nai = reader_tag.libnfc.nai;

    /* Ensure the target is supported */
    for (size_t i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (((nai.szUidLen == 4) || (nai.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (nai.btSak == supported_tags[i].SAK) &&
	    (!supported_tags[i].ATS_min_length || ((nai.szAtsLen >= supported_tags[i].ATS_min_length) &&
						   (0 == memcmp (nai.abtAts, supported_tags[i].ATS, supported_tags[i].ATS_compare_length)))) &&
	    ((supported_tags[i].check_tag_on_reader == NULL) ||
	     supported_tags[i].check_tag_on_reader(device, nai))) {

	    tag_info = &(supported_tags[i]);
	    found = true;
	    break;
	}
    }

    if (!found)
	return NULL;

    /* Allocate memory for the found MIFARE target */
    switch (tag_info->type) {
    case NO_TAG_TYPE:
	tag = NULL;
	break;
    case CLASSIC_1K:
    case CLASSIC_4K:
	tag = mifare_classic_tag_new ();
	break;
    case DESFIRE:
	tag = mifare_desfire_tag_new ();
	break;
    case ULTRALIGHT:
    case ULTRALIGHT_C:
	tag = mifare_ultralight_tag_new ();
	break;
    }

    if (!tag)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    tag->device = device;
    tag->info = nai;
    tag->active = 0;
    tag->tag_info = tag_info;

    return tag;
}


/*
 * MIFARE card common functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the targets.
 */

/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 *
 * The list has to be freed using the freefare_free_tags() function.
 */
MifareTag *
freefare_get_tags (nfc_device *device)
{
    FreefareContext ctx = freefare_implicit_context();

    /*
     * Use the tags_get functionality, but with a local enumeration state
     * and limited to a temporary reader_device injected into the context
     */
    struct freefare_enumeration_state state;
    memset(&state, 0, sizeof(state));

    struct freefare_reader_device *reader_device = calloc(1, sizeof(*reader_device));
    if(reader_device == NULL) {
	return NULL;
    }
    reader_device->device = FREEFARE_DEVICE_LIBNFC(device);
    reader_device->flags = FREEFARE_FLAG_READER_LIBNFC | (ctx->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT);
    reader_device->internal = 1;

    int slot = _reader_device_store(ctx, reader_device);
    if(slot < 0) {
	free(reader_device);
	return NULL;
    }

    state.phase = FREEFARE_ENUMERATION_PHASE_EXT_DEVICE;
    state.single_device = 1;
    state.device_handle = slot;

    MifareTag *tags = _freefare_tags_get(ctx, NO_TAG_TYPE, &state);

    _reader_device_down(ctx, slot);

    return tags;
}

#if 0
/*
 * TODO: Implement this in the tag_first/tag_next API in the libnfc case
 * For now it's just disabled.
 */

{
    MifareTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,false);

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool(device,NP_HANDLE_CRC,true);
    nfc_device_set_property_bool(device,NP_HANDLE_PARITY,true);
    nfc_device_set_property_bool(device,NP_AUTO_ISO14443_4,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target candidates[MAX_CANDIDATES];
    int candidates_count;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    for (int c = 0; c < candidates_count; c++) {
	MifareTag t;
	if ((t = freefare_tag_new(device, candidates[c].nti.nai))) {
	    /* (Re)Allocate memory for the found MIFARE targets array */
	    MifareTag *p = realloc (tags, (tag_count + 2) * sizeof (MifareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    return tags;
}
#endif

/*
 * Returns the type of the provided tag.
 */
enum mifare_tag_type
freefare_get_tag_type (MifareTag tag)
{
    return tag->tag_info->type;
}

/*
 * Returns the friendly name of the provided tag.
 */
const char *
freefare_get_tag_friendly_name (MifareTag tag)
{
    return tag->tag_info->friendly_name;
}

/*
 * Returns the UID of the provided tag.
 */
char *
freefare_get_tag_uid (MifareTag tag)
{
    char *res = malloc (2 * tag->info.szUidLen + 1);
    for (size_t i =0; i < tag->info.szUidLen; i++)
        snprintf (res + 2*i, 3, "%02x", tag->info.abtUid[i]);
    return res;
}

/*
 * Free the provided tag.
 */
void
freefare_free_tag (MifareTag tag)
{
    if (tag) {
        switch (tag->tag_info->type) {
        case NO_TAG_TYPE:
            break;
        case CLASSIC_1K:
        case CLASSIC_4K:
            mifare_classic_tag_free (tag);
            break;
        case DESFIRE:
            mifare_desfire_tag_free (tag);
            break;
        case ULTRALIGHT:
        case ULTRALIGHT_C:
            mifare_ultralight_tag_free (tag);
            break;
        }
    }
}

const char *
freefare_strerror (MifareTag tag)
{
    const char *p = "Unknown error";
    if (nfc_device_get_last_error (tag->device) < 0) {
      p = nfc_strerror (tag->device);
    } else {
      if (tag->tag_info->type == DESFIRE) {
        if (MIFARE_DESFIRE (tag)->last_pcd_error) {
          p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
        } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
          p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
        }
      }
    }
    return p;
}

int
freefare_strerror_r (MifareTag tag, char *buffer, size_t len)
{
    return (snprintf (buffer, len, "%s", freefare_strerror (tag)) < 0) ? -1 : 0;
}

void
freefare_perror (MifareTag tag, const char *string)
{
    fprintf (stderr, "%s: %s\n", string, freefare_strerror (tag));
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags (MifareTag *tags)
{
    if (tags) {
	for (int i=0; tags[i]; i++) {
	    freefare_free_tag(tags[i]);
	}
	free (tags);
    }
}


static struct freefare_reader_context *_libnfc_context_open(FreefareFlags flags)
{
    struct freefare_reader_context *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }
    nfc_init(&(result->context.libnfc));
    result->flags = flags;

    return result;
}

static void _libnfc_context_free(struct freefare_reader_context *context)
{
    if(!context) {
	return;
    }
    if(context->flags & FREEFARE_FLAG_AUTOCLOSE) {
	nfc_exit(context->context.libnfc);
    }
    free(context);
}

static struct freefare_reader_device *_libnfc_device_open(struct freefare_reader_context *context, nfc_connstring connstring, FreefareFlags flags)
{
    if(!context || !(context->flags & FREEFARE_FLAG_READER_LIBNFC)) {
	return NULL;
    }

    struct freefare_reader_device *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }

    nfc_device *device = nfc_open(context->context.libnfc, connstring);
    if(!device) {
	free(result);
	return NULL;
    }

    if(flags & FREEFARE_FLAG_DISABLE_ISO14443_4) {
	nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, false);
    } else {
	nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, true);
    }

    result->device = FREEFARE_DEVICE_LIBNFC(device);
    result->flags = flags | FREEFARE_FLAG_READER_LIBNFC;
    result->references = 1;

    return result;
}

static void _libnfc_device_close(struct freefare_reader_device *device)
{
    if(!device) {
	return;
    }
    if(device->flags & FREEFARE_FLAG_AUTOCLOSE) {
	nfc_close(device->device.libnfc);
    }
    free(device);
}

static int _libnfc_enumerate_device(FreefareContext ctx, struct freefare_reader_device *device, struct freefare_enumeration_state *state, MifareTag *result)
{
    if(!state->libnfc.candidates) {
	state->libnfc.candidates_length = DEFAULT_READER_LIST_LENGTH;
	state->libnfc.candidates = calloc(state->libnfc.candidates_length, sizeof(state->libnfc.candidates[0]));
	if(!state->libnfc.candidates) {
	    state->libnfc.candidates_length = 0;
	    return -1;
	}

	nfc_initiator_init(device->device.libnfc);

	// Drop the field for a while
	nfc_device_set_property_bool(device->device.libnfc,NP_ACTIVATE_FIELD,false);

	// Configure the CRC and Parity settings
	nfc_device_set_property_bool(device->device.libnfc,NP_HANDLE_CRC,true);
	nfc_device_set_property_bool(device->device.libnfc,NP_HANDLE_PARITY,true);
	if(device->flags & FREEFARE_FLAG_DISABLE_ISO14443_4) {
	    nfc_device_set_property_bool(device->device.libnfc,NP_AUTO_ISO14443_4,false);
	} else {
	    nfc_device_set_property_bool(device->device.libnfc,NP_AUTO_ISO14443_4,true);
	}

	// Enable field so more power consuming cards can power themselves up
	nfc_device_set_property_bool(device->device.libnfc,NP_ACTIVATE_FIELD,true);

	// Poll for a ISO14443A (MIFARE) tag
	nfc_modulation modulation = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};
	state->libnfc.candidates_length = nfc_initiator_list_passive_targets(device->device.libnfc, modulation, state->libnfc.candidates, state->libnfc.candidates_length);
	if (state->libnfc.candidates_length < 0) {
	    free(state->libnfc.candidates);
	    state->libnfc.candidates_length = 0;
	    return -1;
	}
	state->libnfc.candidate_index = 0;
    }

    while(state->libnfc.candidate_index < state->libnfc.candidates_length) {
	/*
	 * TODO This uses the legacy code path, that may lead to some, uh, problems :)
	 *
	 * TODO Check and reject type
	 */
	*result = freefare_tag_new(device->device.libnfc, state->libnfc.candidates[state->libnfc.candidate_index].nti.nai);
	state->libnfc.candidate_index++;
	if(*result) {
	    return 0;
	}
    }

    free(state->libnfc.candidates);
    state->libnfc.candidates = 0;
    state->libnfc.candidates_length = 0;

    return 0;
}

/*
 * This enumerates (via nfc_list_devices()) all readers in a libnfc context, then calls _libnfc_enumerate_device()
 * for all of them using a temporary struct freefare_reader_device. If a tag has been found, the struct freefare_reader_device
 * is persisted into ctx.
 * It's written in a slightly complicated way to allow return and resume after a tag detection
 */
static int _libnfc_enumerate_context(FreefareContext ctx, struct freefare_reader_context *context, struct freefare_enumeration_state *state, MifareTag *result)
{
    if(!ctx || !context || !state || !result) {
	return -1;
    }

    if(!state->libnfc.connstrings) {
	/*
	 * Enumerate readers
	 */
	state->libnfc.connstrings_length = DEFAULT_READER_LIST_LENGTH;
	state->libnfc.connstrings = calloc(state->libnfc.connstrings_length, sizeof(state->libnfc.connstrings[0]));
	if(!state->libnfc.connstrings) {
	    state->libnfc.connstrings_length = 0;
	    return -1;
	}
	state->libnfc.connstrings_length = nfc_list_devices(context->context.libnfc, state->libnfc.connstrings, state->libnfc.connstrings_length);
    }

    while(state->context_device_index < state->libnfc.connstrings_length) {
	if(!state->tmp_device) {
	    state->tmp_device = _libnfc_device_open(context, state->libnfc.connstrings[state->context_device_index],
		    FREEFARE_FLAG_AUTOCLOSE | (context->flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT));
	    if(!state->tmp_device) {
		return -1;
	    }
	    state->tmp_device->internal = 1;
	    state->tmp_device_handle = -1;
	}

	if(_libnfc_enumerate_device(ctx, state->tmp_device, state, result) < 0) {
	    return -1;
	}

	if(*result) {
	    /*
	     * The reference counter in the tmp_device structure has already been
	     * incremented. If it has been stored before, just leave it be and return
	     * successfully, otherwise store it in the reader_devices array in the library
	     * context (marking it for autoclose and internal)
	     */
	    if(state->tmp_device_handle < 0) {
		state->tmp_device_handle = _reader_device_store(ctx, state->tmp_device);
	    }
	    if(state->tmp_device_handle >= 0) {
		return 0;
	    } else {
		_reader_device_close(state->tmp_device);
		state->tmp_device = NULL;
		return -1;
	    }

	}

	/*
	 * This is a no-op if the device is referenced by a tag, otherwise it
	 * will close and free the device structure.
	 */
	_reader_device_close(state->tmp_device);
	state->tmp_device = NULL;
	state->context_device_index++;
    }

    if(state->libnfc.connstrings) {
	free(state->libnfc.connstrings);
	state->libnfc.connstrings = NULL;
    }
    state->libnfc.connstrings_length = 0;

    return 0;
}

static int _embiggen_array(void **array, size_t *array_length, size_t element_size, size_t min_elements)
{
    if(!array || !array_length) {
	return -1;
    }

    if(*array && *array_length >= min_elements) {
	return 0;
    }

    void *new_array = calloc(min_elements, element_size);
    if(!new_array) {
	return -1;
    }

    if(*array) {
	memcpy(new_array, *array, element_size * (*array_length));
    }
    free(*array);
    *array = new_array;
    *array_length = min_elements;
    return 0;
}

static int _array_store(void ***array, size_t *array_length, size_t element_size, void *new_element)
{
    if(!array || !array_length) {
	return -1;
    }

    /*
     * Ensure the array is allocated
     */
    if(_embiggen_array((void**)array, array_length, element_size, DEFAULT_READER_LIST_LENGTH) < 0) {
	return -1;
    }

    /*
     * Search through the array for the first free slot and use it
     */
    for(size_t i=0; i<*array_length; i++) {
	if((*array)[i] == NULL) {
	    (*array)[i] = new_element;
	    return i;
	}
    }

    /*
     * No slot found, enlarge the array and use the next one
     */
    int slot = *array_length;
    if(_embiggen_array((void**)array, array_length, element_size, slot+1) < 0) {
	return -1;
    } else {
	(*array)[slot] = new_element;
	return slot;
    }

    return -1;
}

static int _reader_context_store(struct freefare_context *ctx, struct freefare_reader_context *reader_context)
{
    if(!ctx || !reader_context) {
	return -1;
    }

    return _array_store((void***)&ctx->reader_contexts, &ctx->reader_contexts_length, sizeof(ctx->reader_contexts[0]), reader_context);
}

static int _reader_device_store(struct freefare_context *ctx, struct freefare_reader_device *reader_device)
{
    if(!ctx || !reader_device) {
	return -1;
    }

    reader_device->references++;
    return _array_store((void***)&ctx->reader_devices, &ctx->reader_devices_length, sizeof(ctx->reader_devices[0]), reader_device);
}

static void _reader_device_close(struct freefare_reader_device *device)
{
    if(!device) {
	return;
    }
    if(device->references > 1) {
	return;
    }
    if(device->flags & FREEFARE_FLAG_READER_LIBNFC) {
	_libnfc_device_close(device);
    }
}
static void _reader_device_down(struct freefare_context *ctx, int slot)
{
    if(!ctx || slot < 0 || slot >= ctx->reader_devices_length) {
	return;
    }
    if(ctx->reader_devices[slot]->references <= 1) {
	_reader_device_close(ctx->reader_devices[slot]);
	ctx->reader_devices[slot] = NULL;
    } else {
	ctx->reader_devices[slot]--;
    }
}

/*
 * Allocate a new library context, possibly initialize lower-level
 * reader library connections
 */
FreefareContext	 freefare_init (FreefareFlags flags)
{
    struct freefare_context *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }

    result->global_flags = flags;
    if(result->global_flags & FREEFARE_FLAG_READER_ALL) {
	result->global_flags &= ~FREEFARE_FLAG_READER_ALL;
	result->global_flags |= FREEFARE_FLAG_MASK_READER_ALL;
    }

    if(result->global_flags & FREEFARE_FLAG_READER_LIBNFC) {
	/*
	 * Initialize an internal libnfc connection
	 */
	struct freefare_reader_context *libnfc_context = _libnfc_context_open(
		FREEFARE_FLAG_READER_LIBNFC | FREEFARE_FLAG_AUTOCLOSE |
		(result->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT)
	);
	if(!libnfc_context) {
	    goto abort;
	}
	libnfc_context->internal = 1;
	if(_reader_context_store(result, libnfc_context) < 0) {
	    _libnfc_context_free(libnfc_context);
	    goto abort;
	}
    }

    return result;
abort:
    freefare_exit(result);
    return NULL;
}

MifareTag _freefare_tag_next (FreefareContext ctx, struct freefare_enumeration_state *state)
{
    if(!ctx || !state) {
	return NULL;
    }

    MifareTag result = NULL;

    switch(state->phase) {
    case FREEFARE_ENUMERATION_PHASE_NONE:
	state->phase = FREEFARE_ENUMERATION_PHASE_EXT_DEVICE;
	state->device_handle = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_EXT_DEVICE:
	while(state->device_handle < ctx->reader_devices_length) {
	    /*
	     * Ignore empty slots and "internal" devices except when in single_device mode
	     */
	    if(!ctx->reader_devices[state->device_handle] || (ctx->reader_devices[state->device_handle]->internal && !state->single_device)) {
		if(state->single_device) {
		    break;
		}
		state->device_handle++;
		continue;
	    }

	    if( ctx->reader_devices[state->device_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_device(ctx, ctx->reader_devices[state->device_handle], state, &result);
	    }

	    if(result) {
		return result;
	    }

	    if(state->single_device) {
		break;
	    }
	    state->device_handle++;
	}

	if(state->single_device) {
	    break;
	}
	state->phase = FREEFARE_ENUMERATION_PHASE_EXT_CONTEXT;
	state->context_handle = 0;
	state->context_device_index = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_EXT_CONTEXT:
	while(state->context_handle < ctx->reader_contexts_length) {
	    if(!ctx->reader_contexts[state->context_handle] || ctx->reader_contexts[state->context_handle]->internal) {
		state->context_handle++;
		continue;
	    }

	    if( ctx->reader_contexts[state->context_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_context(ctx, ctx->reader_contexts[state->context_handle], state, &result);
	    }

	    if(result) {
		return result;
	    }

	    state->context_handle++;
	}

	state->phase = FREEFARE_ENUMERATION_PHASE_INT;
	state->context_handle = 0;
	state->context_device_index = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_INT:
	while(state->context_handle < ctx->reader_contexts_length) {
	    if(!ctx->reader_contexts[state->context_handle] || !ctx->reader_contexts[state->context_handle]->internal) {
		state->context_handle++;
		continue;
	    }

	    if( ctx->reader_contexts[state->context_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_context(ctx, ctx->reader_contexts[state->context_handle], state, &result);
	    }

	    if(result) {
		return result;
	    }

	    state->context_handle++;
	}

    }

    return result;
}

MifareTag _freefare_tag_first (FreefareContext ctx, struct freefare_enumeration_state *state, enum mifare_tag_type tag_type)
{
    if(!ctx || !state) {
	return NULL;
    }
    /*
     * If there's currently an enumeration ongoing, clean it up
     */
    if(state->libnfc.device) {
	nfc_close(state->libnfc.device);
	state->libnfc.device = NULL;
    }

    if(state->libnfc.connstrings) {
	free(state->libnfc.connstrings);
	state->libnfc.connstrings = NULL;
    }

    if(!state->single_device) {
	state->device_handle = -1;
    }
    state->context_handle = -1;
    state->context_device_index = -1;

    /*
     * Take note of which tag_type the caller requests, then
     * have _freefare_tag_next() handle the remainder of the operation
     */
    state->tag_type = tag_type;

    return _freefare_tag_next(ctx, state);
}

MifareTag freefare_tag_first (FreefareContext ctx, enum mifare_tag_type tag_type)
{
    if(!ctx) return NULL;
    return _freefare_tag_first(ctx, &(ctx->enumeration_state), tag_type);
}
MifareTag freefare_tag_next (FreefareContext ctx)
{
    if(!ctx) return NULL;
    return _freefare_tag_next(ctx, &(ctx->enumeration_state));
}

MifareTag *_freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type, struct freefare_enumeration_state *state)
{
    MifareTag *result = NULL;
    size_t result_length = 0;
    MifareTag tag = NULL;

    if( (tag = _freefare_tag_first(ctx, state, tag_type)) ) do {
	size_t slot = result_length;
	if(_embiggen_array((void**)&result, &result_length, sizeof(*result), slot+1) < 0) {
	    goto abort;
	} else {
	    result[slot] = tag;
	}
    } while( (tag = _freefare_tag_next(ctx, state)) );

    /*
     * Make sure that there's at least one trailing NULL in the array
     */
    if(_embiggen_array((void**)&result, &result_length, sizeof(*result), result_length+1) < 0) {
	goto abort;
    }

    return result;
abort:
    freefare_free_tags(result);
    return NULL;

}

MifareTag *freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type)
{
    /*
     * Use a tag_first/tag_next loop, but store state in a local variable
     * so that it's independent from the global enumeration state in ctx.
     */
    struct freefare_enumeration_state state;
    memset(&state, 0, sizeof(state));

    return _freefare_tags_get(ctx, tag_type, &state);
}

void freefare_exit (FreefareContext ctx)
{
    if(!ctx) {
	ctx = implicit_context;
    }
    if(!ctx) {
	return;
    }

    for(size_t i=0; i<ctx->reader_contexts_length; i++) {
	if(ctx->reader_contexts[i] && (ctx->reader_contexts[i]->flags & FREEFARE_FLAG_AUTOCLOSE)) {
	    if(ctx->reader_contexts[i]->flags & FREEFARE_FLAG_READER_LIBNFC) {
		_libnfc_context_free(ctx->reader_contexts[i]);
		ctx->reader_contexts[i] = NULL;
	    }
	}
    }

    for(size_t i=0; i<ctx->reader_devices_length; i++) {
	if(ctx->reader_devices[i] && (ctx->reader_devices[i]->flags & FREEFARE_FLAG_AUTOCLOSE)) {
	    if(ctx->reader_devices[i]->flags & FREEFARE_FLAG_READER_LIBNFC) {
		_libnfc_device_close(ctx->reader_devices[i]);
		ctx->reader_devices[i] = NULL;
	    }
	}
    }

    if(ctx->reader_contexts) {
	free(ctx->reader_contexts);
    }

    if(ctx->reader_devices) {
	free(ctx->reader_devices);
    }

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

/*
 * Low-level API
 */

void *
memdup (const void *p, const size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}
