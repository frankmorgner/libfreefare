/*-
 * Copyright (C) 2010, Romain Tartiere
 * Copyright (C) 2013, Romuald Conty
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

#include <cutter.h>
#include <freefare.h>

#include "mifare_classic_fixture.h"

FreefareContext ctx = NULL;
static MifareTag *tags = NULL;
MifareTag tag = NULL;

void
cut_setup (void)
{
    int res;
    
    ctx = freefare_init(FREEFARE_FLAG_READER_ALL);
    cut_assert_not_null (ctx, cut_message ("Unable to init libfreefare"));

    tags = freefare_tags_get (ctx, NO_TAG_TYPE);
    cut_assert_not_null (tags, cut_message ("freefare_tags_get() failed"));

    tag = NULL;
    for (int i=0; tags[i]; i++) {
	if ((freefare_get_tag_type(tags[i]) == CLASSIC_1K) ||
		(freefare_get_tag_type(tags[i]) == CLASSIC_4K)) {
	    tag = tags[i];
	    res = mifare_classic_connect (tag);
	    cut_assert_equal_int (0, res, cut_message ("mifare_classic_connect() failed"));
	    return;
	}
    }
    freefare_free_tags (tags);
    tags = NULL;

    cut_omit ("No MIFARE Classic tag on NFC device");
}

void
cut_teardown (void)
{
    if (tag)
        mifare_classic_disconnect (tag);

    if (tags) {
        freefare_free_tags (tags);
        tags = NULL;
    }

    if (ctx)
        freefare_exit(ctx);
}

