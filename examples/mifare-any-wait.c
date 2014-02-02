/*-
 * Copyright (C) 2013, Henryk Plötz
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
#include <err.h>
#include <stdlib.h>

#include <freefare.h>

int
main (int argc, char *argv[])
{
    int error = EXIT_SUCCESS;

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    FreefareContext ctx = freefare_init(FREEFARE_FLAG_READER_ALL);
    if (ctx == NULL)
	errx(EXIT_FAILURE, "Unable to init libfreefare");

    FreefareTagWaitContext wait_ctx = freefare_tag_wait_new(ctx, FREEFARE_FLAG_READER_PCSC, FREEFARE_TAG_WAIT_PCSC_AUTO(), NO_TAG_TYPE);
    if(wait_ctx == NULL)
	errx(EXIT_FAILURE, "Unable to init wait context");

    MifareTag tag = NULL;
    while( (tag = freefare_tag_wait_next(wait_ctx, 0)) ) {
	char *tag_uid = freefare_get_tag_uid (tag);
	printf ("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name (tag));

	free (tag_uid);
	freefare_free_tag(tag);
    }



    freefare_tag_wait_free(wait_ctx);
    freefare_exit(ctx);
    exit(error);
}
