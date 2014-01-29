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
    MifareTag *tags = NULL;

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    FreefareContext ctx = freefare_init(FREEFARE_FLAG_READER_ALL);
    if (ctx == NULL)
	errx(EXIT_FAILURE, "Unable to init libfreefare");

    tags = freefare_tags_get (ctx, NO_TAG_TYPE);
    if (!tags) {
	freefare_exit(ctx);
	errx (EXIT_FAILURE, "Error listing tags.");
    }

    for (int i = 0; (!error) && tags[i]; i++) {
	char *tag_uid = freefare_get_tag_uid (tags[i]);
	printf ("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name (tags[i]));

	free (tag_uid);
    }

    freefare_free_tags (tags);
    freefare_exit(ctx);
    exit(error);
}
