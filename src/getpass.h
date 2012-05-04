/*
 * SQLassie - database firewall
 * Copyright (C) 2011 Brandon Skari <brandon.skari@gmail.com>
 *
 * This file is part of SQLassie.
 *
 * SQLassie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SQLassie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SQLassie. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

/**
 * getpass is deprecated and will be removed soon - this duplicates that
 * feature and allows user input without echo.
 * @author Brandon Skari
 * @date May 5 2011
 */

char* getpass(const char* prompt, char* buffer, const int size)
{
    struct termios oflags, nflags;

    /* Disable echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (0 != tcsetattr(fileno(stdin), TCSANOW, &nflags))
    {
        return NULL;
    }

    printf("%s", prompt);
    char* const success = fgets(buffer, size, stdin);
    if (NULL == success)
    {
        return NULL;
    }

    /* Make sure it's null-terminated */
    buffer[size - 1] = '\0';

    /* fgets will also include a newline, so remove it */
    for (char* i = buffer; i != '\0'; ++i)
    {
        if ('\n' == *i || '\r' == *i)
        {
            *i = '\0';
            break;
        }
    }

    /* Enable echo */
    if (0 != tcsetattr(fileno(stdin), TCSANOW, &oflags))
    {
        return NULL;
    }

    return buffer;
}
