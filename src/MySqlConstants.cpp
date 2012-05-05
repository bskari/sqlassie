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

#include "Logger.hpp"
#include "MySqlConstants.hpp"

#include <boost/cstdint.hpp>
#include <cassert>
#include <string>
#include <boost/regex.hpp>

using std::string;
using boost::regex;
using boost::regex_match;
using boost::regex_replace;


const char* MySqlConstants::errorCodeTo5CharMessage(const uint16_t code)
{
    switch (code)
    {
        case 1249:
        case 1261:
        case 1262:
        case 1265:
        case 1311: return "01000";
        case 1329: return "02000";
        case 1040:
        case 1251: return "08004";
        case 1042:
        case 1043:
        case 1047:
        case 1053:
        case 1080:
        case 1081:
        case 1152:
        case 1153:
        case 1154:
        case 1155:
        case 1156:
        case 1157:
        case 1158:
        case 1159:
        case 1160:
        case 1161:
        case 1184:
        case 1189:
        case 1190:
        case 1218: return "08S01";
        case 1312:
        case 1314:
        case 1335:
        case 1415: return "0A000";
        case 1339: return "20000";
        case 1222:
        case 1241:
        case 1242: return "21000";
        case 1058:
        case 1136: return "21S01";
        case 1406: return "22001";
        case 1264:
        case 1416: return "22003";
        case 1138:
        case 1263: return "22004";
        case 1292:
        case 1367: return "22007";
        case 1365: return "22012";
        case 1022:
        case 1048:
        case 1052:
        case 1062:
        case 1169:
        case 1216:
        case 1217: return "23000";
        case 1325:
        case 1326: return "24000";
        case 1179:
        case 1207: return "25000";
        case 1045: return "28000";
        case 1303: return "2F003";
        case 1321: return "2F005";
        case 1046: return "3D000";
        case 1213: return "40001";
        case 1044:
        case 1049:
        case 1055:
        case 1056:
        case 1057:
        case 1059:
        case 1061:
        case 1063:
        case 1064:
        case 1065:
        case 1066:
        case 1067:
        case 1068:
        case 1069:
        case 1070:
        case 1071:
        case 1072:
        case 1073:
        case 1074:
        case 1075:
        case 1083:
        case 1084:
        case 1090:
        case 1091:
        case 1101:
        case 1102:
        case 1103:
        case 1104:
        case 1106:
        case 1107:
        case 1110:
        case 1112:
        case 1113:
        case 1115:
        case 1118:
        case 1120:
        case 1121:
        case 1131:
        case 1132:
        case 1133:
        case 1139:
        case 1140:
        case 1141:
        case 1142:
        case 1143:
        case 1144:
        case 1145:
        case 1147:
        case 1148:
        case 1149:
        case 1162:
        case 1163:
        case 1164:
        case 1166:
        case 1167:
        case 1170:
        case 1171:
        case 1172:
        case 1173:
        case 1177:
        case 1178:
        case 1203:
        case 1211:
        case 1226:
        case 1227:
        case 1230:
        case 1231:
        case 1232:
        case 1234:
        case 1235:
        case 1239:
        case 1248:
        case 1250:
        case 1252:
        case 1253:
        case 1280:
        case 1281:
        case 1286:
        case 1304:
        case 1305:
        case 1308:
        case 1309:
        case 1310:
        case 1313:
        case 1315:
        case 1316:
        case 1318:
        case 1319:
        case 1320:
        case 1322:
        case 1323:
        case 1324:
        case 1327:
        case 1330:
        case 1331:
        case 1332:
        case 1333:
        case 1336:
        case 1337:
        case 1338:
        case 1370:
        case 1403:
        case 1407:
        case 1410:
        case 1413:
        case 1414: return "42000";
        case 1050: return "42S01";
        case 1051:
        case 1109:
        case 1146: return "42S02";
        case 1082: return "42S12";
        case 1060: return "42S21";
        case 1054:
        case 1247: return "42S22";
        case 1317: return "70100";
        case 1037:
        case 1038: return "HY001";
        case 1402: return "XA100";
        case 1401: return "XAE03";
        case 1397: return "XAE04";
        case 1398: return "XAE05";
        case 1399: return "XAE07";
        case 1400: return "XAE09";
        default:
            Logger::log(Logger::ERROR) << "Unknown error code " << code;
            assert(false);
            return "_____";
    }
}


string MySqlConstants::mySqlRegexToPerlRegex(const string& mySqlRegex)
{
    // Some people, when confronted with a problem, think
    // "I know, I'll use regular expressions." Now they have two problems.
    // - Jamie Zawinski

    // Start with the line anchor
    string returnValue("^");

    bool lastWasEscape = false;
    for (size_t i = 0; i < mySqlRegex.length(); ++i)
    {
        switch (mySqlRegex.at(i))
        {
            // MySQL regex control characters
            case '\\':
                if (lastWasEscape)
                {
                    returnValue += '\\';
                }
                else
                {
                    lastWasEscape = true;
                }
                break;

            case '_':
                if (lastWasEscape)
                {
                    returnValue += '_';
                }
                else
                {
                    returnValue += '.';
                }
                lastWasEscape = false;
                break;

            case '%':
                if (lastWasEscape)
                {
                    returnValue += '%';
                }
                else
                {
                    returnValue += ".*";
                }
                lastWasEscape = false;
                break;

                // Perl regex control characters
            case '.':
                returnValue += "\\.";
                break;

            case ',':
                returnValue += "\\,";
                break;

            case '?':
                returnValue += "\\?";
                break;

            case '*':
                returnValue += "\\*";
                break;

            case '[':
                returnValue += "\\[";
                break;

            case ']':
                returnValue += "\\]";
                break;

            case '|':
                returnValue += "\\|";
                break;

            case '^':
                returnValue += "\\^";
                break;

            case '$':
                returnValue += "\\$";
                break;

            case '+':
                returnValue += "\\+";
                break;

            case '(':
                returnValue += "\\(";
                break;

            case ')':
                returnValue += "\\)";
                break;

            case '{':
                returnValue += "\\{";
                break;

            case '}':
                returnValue += "\\}";
                break;

                // Normal characters
            default:
                returnValue += mySqlRegex.at(i);
                break;
        }
    }

    // Add line anchor
    return returnValue + '$';
}


string MySqlConstants::soundex(const string& str)
{
    if (str.empty())
    {
        return string("");
    }

    // Remove all non-letters
    static const regex nonLetters("([^a-z])", regex::perl | regex::icase);
    string dropped(regex_replace(str, nonLetters, ""));

    if (dropped.empty())
    {
        return string("");
    }

    // Retain the first letter (as uppercase)
    const char firstLetter = (toupper(dropped.at(0)));

    // Drop all occurrences of a, e, h, i, o, u, w, y in the other positions
    static const regex dropChars("[aehiouwy]", regex::perl | regex::icase);
    dropped = regex_replace(dropped, dropChars, "");


    // Assign the following numbers to the remaining letters:
    // b f p v => 1
    // c f j k q s x z => 2
    // d t => 3
    // l => 4
    // m n => 5
    // r => 6
    static const regex one("[bfpv]", regex::perl | regex::icase);
    static const regex two("[cgjkqsxz]", regex::perl | regex::icase);
    static const regex three("[dt]", regex::perl | regex::icase);
    static const regex four("[l]", regex::perl | regex::icase);
    static const regex five("[nm]", regex::perl | regex::icase);
    static const regex six("[r]", regex::perl | regex::icase);
    static const regex* const search[6] = {
        &one,
        &two,
        &three,
        &four,
        &five,
        &six
    };
    static const char* const replace[6] = {"1", "2", "3", "4", "5", "6"};
    char firstLettersCode = '\0';
    string firstLetterStr;
    firstLetterStr += firstLetter;
    for (
        int i = 0;
        i < static_cast<int>(sizeof(search) / sizeof(search[0]));
        ++i
    )
    {
        dropped = regex_replace(dropped, *search[i], replace[i]);
        if (regex_match(firstLetterStr, *search[i]))
        {
            firstLettersCode = '0' + i + 1;
        }
    }

    // If two or more letters with the same code were adjacent in the original
    // name (before step 1) or adjacent except for intervening h's and w's,
    // omit all but the first
    string removedDuplicates;
    if (!dropped.empty())
    {
        char last = dropped.at(0);

        // MySQL won't add a code if the first letter's code matches the next
        // intact letter's code
        if ('\0' == firstLettersCode && last != firstLettersCode)
        {
            removedDuplicates += last;
        }

        for (size_t i = 1; i < dropped.length(); ++i)
        {
            if (dropped.at(i) != last)
            {
                removedDuplicates += dropped.at(i);
            }
            last = dropped.at(i);
        }
    }

    // Convert to letter digit*, padding with zeroes to 3 digits if necessary
    while (removedDuplicates.size() < 3)
    {
        removedDuplicates += '0';
    }

    return firstLetter + removedDuplicates;
}
