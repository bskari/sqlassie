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

/**
 * Tests various functions in MySqlConstants.
 * @author Brandon Skari
 * @date January 4 2012
 */

#include "testMySqlConstants.hpp"
#include "../MySqlConstants.hpp"

#include <boost/test/unit_test.hpp>


void testSoundex()
{
    // These checks taken from MySQL soundex function
    // Make sure extra punctuation is removed
    BOOST_CHECK(MySqlConstants::soundex("brandonskari") == "B653526");
    BOOST_CHECK(MySqlConstants::soundex("   B ran don Sk ari") == "B653526");
    BOOST_CHECK(MySqlConstants::soundex("\t\t&Bran42`d~on \t\t%%%^()Ska-9989ri---++=") == "B653526");
    BOOST_CHECK(MySqlConstants::soundex("rupert") == MySqlConstants::soundex("robert"));
    BOOST_CHECK(MySqlConstants::soundex("") == "");
    BOOST_CHECK(MySqlConstants::soundex("aardvark") == "A63162");
    BOOST_CHECK(MySqlConstants::soundex("euouae") == "E000");
    BOOST_CHECK(MySqlConstants::soundex("queueing") == "Q520");
    BOOST_CHECK(MySqlConstants::soundex("Aureolae") == "A640");

    // These checks taken from MySQL soundex function
    BOOST_CHECK(MySqlConstants::soundex("Akihitos") == "A232");
    BOOST_CHECK(MySqlConstants::soundex("Altheas") == "A432");
    BOOST_CHECK(MySqlConstants::soundex("Annapoliss") == "A5142");
    BOOST_CHECK(MySqlConstants::soundex("Armands") == "A6532");
    BOOST_CHECK(MySqlConstants::soundex("Australias") == "A23642");
    BOOST_CHECK(MySqlConstants::soundex("Barbarys") == "B6162");
    BOOST_CHECK(MySqlConstants::soundex("Bellamy") == "B450");
    BOOST_CHECK(MySqlConstants::soundex("Bioko") == "B200");
    BOOST_CHECK(MySqlConstants::soundex("Bourbaki") == "B612");
    BOOST_CHECK(MySqlConstants::soundex("Brownies") == "B652");
    BOOST_CHECK(MySqlConstants::soundex("Calaiss") == "C420");
    BOOST_CHECK(MySqlConstants::soundex("Carole") == "C640");
    BOOST_CHECK(MySqlConstants::soundex("Chandraguptas") == "C5362132");
    BOOST_CHECK(MySqlConstants::soundex("Christie") == "C623");
    BOOST_CHECK(MySqlConstants::soundex("Colon") == "C450");
    BOOST_CHECK(MySqlConstants::soundex("Cotswolds") == "C32432");
    BOOST_CHECK(MySqlConstants::soundex("Dalmatians") == "D45352");
    BOOST_CHECK(MySqlConstants::soundex("Delta") == "D430");
    BOOST_CHECK(MySqlConstants::soundex("Domingos") == "D520");
    BOOST_CHECK(MySqlConstants::soundex("Eakins") == "E252");
    BOOST_CHECK(MySqlConstants::soundex("Elvis") == "E412");
    BOOST_CHECK(MySqlConstants::soundex("Etta") == "E300");
    BOOST_CHECK(MySqlConstants::soundex("Feynman") == "F500");
    BOOST_CHECK(MySqlConstants::soundex("Freida") == "F630");
    BOOST_CHECK(MySqlConstants::soundex("Gates") == "G320");
    BOOST_CHECK(MySqlConstants::soundex("Glaxo") == "G420");
    BOOST_CHECK(MySqlConstants::soundex("Griegs") == "G620");
    BOOST_CHECK(MySqlConstants::soundex("Hamptons") == "H51352");
    BOOST_CHECK(MySqlConstants::soundex("Henchs") == "H520");
    BOOST_CHECK(MySqlConstants::soundex("Hohhots") == "H320");
    BOOST_CHECK(MySqlConstants::soundex("Id") == "I300");
    BOOST_CHECK(MySqlConstants::soundex("Ishmaels") == "I2542");
    BOOST_CHECK(MySqlConstants::soundex("Jean") == "J500");
    BOOST_CHECK(MySqlConstants::soundex("Josephines") == "J152");
    BOOST_CHECK(MySqlConstants::soundex("Kathryn") == "K365");
    BOOST_CHECK(MySqlConstants::soundex("Kiribati") == "K613");
    BOOST_CHECK(MySqlConstants::soundex("Kwanzaas") == "K520");
    BOOST_CHECK(MySqlConstants::soundex("Lebanese") == "L152");
    BOOST_CHECK(MySqlConstants::soundex("Limbaughs") == "L512");
    BOOST_CHECK(MySqlConstants::soundex("Loyds") == "L320");
    BOOST_CHECK(MySqlConstants::soundex("Madonna") == "M350");
    BOOST_CHECK(MySqlConstants::soundex("Maras") == "M620");
    BOOST_CHECK(MySqlConstants::soundex("MasterCards") == "M2362632");
    BOOST_CHECK(MySqlConstants::soundex("Meiers") == "M620");
    BOOST_CHECK(MySqlConstants::soundex("Middleton") == "M3435");
    BOOST_CHECK(MySqlConstants::soundex("Monas") == "M200");
    BOOST_CHECK(MySqlConstants::soundex("Muppet") == "M130");
    BOOST_CHECK(MySqlConstants::soundex("Negro") == "N260");
    BOOST_CHECK(MySqlConstants::soundex("Normas") == "N652");
    BOOST_CHECK(MySqlConstants::soundex("Ollies") == "O420");
    BOOST_CHECK(MySqlConstants::soundex("Palestinians") == "P42352");
    BOOST_CHECK(MySqlConstants::soundex("Pennys") == "P520");
    BOOST_CHECK(MySqlConstants::soundex("Plataea") == "P430");
    BOOST_CHECK(MySqlConstants::soundex("Procters") == "P62362");
    BOOST_CHECK(MySqlConstants::soundex("Rafaels") == "R142");
    BOOST_CHECK(MySqlConstants::soundex("Rice") == "R200");
    BOOST_CHECK(MySqlConstants::soundex("Ronnys") == "R520");
    BOOST_CHECK(MySqlConstants::soundex("Sade") == "S300");
    BOOST_CHECK(MySqlConstants::soundex("Saxons") == "S520");
    BOOST_CHECK(MySqlConstants::soundex("September") == "S13516");
    BOOST_CHECK(MySqlConstants::soundex("Siddhartha") == "S363");
    BOOST_CHECK(MySqlConstants::soundex("Southerner") == "S3656");
    BOOST_CHECK(MySqlConstants::soundex("Strombolis") == "S365142");
    BOOST_CHECK(MySqlConstants::soundex("Tagalog") == "T242");
    BOOST_CHECK(MySqlConstants::soundex("Tessa") == "T200");
    BOOST_CHECK(MySqlConstants::soundex("Tokugawa") == "T200");
    BOOST_CHECK(MySqlConstants::soundex("Turgenevs") == "T62512");
    BOOST_CHECK(MySqlConstants::soundex("Vang") == "V520");
    BOOST_CHECK(MySqlConstants::soundex("Vonda") == "V530");
    BOOST_CHECK(MySqlConstants::soundex("Whirlpools") == "W64142");
    BOOST_CHECK(MySqlConstants::soundex("Wycherley") == "W264");
    BOOST_CHECK(MySqlConstants::soundex("Zelma") == "Z450");
    BOOST_CHECK(MySqlConstants::soundex("abolishing") == "A14252");
    BOOST_CHECK(MySqlConstants::soundex("accepted") == "A213");
    BOOST_CHECK(MySqlConstants::soundex("acquiescent") == "A253");
    BOOST_CHECK(MySqlConstants::soundex("adjudicate") == "A32323");
    BOOST_CHECK(MySqlConstants::soundex("advised") == "A3123");
    BOOST_CHECK(MySqlConstants::soundex("agglutinations") == "A2435352");
    BOOST_CHECK(MySqlConstants::soundex("albumens") == "A4152");
    BOOST_CHECK(MySqlConstants::soundex("alphabetized") == "A41323");
    BOOST_CHECK(MySqlConstants::soundex("amorousnesss") == "A56252");
    BOOST_CHECK(MySqlConstants::soundex("anesthetists") == "A523232");
    BOOST_CHECK(MySqlConstants::soundex("antennas") == "A5352");
    BOOST_CHECK(MySqlConstants::soundex("apogees") == "A120");
    BOOST_CHECK(MySqlConstants::soundex("approved") == "A1613");
    BOOST_CHECK(MySqlConstants::soundex("aristocratically") == "A62326324");
    BOOST_CHECK(MySqlConstants::soundex("ascertained") == "A26353");
    BOOST_CHECK(MySqlConstants::soundex("assumptions") == "A251352");
    BOOST_CHECK(MySqlConstants::soundex("attractions") == "A362352");
    BOOST_CHECK(MySqlConstants::soundex("avasts") == "A1232");
    BOOST_CHECK(MySqlConstants::soundex("backdrop") == "B2361");
    BOOST_CHECK(MySqlConstants::soundex("balking") == "B4252");
    BOOST_CHECK(MySqlConstants::soundex("barbs") == "B612");
    BOOST_CHECK(MySqlConstants::soundex("bassoons") == "B252");
    BOOST_CHECK(MySqlConstants::soundex("beaus") == "B200");
    BOOST_CHECK(MySqlConstants::soundex("behavioral") == "B640");
    BOOST_CHECK(MySqlConstants::soundex("berylliums") == "B6452");
    BOOST_CHECK(MySqlConstants::soundex("bighearted") == "B263");
    BOOST_CHECK(MySqlConstants::soundex("bishop") == "B210");
    BOOST_CHECK(MySqlConstants::soundex("bleariest") == "B4623");
    BOOST_CHECK(MySqlConstants::soundex("blowouts") == "B432");
    BOOST_CHECK(MySqlConstants::soundex("bogys") == "B200");
    BOOST_CHECK(MySqlConstants::soundex("bootees") == "B320");
    BOOST_CHECK(MySqlConstants::soundex("boxings") == "B252");
    BOOST_CHECK(MySqlConstants::soundex("breast") == "B623");
    BOOST_CHECK(MySqlConstants::soundex("broader") == "B636");
    BOOST_CHECK(MySqlConstants::soundex("bucksaws") == "B200");
    BOOST_CHECK(MySqlConstants::soundex("bunchs") == "B520");
    BOOST_CHECK(MySqlConstants::soundex("bustle") == "B234");
    BOOST_CHECK(MySqlConstants::soundex("cadres") == "C362");
    BOOST_CHECK(MySqlConstants::soundex("camisoles") == "C5242");
    BOOST_CHECK(MySqlConstants::soundex("canvases") == "C512");
    BOOST_CHECK(MySqlConstants::soundex("cares") == "C620");
    BOOST_CHECK(MySqlConstants::soundex("cashiers") == "C620");
    BOOST_CHECK(MySqlConstants::soundex("catkins") == "C3252");
    BOOST_CHECK(MySqlConstants::soundex("centenary") == "C5356");
    BOOST_CHECK(MySqlConstants::soundex("chancellors") == "C52462");
    BOOST_CHECK(MySqlConstants::soundex("cheapnesss") == "C152");
    BOOST_CHECK(MySqlConstants::soundex("childish") == "C432");
    BOOST_CHECK(MySqlConstants::soundex("chortled") == "C6343");
    BOOST_CHECK(MySqlConstants::soundex("circumferences") == "C6251652");
    BOOST_CHECK(MySqlConstants::soundex("classroom") == "C4265");
    BOOST_CHECK(MySqlConstants::soundex("clod") == "C430");
    BOOST_CHECK(MySqlConstants::soundex("coauthors") == "C362");
    BOOST_CHECK(MySqlConstants::soundex("coiffed") == "C130");
    BOOST_CHECK(MySqlConstants::soundex("coltish") == "C432");
    BOOST_CHECK(MySqlConstants::soundex("commonwealths") == "C5432");
    BOOST_CHECK(MySqlConstants::soundex("composers") == "C51262");
    BOOST_CHECK(MySqlConstants::soundex("concurrences") == "C52652");
    BOOST_CHECK(MySqlConstants::soundex("confutes") == "C5132");
    BOOST_CHECK(MySqlConstants::soundex("consignment") == "C5253");
    BOOST_CHECK(MySqlConstants::soundex("contextual") == "C53234");
    BOOST_CHECK(MySqlConstants::soundex("convict") == "C5123");
    BOOST_CHECK(MySqlConstants::soundex("cornballs") == "C65142");
    BOOST_CHECK(MySqlConstants::soundex("costars") == "C362");
    BOOST_CHECK(MySqlConstants::soundex("courteous") == "C632");
    BOOST_CHECK(MySqlConstants::soundex("crankiness") == "C65252");
    BOOST_CHECK(MySqlConstants::soundex("crews") == "C620");
    BOOST_CHECK(MySqlConstants::soundex("crowbar") == "C616");
    BOOST_CHECK(MySqlConstants::soundex("culling") == "C452");
    BOOST_CHECK(MySqlConstants::soundex("cusps") == "C120");
    BOOST_CHECK(MySqlConstants::soundex("damaged") == "D523");
    BOOST_CHECK(MySqlConstants::soundex("deadbeat") == "D130");
    BOOST_CHECK(MySqlConstants::soundex("decently") == "D2534");
    BOOST_CHECK(MySqlConstants::soundex("defeating") == "D1352");
    BOOST_CHECK(MySqlConstants::soundex("deleted") == "D430");
    BOOST_CHECK(MySqlConstants::soundex("demurs") == "D562");
    BOOST_CHECK(MySqlConstants::soundex("deprive") == "D161");
    BOOST_CHECK(MySqlConstants::soundex("despoils") == "D2142");
    BOOST_CHECK(MySqlConstants::soundex("devotedly") == "D134");
    BOOST_CHECK(MySqlConstants::soundex("difficulty") == "D1243");
    BOOST_CHECK(MySqlConstants::soundex("direct") == "D623");
    BOOST_CHECK(MySqlConstants::soundex("discompose") == "D2512");
    BOOST_CHECK(MySqlConstants::soundex("dishing") == "D252");
    BOOST_CHECK(MySqlConstants::soundex("dispossess") == "D212");
    BOOST_CHECK(MySqlConstants::soundex("distressing") == "D236252");
    BOOST_CHECK(MySqlConstants::soundex("doffed") == "D130");
    BOOST_CHECK(MySqlConstants::soundex("dormitories") == "D65362");
    BOOST_CHECK(MySqlConstants::soundex("drainpipes") == "D6512");
    BOOST_CHECK(MySqlConstants::soundex("drove") == "D610");
    BOOST_CHECK(MySqlConstants::soundex("dunking") == "D5252");
    BOOST_CHECK(MySqlConstants::soundex("earthinesss") == "E6352");
    BOOST_CHECK(MySqlConstants::soundex("effected") == "E123");
    BOOST_CHECK(MySqlConstants::soundex("electrolyte") == "E423643");
    BOOST_CHECK(MySqlConstants::soundex("emblazoning") == "E514252");
    BOOST_CHECK(MySqlConstants::soundex("encapsulate") == "E521243");
    BOOST_CHECK(MySqlConstants::soundex("engrave") == "E5261");
    BOOST_CHECK(MySqlConstants::soundex("entomologist") == "E535423");
    BOOST_CHECK(MySqlConstants::soundex("equines") == "E252");
    BOOST_CHECK(MySqlConstants::soundex("estimates") == "E23532");
    BOOST_CHECK(MySqlConstants::soundex("evolving") == "E14152");
    BOOST_CHECK(MySqlConstants::soundex("exercise") == "E262");
    BOOST_CHECK(MySqlConstants::soundex("explains") == "E21452");
    BOOST_CHECK(MySqlConstants::soundex("extrapolate") == "E236143");
    BOOST_CHECK(MySqlConstants::soundex("faining") == "F520");
    BOOST_CHECK(MySqlConstants::soundex("fascist") == "F230");
    BOOST_CHECK(MySqlConstants::soundex("feelingly") == "F4524");
    BOOST_CHECK(MySqlConstants::soundex("fibula") == "F400");
    BOOST_CHECK(MySqlConstants::soundex("findings") == "F5352");
    BOOST_CHECK(MySqlConstants::soundex("fixations") == "F2352");
    BOOST_CHECK(MySqlConstants::soundex("flavor") == "F416");
    BOOST_CHECK(MySqlConstants::soundex("flounder") == "F4536");
    BOOST_CHECK(MySqlConstants::soundex("foggy") == "F200");
    BOOST_CHECK(MySqlConstants::soundex("forecastles") == "F62342");
    BOOST_CHECK(MySqlConstants::soundex("forsakes") == "F620");
    BOOST_CHECK(MySqlConstants::soundex("fraternal") == "F63654");
    BOOST_CHECK(MySqlConstants::soundex("friskiest") == "F623");
    BOOST_CHECK(MySqlConstants::soundex("functionary") == "F52356");
    BOOST_CHECK(MySqlConstants::soundex("gagged") == "G300");
    BOOST_CHECK(MySqlConstants::soundex("garish") == "G620");
    BOOST_CHECK(MySqlConstants::soundex("gelds") == "G432");
    BOOST_CHECK(MySqlConstants::soundex("getaways") == "G320");
    BOOST_CHECK(MySqlConstants::soundex("glance") == "G452");
    BOOST_CHECK(MySqlConstants::soundex("gnawings") == "G520");
    BOOST_CHECK(MySqlConstants::soundex("gorses") == "G620");
    BOOST_CHECK(MySqlConstants::soundex("graphs") == "G612");
    BOOST_CHECK(MySqlConstants::soundex("grimaces") == "G652");
    BOOST_CHECK(MySqlConstants::soundex("grumbler") == "G65146");
    BOOST_CHECK(MySqlConstants::soundex("gurus") == "G620");
    BOOST_CHECK(MySqlConstants::soundex("hairstyle") == "H6234");
    BOOST_CHECK(MySqlConstants::soundex("handstands") == "H5323532");
    BOOST_CHECK(MySqlConstants::soundex("harvesting") == "H612352");
    BOOST_CHECK(MySqlConstants::soundex("headsets") == "H3232");
    BOOST_CHECK(MySqlConstants::soundex("helicoptered") == "H421363");
    BOOST_CHECK(MySqlConstants::soundex("hertzs") == "H632");
    BOOST_CHECK(MySqlConstants::soundex("hippopotamuses") == "H1352");
    BOOST_CHECK(MySqlConstants::soundex("homburgs") == "H5162");
    BOOST_CHECK(MySqlConstants::soundex("hope") == "H100");
    BOOST_CHECK(MySqlConstants::soundex("housecleans") == "H2452");
    BOOST_CHECK(MySqlConstants::soundex("humorous") == "H562");
    BOOST_CHECK(MySqlConstants::soundex("hyperactives") == "H162312");
    BOOST_CHECK(MySqlConstants::soundex("idolatrys") == "I34362");
    BOOST_CHECK(MySqlConstants::soundex("immortally") == "I5634");
    BOOST_CHECK(MySqlConstants::soundex("implying") == "I51452");
    BOOST_CHECK(MySqlConstants::soundex("inaudible") == "I5314");
    BOOST_CHECK(MySqlConstants::soundex("increased") == "I52623");
    BOOST_CHECK(MySqlConstants::soundex("indolent") == "I53453");
    BOOST_CHECK(MySqlConstants::soundex("infinitives") == "I515312");
    BOOST_CHECK(MySqlConstants::soundex("initiators") == "I5362");
    BOOST_CHECK(MySqlConstants::soundex("insinuating") == "I525352");
    BOOST_CHECK(MySqlConstants::soundex("intelligibilitys") == "I53421432");
    BOOST_CHECK(MySqlConstants::soundex("interpositions") == "I53612352");
    BOOST_CHECK(MySqlConstants::soundex("invariants") == "I516532");
    BOOST_CHECK(MySqlConstants::soundex("irretrievable") == "I63614");
    BOOST_CHECK(MySqlConstants::soundex("japanned") == "J153");
    BOOST_CHECK(MySqlConstants::soundex("jived") == "J130");
    BOOST_CHECK(MySqlConstants::soundex("jumble") == "J514");
    BOOST_CHECK(MySqlConstants::soundex("keyhole") == "K400");
    BOOST_CHECK(MySqlConstants::soundex("kitchens") == "K3252");
    BOOST_CHECK(MySqlConstants::soundex("laburnum") == "L165");
    BOOST_CHECK(MySqlConstants::soundex("landscape") == "L5321");
    BOOST_CHECK(MySqlConstants::soundex("laundering") == "L53652");
    BOOST_CHECK(MySqlConstants::soundex("lectern") == "L2365");
    BOOST_CHECK(MySqlConstants::soundex("lesser") == "L260");
    BOOST_CHECK(MySqlConstants::soundex("lifeboat") == "L130");
    BOOST_CHECK(MySqlConstants::soundex("liniments") == "L532");
    BOOST_CHECK(MySqlConstants::soundex("loaders") == "L362");
    BOOST_CHECK(MySqlConstants::soundex("lonelinesss") == "L5452");
    BOOST_CHECK(MySqlConstants::soundex("loyaler") == "L600");
    BOOST_CHECK(MySqlConstants::soundex("lyres") == "L620");
    BOOST_CHECK(MySqlConstants::soundex("mailer") == "M460");
    BOOST_CHECK(MySqlConstants::soundex("mandibles") == "M3142");
    BOOST_CHECK(MySqlConstants::soundex("marchers") == "M6262");
    BOOST_CHECK(MySqlConstants::soundex("massages") == "M200");
    BOOST_CHECK(MySqlConstants::soundex("maxims") == "M252");
    BOOST_CHECK(MySqlConstants::soundex("melancholys") == "M45242");
    BOOST_CHECK(MySqlConstants::soundex("mes") == "M200");
    BOOST_CHECK(MySqlConstants::soundex("middays") == "M320");
    BOOST_CHECK(MySqlConstants::soundex("mimeograph") == "M261");
    BOOST_CHECK(MySqlConstants::soundex("misappropriated") == "M216163");
    BOOST_CHECK(MySqlConstants::soundex("misrepresented") == "M2616253");
    BOOST_CHECK(MySqlConstants::soundex("modestly") == "M3234");
    BOOST_CHECK(MySqlConstants::soundex("monoliths") == "M432");
    BOOST_CHECK(MySqlConstants::soundex("mortars") == "M6362");
    BOOST_CHECK(MySqlConstants::soundex("moussing") == "M252");
    BOOST_CHECK(MySqlConstants::soundex("mumps") == "M120");
    BOOST_CHECK(MySqlConstants::soundex("mysteried") == "M2363");
    BOOST_CHECK(MySqlConstants::soundex("natures") == "N362");
    BOOST_CHECK(MySqlConstants::soundex("nerdy") == "N630");
    BOOST_CHECK(MySqlConstants::soundex("nightclub") == "N23241");
    BOOST_CHECK(MySqlConstants::soundex("nonconformist") == "N2516523");
    BOOST_CHECK(MySqlConstants::soundex("notches") == "N320");
    BOOST_CHECK(MySqlConstants::soundex("nutrition") == "N3635");
    BOOST_CHECK(MySqlConstants::soundex("obstruction") == "O1236235");
    BOOST_CHECK(MySqlConstants::soundex("ohos") == "O200");
    BOOST_CHECK(MySqlConstants::soundex("opportunities") == "O163532");
    BOOST_CHECK(MySqlConstants::soundex("originator") == "O62536");
    BOOST_CHECK(MySqlConstants::soundex("outlaid") == "O343");
    BOOST_CHECK(MySqlConstants::soundex("overcomes") == "O16252");
    BOOST_CHECK(MySqlConstants::soundex("oversizing") == "O16252");
    BOOST_CHECK(MySqlConstants::soundex("padlock") == "P342");
    BOOST_CHECK(MySqlConstants::soundex("panegyrics") == "P5262");
    BOOST_CHECK(MySqlConstants::soundex("parapsychology") == "P61242");
    BOOST_CHECK(MySqlConstants::soundex("partook") == "P632");
    BOOST_CHECK(MySqlConstants::soundex("patterned") == "P3653");
    BOOST_CHECK(MySqlConstants::soundex("pedigree") == "P326");
    BOOST_CHECK(MySqlConstants::soundex("peppiest") == "P230");
    BOOST_CHECK(MySqlConstants::soundex("perniciously") == "P6524");
    BOOST_CHECK(MySqlConstants::soundex("petroleum") == "P3645");
    BOOST_CHECK(MySqlConstants::soundex("photocopiers") == "P32162");
    BOOST_CHECK(MySqlConstants::soundex("pigskins") == "P252");
    BOOST_CHECK(MySqlConstants::soundex("pirate") == "P630");
    BOOST_CHECK(MySqlConstants::soundex("plasterboards") == "P42361632");
    BOOST_CHECK(MySqlConstants::soundex("ploys") == "P420");
    BOOST_CHECK(MySqlConstants::soundex("polecat") == "P423");
    BOOST_CHECK(MySqlConstants::soundex("ponytail") == "P534");
    BOOST_CHECK(MySqlConstants::soundex("possessively") == "P214");
    BOOST_CHECK(MySqlConstants::soundex("practice") == "P6232");
    BOOST_CHECK(MySqlConstants::soundex("preempting") == "P651352");
    BOOST_CHECK(MySqlConstants::soundex("preses") == "P620");
    BOOST_CHECK(MySqlConstants::soundex("princes") == "P652");
    BOOST_CHECK(MySqlConstants::soundex("profanes") == "P6152");
    BOOST_CHECK(MySqlConstants::soundex("proofs") == "P612");
    BOOST_CHECK(MySqlConstants::soundex("protestations") == "P632352");
    BOOST_CHECK(MySqlConstants::soundex("puberty") == "P630");
    BOOST_CHECK(MySqlConstants::soundex("puppetry") == "P360");
    BOOST_CHECK(MySqlConstants::soundex("quack") == "Q000");
    BOOST_CHECK(MySqlConstants::soundex("queues") == "Q000");
    BOOST_CHECK(MySqlConstants::soundex("radiations") == "R352");
    BOOST_CHECK(MySqlConstants::soundex("randomnesss") == "R5352");
    BOOST_CHECK(MySqlConstants::soundex("ravishingly") == "R12524");
    BOOST_CHECK(MySqlConstants::soundex("rebating") == "R1352");
    BOOST_CHECK(MySqlConstants::soundex("recompensed") == "R251523");
    BOOST_CHECK(MySqlConstants::soundex("redistributed") == "R323613");
    BOOST_CHECK(MySqlConstants::soundex("reformatories") == "R165362");
    BOOST_CHECK(MySqlConstants::soundex("rehiring") == "R520");
    BOOST_CHECK(MySqlConstants::soundex("remands") == "R532");
    BOOST_CHECK(MySqlConstants::soundex("repartees") == "R1632");
    BOOST_CHECK(MySqlConstants::soundex("reputable") == "R1314");
    BOOST_CHECK(MySqlConstants::soundex("resplendences") == "R2145352");
    BOOST_CHECK(MySqlConstants::soundex("retraining") == "R3652");
    BOOST_CHECK(MySqlConstants::soundex("revoltingly") == "R143524");
    BOOST_CHECK(MySqlConstants::soundex("righteously") == "R2324");
    BOOST_CHECK(MySqlConstants::soundex("robbers") == "R162");
    BOOST_CHECK(MySqlConstants::soundex("rotations") == "R352");
    BOOST_CHECK(MySqlConstants::soundex("ruff") == "R100");
    BOOST_CHECK(MySqlConstants::soundex("sacrifices") == "S612");
    BOOST_CHECK(MySqlConstants::soundex("salutes") == "S432");
    BOOST_CHECK(MySqlConstants::soundex("satchels") == "S3242");
    BOOST_CHECK(MySqlConstants::soundex("scampis") == "S512");
    BOOST_CHECK(MySqlConstants::soundex("schoolwork") == "S462");
    BOOST_CHECK(MySqlConstants::soundex("scribes") == "S612");
    BOOST_CHECK(MySqlConstants::soundex("seashores") == "S620");
    BOOST_CHECK(MySqlConstants::soundex("seized") == "S300");
    BOOST_CHECK(MySqlConstants::soundex("separators") == "S16362");
    BOOST_CHECK(MySqlConstants::soundex("sewing") == "S520");
    BOOST_CHECK(MySqlConstants::soundex("shawls") == "S420");
    BOOST_CHECK(MySqlConstants::soundex("shirred") == "S630");
    BOOST_CHECK(MySqlConstants::soundex("showmanship") == "S521");
    BOOST_CHECK(MySqlConstants::soundex("sidestep") == "S3231");
    BOOST_CHECK(MySqlConstants::soundex("simulators") == "S54362");
    BOOST_CHECK(MySqlConstants::soundex("skied") == "S300");
    BOOST_CHECK(MySqlConstants::soundex("slaughterer") == "S4236");
    BOOST_CHECK(MySqlConstants::soundex("sloppiest") == "S4123");
    BOOST_CHECK(MySqlConstants::soundex("smokier") == "S526");
    BOOST_CHECK(MySqlConstants::soundex("snorers") == "S562");
    BOOST_CHECK(MySqlConstants::soundex("soggier") == "S600");
    BOOST_CHECK(MySqlConstants::soundex("sopped") == "S130");
    BOOST_CHECK(MySqlConstants::soundex("spangles") == "S15242");
    BOOST_CHECK(MySqlConstants::soundex("spellers") == "S1462");
    BOOST_CHECK(MySqlConstants::soundex("splitting") == "S14352");
    BOOST_CHECK(MySqlConstants::soundex("spritzed") == "S16323");
    BOOST_CHECK(MySqlConstants::soundex("stacked") == "S323");
    BOOST_CHECK(MySqlConstants::soundex("startling") == "S363452");
    BOOST_CHECK(MySqlConstants::soundex("steppes") == "S312");
    BOOST_CHECK(MySqlConstants::soundex("stockpile") == "S3214");
    BOOST_CHECK(MySqlConstants::soundex("stranglehold") == "S365243");
    BOOST_CHECK(MySqlConstants::soundex("strudels") == "S36342");
    BOOST_CHECK(MySqlConstants::soundex("subjectively") == "S12314");
    BOOST_CHECK(MySqlConstants::soundex("subways") == "S120");
    BOOST_CHECK(MySqlConstants::soundex("summering") == "S5652");
    BOOST_CHECK(MySqlConstants::soundex("supplements") == "S14532");
    BOOST_CHECK(MySqlConstants::soundex("suture") == "S360");
    BOOST_CHECK(MySqlConstants::soundex("swirl") == "S640");
    BOOST_CHECK(MySqlConstants::soundex("systematically") == "S35324");
    BOOST_CHECK(MySqlConstants::soundex("taming") == "T520");
    BOOST_CHECK(MySqlConstants::soundex("tattletales") == "T4342");
    BOOST_CHECK(MySqlConstants::soundex("telecommutes") == "T42532");
    BOOST_CHECK(MySqlConstants::soundex("tensors") == "T5262");
    BOOST_CHECK(MySqlConstants::soundex("thematics") == "T532");
    BOOST_CHECK(MySqlConstants::soundex("thousandths") == "T2532");
    BOOST_CHECK(MySqlConstants::soundex("tidal") == "T400");
    BOOST_CHECK(MySqlConstants::soundex("tireless") == "T642");
    BOOST_CHECK(MySqlConstants::soundex("tonier") == "T560");
    BOOST_CHECK(MySqlConstants::soundex("touchstone") == "T235");
    BOOST_CHECK(MySqlConstants::soundex("trampolines") == "T651452");
    BOOST_CHECK(MySqlConstants::soundex("transvestites") == "T6521232");
    BOOST_CHECK(MySqlConstants::soundex("trices") == "T620");
    BOOST_CHECK(MySqlConstants::soundex("troubadours") == "T61362");
    BOOST_CHECK(MySqlConstants::soundex("tumblers") == "T51462");
    BOOST_CHECK(MySqlConstants::soundex("twiddled") == "T430");
    BOOST_CHECK(MySqlConstants::soundex("umiaks") == "U520");
    BOOST_CHECK(MySqlConstants::soundex("uncoordinated") == "U526353");
    BOOST_CHECK(MySqlConstants::soundex("undertakers") == "U5363262");
    BOOST_CHECK(MySqlConstants::soundex("unhealthiest") == "U54323");
    BOOST_CHECK(MySqlConstants::soundex("unofficially") == "U5124");
    BOOST_CHECK(MySqlConstants::soundex("unsteadier") == "U5236");
    BOOST_CHECK(MySqlConstants::soundex("uprooted") == "U163");
    BOOST_CHECK(MySqlConstants::soundex("vaginas") == "V252");
    BOOST_CHECK(MySqlConstants::soundex("vealed") == "V430");
    BOOST_CHECK(MySqlConstants::soundex("vertex") == "V632");
    BOOST_CHECK(MySqlConstants::soundex("vindication") == "V53235");
    BOOST_CHECK(MySqlConstants::soundex("vocalists") == "V24232");
    BOOST_CHECK(MySqlConstants::soundex("wagered") == "W263");
    BOOST_CHECK(MySqlConstants::soundex("warmer") == "W656");
    BOOST_CHECK(MySqlConstants::soundex("wavered") == "W163");
    BOOST_CHECK(MySqlConstants::soundex("weirs") == "W620");
    BOOST_CHECK(MySqlConstants::soundex("whiniest") == "W523");
    BOOST_CHECK(MySqlConstants::soundex("wiggler") == "W246");
    BOOST_CHECK(MySqlConstants::soundex("wintry") == "W536");
    BOOST_CHECK(MySqlConstants::soundex("wooded") == "W300");
    BOOST_CHECK(MySqlConstants::soundex("wrap") == "W610");
    BOOST_CHECK(MySqlConstants::soundex("yearling") == "Y6452");
    BOOST_CHECK(MySqlConstants::soundex("zippers") == "Z162");
}


void testConvertRegex()
{
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("abc_de") == "^abc.de$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("%ab_a") == "^.*ab.a$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("abc_de") == "^abc.de$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("_%%__") == "^..*.*..$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("%\\_%") == "^.*_.*$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("\\%_\\%") == "^%.%$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex(".*") == "^\\.\\*$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("%\\%%.%*%") == "^.*%.*\\..*\\*.*$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("(a[^b]){2,3}|(c|d|[^e]+)*") ==
        "^\\(a\\[\\^b\\]\\)\\{2\\,3\\}\\|\\(c\\|d\\|\\[\\^e\\]\\+\\)\\*$");
    BOOST_CHECK(MySqlConstants::mySqlRegexToPerlRegex("ab_cd\\_sf.e?kl%l(k|)f*j%e\\%") ==
        "^ab.cd_sf\\.e\\?kl.*l\\(k\\|\\)f\\*j.*e%$");
}
