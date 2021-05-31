#!/usr/bin/python

''' 
Original Simplified code

t = [[[14586168612424419542, 14541121889201905637, 16748868775416160675, 8773336254753264971, 17476111989962044140, 12851090751652534656, 769320473991584680, 17643726021726070308, 18357882647857685945, 13538796384061610099, 1477001565574451452, 8633969643285546147], [2273205417713124696, 11848299281022209059, 9116359957875643523, 13336332834851887502, 3360334562945334821, 596948806089999970, 2748318221482652992, 7319517411554420964, 13602843790679350395, 5604422129727112635, 1634233891437448726, 8183485077577182032], [14499862640848407525, 250841361438391577, 9947806146845542654, 1856289386069333917, 16453431227137625600, 14862801950788544843, 17648616815920982361, 7023098512403165584, 1285750502695637697, 1169771794189702948, 4729650554142191194, 15882693513064312395], [9111214901620583823, 17516148618990980082, 119208524944332475, 16361492977773658172, 18076523777982832574, 7834987589315443227, 4717523900419308173, 3357221579634120007, 6066754409564225181, 12443278873111868977, 5184467787006601179, 14057944522841040737], [5858270620869682859, 11540780522932850142, 16677992906336259695, 3366749372174628946, 6554029428792699696, 11832738694177735399, 10569757204262932169, 17514226877222438116, 492063954631359734, 594143400074710991, 4123568648722452318, 867415420364512825], [14388309115375466439, 8306595701586321458, 7738352353086041661, 6241875051489388206, 17903547652211937974, 50930364728029066, 3973325635889487230, 256471474897332868, 9443744853222313808, 3236518987863944429, 17335622021394517203, 16213831917265414899], [3086431623297336087, 8518432483701197038, 4159279002208294167, 16997429753626683984, 13066862622888533678, 10786299688073873895, 11255562372772592650, 5590034580657540441, 5746068719239046763, 6498005893670088510, 16534828376917829504, 3153717479840323678], [6588405447493985660, 11255878264069256625, 1498502540495290613, 16895340516835473086, 12018093593712114203, 11066487837983851026, 373507127205945990, 13995474860969721920, 2959157596836532858, 5474051327379742390, 11231356098516250761, 6484309720562262839]], [[16724465982663280052, 2348921351873469095, 1470450344616180329, 4866287752592284249, 15175807381929928280, 14700955333458187823, 10713543572839956082, 7274169129683470339, 15899529342132266702, 8297193936610058630, 10998390243211094924, 13991062328971510869], [17900746894713495637, 10387969461598435041, 16210189037098056819, 5087592485341075911, 3370063027464811548, 942734294279816452, 1360515023950266126, 11590320229502638299, 8283303970677178090, 8524118236792287800, 3141475739049572501, 5351995102306974558], [12028944139035135489, 17966662226790278927, 14927748224312611030, 1013814967537242951, 9831516360682801921, 11094828134418956922, 8237122987678659119, 10088721701771520442, 9049584720571616450, 8179614762889098765, 2141354173125403847, 1183386254472165050], [1187255417954525148, 9724466642314178682, 270329461859199921, 7849262497313496349, 15328436458134221079, 15395661180448324883, 15857476331305247896, 3284539623631307568, 8995327438136485788, 17424995039934276316, 2031352113631406683, 13774677249399165299], [12862790671721252845, 2871337687899386211, 11923201802394805530, 2183871758569292420, 865511271762420629, 6800228876120056777, 9430219274510533534, 15336206638338966985, 18223208017345885228, 9083164381750618596, 14292898707989518227, 8932917623324518004], [14207051321282667015, 17783568569820650974, 15560933176275239808, 7299126227535558811, 11703111934126536780, 972301600364109117, 5765699471099725580, 8044592121434282194, 1163610804134091879, 8497295873518300906, 814960942050084195, 5163031367748684909], [16956441493581201316, 13995621344034442492, 2128478591246847466, 3994766320959017497, 14771289961556426271, 795056501027536013, 994801385378182343, 12152687589388778716, 2920517254572299871, 14253184557323452188, 4080112468369161437, 6281093703359001520], [2352085126820096267, 10160827339506947943, 7066018319340726105, 18255222873623105200, 14832967463315024999, 14597247942156592956, 16209627374783816007, 8681683582651076475, 14303719215144781757, 754830521800315330, 12903523593414664408, 7568199120062412874]], [[5842413865942023245, 14517418930023992139, 74556089488680610, 3891052305512597556, 15777570658534924795, 13197993204780081968, 10501825012209038266, 3637443820361173560, 8952315100234781481, 1118857095792813608, 16257716308957393820, 2862588299861085090], [8975421281571922609, 1052266136008449431, 11062596308662488389, 8849964357105117854, 2408172992167966360, 7509026273845554592, 7536086928565107590, 12052465341608674211, 9070762534119554349, 17074610473966350664, 9166738275208572305, 84573893684727546], [2960446212982787791, 17341818875156352121, 15084248339645870656, 6395130961698659244, 1111195101714363450, 7839374646870373843, 13866178738924985040, 8716596179720898458, 3925464899830281436, 2649345198117702726, 11598041907710063131, 3294096925645082893], [9841196968575301353, 10782469673722134049, 16539665726472587875, 10252390191428185247, 16148069137672008434, 3621466653539876435, 14724423911156565828, 5730408015055795056, 18203000583690757054, 16921202516479617715, 4363777357232723309, 2685174799906631255], [2487426668019134438, 14885009509429826690, 6666636911672224405, 10128626286270046747, 11847583891963838431, 7920750272405458619, 18252667541525677251, 8963148275078359612, 8611439525942223068, 12145863724234147565, 4986917085754502481, 10675115801814030419], [2775659208898973712, 14013925291575103787, 2356726262282283306, 16694172352080420897, 348004870121589147, 5060968559021370875, 11622637608827701700, 11037719206751553860, 4537533360392336120, 5288523573808642613, 2165630121156993092, 6150303582811483110], [6914334972790540195, 2714771450876304901, 18080461952077216414, 18011611224881878514, 13548667373177564281, 18033829192824739795, 5652456953253094934, 13652389522895551677, 10089371922637420384, 4766072674937288135, 14709820735044582804, 100071119538674192], [2689351859112484056, 7362353775847411518, 1840250726434272149, 17520609984290487761, 9217278994450994080, 6464573092752579181, 8545198790568897298, 16837350989205958929, 12953042434207142509, 15510178867333439243, 8953613131359665890, 1031166521949641150]], [[1749944585611448012, 3465864848342769521, 12265839745044871832, 18267042971950836436, 17157310116305944964, 6777710626638653472, 3172040038779591312, 5770065297300212332, 16189458954942463890, 11403738922866271764, 14007688460170463871, 111878400982508504], [14156827907028186779, 7721889972553807300, 887371198222706032, 8979650893349212070, 1539384513926070305, 11752827293088935224, 7784242762323924176, 176832345400408645, 12343654491197551632, 10082469480155244029, 4194980585841162070, 14718975453355785958], [1667305140433041971, 15595377941814739932, 3165167193233115266, 17289267390106649449, 150689826596934372, 18341216741751051610, 5005379685967026135, 12495326401045994525, 2806352094540337395, 9903161174906350430, 11919139270583329708, 11500875016637886856], [2286043502785988211, 7872095424626026574, 16563894952743868319, 4408329839572362951, 18155123497378218661, 12902407359772009165, 8865149947254745191, 17143029211258868948, 15733557398134048687, 4720346143459974364, 4420207605115323986, 9093462416959527572], [12249915362121119375, 8668322873766766449, 2348679393848468425, 18076566173740065516, 17513212968583160981, 2792845186845936937, 12683379603292416813, 1978559934856268871, 16956844471885024636, 13517557311450411322, 12631808044235759426, 16583207514153508040], [16449980024181002153, 16972203551027064316, 17727959256969461791, 17610913610006052716, 8196522987550526928, 11613584809803570715, 10373060861379556756, 14235041340440861464, 13119484215956582650, 6149797867924678493, 8502275908070981101, 3309418334912902304], [8465090004707576008, 4379250818575963384, 2502049713857648250, 9080775779571334279, 7880997681065488977, 11374468334787802211, 14230726139028209243, 352563841977690260, 18437531419301443865, 9463283882776136172, 5349527181973981012, 2580752542655242574], [10890575104826632442, 2449526278978111358, 6060508785815223686, 11758099717512767228, 4616577479501921087, 9633061021221910428, 15111913884585171112, 1389839317632481917, 11885184540635276568, 3272988541963837464, 8960647733035152230, 12203856936970445518]], [
    [9733231344669328735, 5548733193108641819, 4705172363568415797, 11781209478868943448, 1919228145651407633, 1775330446546392353, 10724807573345526551, 1967283232905637602, 6515773239107448421, 13653806088615625161, 643546966244998855, 10681809698512937744], [17285057401469898965, 10304573974850975125, 6328338977297187411, 4517129014502432919, 17921369186519858830, 2457736372262443587, 195867948177829059, 7938937722311000187, 14218929416258863338, 9347673468375432500, 3241841897702419736, 10746911945805174976], [1554628878835337516, 1315962507125352689, 15980006650457474654, 14025335940556292136, 11996715072966883839, 10263117305964118734, 6103778675720005639, 14493309045974402926, 636546665555841134, 1447835596568559102, 1820676179077403493, 17611680291342768101], [15752743012715710409, 1069204384403491832, 8681410974737286725, 10279912839048608529, 12466206848981967349, 12108307333641394964, 7017488702758899440, 4210106327330151040, 12443030702696066290, 6741007069741674078, 813532297964263359, 13158255591531498244], [7830903105857100924, 18251945699376260952, 2748043292979030692, 9029758625218703567, 11711418608702970485, 3958117126019910773, 14690711094563190232, 1352008166183212766, 10760151434863147786, 16955422982451864917, 3421285272335313725, 14137670255833520067], [12047044389829388399, 571103914872873630, 12367260525713275925, 4493706752595869745, 6270347175400406400, 5993393662627087109, 11626517494770647206, 6041994049220883424, 7971253973256725577, 14542039214001557552, 599550088197781209, 3751281844625774621], [18000340782513786819, 17117735421902891198, 825812718962249352, 8924611489215641424, 3599683406219071161, 8528158238098480016, 16086948782942490971, 5064266944641258838, 15880497664380128242, 15774298213143908000, 5071939610338034840, 15770931848393261410], [9658832362643474197, 18033244835173753647, 4101885028868187697, 105887552555968243, 2952608566257631572, 1095731799474328072, 13444506094656192753, 5712280710246162929, 6475958422144764849, 14859003958311422233, 18013536275004226312, 741850955103306816]], [[7006919629650631586, 5537601628452959580, 7212076025103765952, 10245773489411584391, 7807270704703322700, 2203923223528622308, 3993938768572151545, 13193841193728067072, 137634461210737815, 11300160437631887555, 4328741338547670889, 16284673274074039125], [14717278398306541497, 10189170804253038287, 1741480310047288860, 9572790705058443772, 4653065447777421814, 16862512143720489260, 13854148416645798068, 12797120931827438905, 16301626116157083014, 13250959920764001060, 10870349129804602659, 6009411360479418063], [3759147821560899156, 10773766556087375738, 2295572981190360670, 4254658370350597514, 11154703230825797447, 11350160538808462040, 6579352032389884042, 9801984944620249509, 8101329473071636433, 6391125925636527785, 11893773129367555692, 16786352726662643000], [2339136812480712409, 8171404571975137867, 7006815446249165913, 9002194230252505803, 14093890993276811521, 2413849616086358459, 16140486973683360730, 952716377275843125, 10307401455320959342, 17709783684534609601, 10515836417812756409, 2118370427717003616], [10652201621160070918, 15046276837028797247, 11703523505500271688, 12265858968543297487, 1966013264906485105, 10764472217572857485, 15826103915358434175, 7777016262533949872, 15597945584849495984, 17421698395269522576, 2655112251932262547, 1664623629088386009], [6686061357415315782, 11410326515682703060, 7664824483665637543, 8596947157730227727, 17230487002487586809, 11748623996858567638, 14332706359819641862, 13053077707435720712, 9208209397405214641, 12000851756890913542, 17690662213184560896, 13741921823224515564], [4916639549318050784, 5245652587905115594, 16738096241532632571, 12190988591391638850, 18307305243272547679, 13348216565398599441, 2345221132844026477, 5341351442877541548, 7380526113918485205, 17801854134402114873, 890307752407036614, 7435739250916998388], [8689096783713743979, 3151592226914620421, 16614433031463627664, 4471500400672391738, 2112487408439498509, 5755384923320960563, 1148490323301658496, 8028929252276898592, 7678111343260614140, 2737534649755955796, 8961022104883265201, 5880954026813340011]], [[7616914967537244050, 7365803020768918243, 8711920488976059619, 8938790624474449040, 1159159104162528454, 16949256903685896013, 12473408401660304914, 10905308386699668977, 17925791636244140455, 9288990354238109189, 15173017305619320627, 3463884327747587051], [11859829041479461221, 3629964463178909179, 9871567050322488464, 14657457708816829588, 4152347064914825707, 14839124408983216972, 16476290425232237273, 3724207094362160388, 14582395040476960107, 11551336631247364675, 18376036630900844554, 17052013930078737531], [12394137988941655005, 6674425122712002108, 10753659570829623166, 6418776207487767533, 17797727469836248119, 1515800202582718216, 1740912449353622785, 16672218112507242588, 4032132732989464596, 2929698391297755863, 9474286119892527210, 17087629547700286766], [1308081652790024712, 230501589390101400, 6303549647552995706, 18164677049654481248, 14180488224975822649, 9023806624284850871, 15860803726873828651, 14638384725208860442, 14821721451569336683, 11951376201960229682, 2899717178035499511, 10617241643398221930], [8167379152646388710, 2017451277858508104, 1205158668245396952, 14067723394688549768, 9277712353641366755, 16973050690199374724, 10523853458743005118, 8460978452920310890, 4884642775040807175, 270580780234877650, 12172516839198928151, 9633778864419401898], [11028821325278624208, 10330420171989894507, 12280290454179212181, 13416687020400751431, 10155547210140796629, 2032485900619015456, 14733536338504429370, 5415206329611435123, 4579118454145583424, 6148675580352751078, 8026759258572882707, 5001308161000419825], [307162144960338366, 5403723290971859906, 8390662671866308813, 9758824080385858152, 974994808658216282, 16146690164614366068, 11175953905457728618, 1620320475813026201, 4923271553630224983, 1147472878557554449, 8201712344122064432, 5618594440038450106], [9603298805104121809, 6862051559275089008, 12939581300414102791, 12505087044275509296, 1701661582820968570, 4439875090798297524, 4461877569401315594, 4224471956132743449, 8898657515345699643, 17393476357479495248, 8399594708527604053, 10006319982923178493]], [[2555416427821776030, 11402924978444658325, 12941203519022988107, 5311175269429115704, 2773823741371004728, 11253220130998607824, 8416440214424612145, 10249472772577991048, 2084226548005411333, 10590523218113339458, 15288312366426920670, 13270472079063015591], [17781269279280225446, 13015292421708890517, 15342531837049364923, 13681235415385618305, 11788274640615749814, 8687637348604723495, 5803769027927405788, 7121551599680162986, 17296664960917118046, 7456147676597847385, 2492660745651716303, 5425349426979739575], [16334486434132542503, 14591539152589566374, 17302994393845051411, 6131703842960426874, 9067986825273227479, 11408332851191607709, 10954327950070293060, 3386563186304236250, 2478318980704765835, 6668746760754594437, 342560441454420260, 9190223454038750216], [12668938522591992844, 9741476227319238324, 6890621764172383629, 5424339090479052114, 6127703160145610211, 308064909272341656, 13993541688018413137, 10880366299923602509, 15840093449820427478, 16921252653733870444, 9854779170231874705, 11099366986477949240], [3078358950631700073, 6258801842645824120, 13050112696410388346, 3752858604713647119, 14200871668514327381, 3097139536349110293, 4383879905928334233, 3724663656796115326, 12290011123439205282, 11735787420955473676, 6788452111004226644, 1841877522774376961], [13796859120857865020, 5558369248921807556, 8363944458246729175, 2666885242527112949, 1241145176945632240, 10315241685965717872, 16758852625868778192, 15086522952413569712, 2430254104369320087, 17933427592729961399, 9949436930775163011, 8805948802964418229], [16552022403549484528, 3009499922975509181, 4735203310083606941, 2431757487473540923, 6721085760516283975, 13995921374600251446, 6233528110197926270, 3892704558279470070, 7539171844680129677, 11157089102175406956, 8358168820526681882, 13738541267119909974], [18346136916279031454, 1764327637720352020, 14565932671983186982, 14222284630315978850, 4678386085323381197, 17061206254994332795, 6260301950936826740, 12622793439466874773, 2001185040820435755, 9393970415083662987, 4175315046250555234, 14179846691355520120]]]

m = {k: v for v, k in enumerate('PNBRQKpnbrqk')}


def hash(b):
    h = 0
    for i in range(8):
        for j in range(8):
            if b[i][j] in m:
                p = m[b[i][j]]
                h ^= t[i][j][p]
    return f'%016x' % h

'''

t = [[[14586168612424419542, 14541121889201905637, 16748868775416160675, 8773336254753264971, 17476111989962044140, 12851090751652534656, 769320473991584680, 17643726021726070308, 18357882647857685945, 13538796384061610099, 1477001565574451452, 8633969643285546147], [2273205417713124696, 11848299281022209059, 9116359957875643523, 13336332834851887502, 3360334562945334821, 596948806089999970, 2748318221482652992, 7319517411554420964, 13602843790679350395, 5604422129727112635, 1634233891437448726, 8183485077577182032], [14499862640848407525, 250841361438391577, 9947806146845542654, 1856289386069333917, 16453431227137625600, 14862801950788544843, 17648616815920982361, 7023098512403165584, 1285750502695637697, 1169771794189702948, 4729650554142191194, 15882693513064312395], [9111214901620583823, 17516148618990980082, 119208524944332475, 16361492977773658172, 18076523777982832574, 7834987589315443227, 4717523900419308173, 3357221579634120007, 6066754409564225181, 12443278873111868977, 5184467787006601179, 14057944522841040737], [5858270620869682859, 11540780522932850142, 16677992906336259695, 3366749372174628946, 6554029428792699696, 11832738694177735399, 10569757204262932169, 17514226877222438116, 492063954631359734, 594143400074710991, 4123568648722452318, 867415420364512825], [14388309115375466439, 8306595701586321458, 7738352353086041661, 6241875051489388206, 17903547652211937974, 50930364728029066, 3973325635889487230, 256471474897332868, 9443744853222313808, 3236518987863944429, 17335622021394517203, 16213831917265414899], [3086431623297336087, 8518432483701197038, 4159279002208294167, 16997429753626683984, 13066862622888533678, 10786299688073873895, 11255562372772592650, 5590034580657540441, 5746068719239046763, 6498005893670088510, 16534828376917829504, 3153717479840323678], [6588405447493985660, 11255878264069256625, 1498502540495290613, 16895340516835473086, 12018093593712114203, 11066487837983851026, 373507127205945990, 13995474860969721920, 2959157596836532858, 5474051327379742390, 11231356098516250761, 6484309720562262839]], [[16724465982663280052, 2348921351873469095, 1470450344616180329, 4866287752592284249, 15175807381929928280, 14700955333458187823, 10713543572839956082, 7274169129683470339, 15899529342132266702, 8297193936610058630, 10998390243211094924, 13991062328971510869], [17900746894713495637, 10387969461598435041, 16210189037098056819, 5087592485341075911, 3370063027464811548, 942734294279816452, 1360515023950266126, 11590320229502638299, 8283303970677178090, 8524118236792287800, 3141475739049572501, 5351995102306974558], [12028944139035135489, 17966662226790278927, 14927748224312611030, 1013814967537242951, 9831516360682801921, 11094828134418956922, 8237122987678659119, 10088721701771520442, 9049584720571616450, 8179614762889098765, 2141354173125403847, 1183386254472165050], [1187255417954525148, 9724466642314178682, 270329461859199921, 7849262497313496349, 15328436458134221079, 15395661180448324883, 15857476331305247896, 3284539623631307568, 8995327438136485788, 17424995039934276316, 2031352113631406683, 13774677249399165299], [12862790671721252845, 2871337687899386211, 11923201802394805530, 2183871758569292420, 865511271762420629, 6800228876120056777, 9430219274510533534, 15336206638338966985, 18223208017345885228, 9083164381750618596, 14292898707989518227, 8932917623324518004], [14207051321282667015, 17783568569820650974, 15560933176275239808, 7299126227535558811, 11703111934126536780, 972301600364109117, 5765699471099725580, 8044592121434282194, 1163610804134091879, 8497295873518300906, 814960942050084195, 5163031367748684909], [16956441493581201316, 13995621344034442492, 2128478591246847466, 3994766320959017497, 14771289961556426271, 795056501027536013, 994801385378182343, 12152687589388778716, 2920517254572299871, 14253184557323452188, 4080112468369161437, 6281093703359001520], [2352085126820096267, 10160827339506947943, 7066018319340726105, 18255222873623105200, 14832967463315024999, 14597247942156592956, 16209627374783816007, 8681683582651076475, 14303719215144781757, 754830521800315330, 12903523593414664408, 7568199120062412874]], [[5842413865942023245, 14517418930023992139, 74556089488680610, 3891052305512597556, 15777570658534924795, 13197993204780081968, 10501825012209038266, 3637443820361173560, 8952315100234781481, 1118857095792813608, 16257716308957393820, 2862588299861085090], [8975421281571922609, 1052266136008449431, 11062596308662488389, 8849964357105117854, 2408172992167966360, 7509026273845554592, 7536086928565107590, 12052465341608674211, 9070762534119554349, 17074610473966350664, 9166738275208572305, 84573893684727546], [2960446212982787791, 17341818875156352121, 15084248339645870656, 6395130961698659244, 1111195101714363450, 7839374646870373843, 13866178738924985040, 8716596179720898458, 3925464899830281436, 2649345198117702726, 11598041907710063131, 3294096925645082893], [9841196968575301353, 10782469673722134049, 16539665726472587875, 10252390191428185247, 16148069137672008434, 3621466653539876435, 14724423911156565828, 5730408015055795056, 18203000583690757054, 16921202516479617715, 4363777357232723309, 2685174799906631255], [2487426668019134438, 14885009509429826690, 6666636911672224405, 10128626286270046747, 11847583891963838431, 7920750272405458619, 18252667541525677251, 8963148275078359612, 8611439525942223068, 12145863724234147565, 4986917085754502481, 10675115801814030419], [2775659208898973712, 14013925291575103787, 2356726262282283306, 16694172352080420897, 348004870121589147, 5060968559021370875, 11622637608827701700, 11037719206751553860, 4537533360392336120, 5288523573808642613, 2165630121156993092, 6150303582811483110], [6914334972790540195, 2714771450876304901, 18080461952077216414, 18011611224881878514, 13548667373177564281, 18033829192824739795, 5652456953253094934, 13652389522895551677, 10089371922637420384, 4766072674937288135, 14709820735044582804, 100071119538674192], [2689351859112484056, 7362353775847411518, 1840250726434272149, 17520609984290487761, 9217278994450994080, 6464573092752579181, 8545198790568897298, 16837350989205958929, 12953042434207142509, 15510178867333439243, 8953613131359665890, 1031166521949641150]], [[1749944585611448012, 3465864848342769521, 12265839745044871832, 18267042971950836436, 17157310116305944964, 6777710626638653472, 3172040038779591312, 5770065297300212332, 16189458954942463890, 11403738922866271764, 14007688460170463871, 111878400982508504], [14156827907028186779, 7721889972553807300, 887371198222706032, 8979650893349212070, 1539384513926070305, 11752827293088935224, 7784242762323924176, 176832345400408645, 12343654491197551632, 10082469480155244029, 4194980585841162070, 14718975453355785958], [1667305140433041971, 15595377941814739932, 3165167193233115266, 17289267390106649449, 150689826596934372, 18341216741751051610, 5005379685967026135, 12495326401045994525, 2806352094540337395, 9903161174906350430, 11919139270583329708, 11500875016637886856], [2286043502785988211, 7872095424626026574, 16563894952743868319, 4408329839572362951, 18155123497378218661, 12902407359772009165, 8865149947254745191, 17143029211258868948, 15733557398134048687, 4720346143459974364, 4420207605115323986, 9093462416959527572], [12249915362121119375, 8668322873766766449, 2348679393848468425, 18076566173740065516, 17513212968583160981, 2792845186845936937, 12683379603292416813, 1978559934856268871, 16956844471885024636, 13517557311450411322, 12631808044235759426, 16583207514153508040], [16449980024181002153, 16972203551027064316, 17727959256969461791, 17610913610006052716, 8196522987550526928, 11613584809803570715, 10373060861379556756, 14235041340440861464, 13119484215956582650, 6149797867924678493, 8502275908070981101, 3309418334912902304], [8465090004707576008, 4379250818575963384, 2502049713857648250, 9080775779571334279, 7880997681065488977, 11374468334787802211, 14230726139028209243, 352563841977690260, 18437531419301443865, 9463283882776136172, 5349527181973981012, 2580752542655242574], [10890575104826632442, 2449526278978111358, 6060508785815223686, 11758099717512767228, 4616577479501921087, 9633061021221910428, 15111913884585171112, 1389839317632481917, 11885184540635276568, 3272988541963837464, 8960647733035152230, 12203856936970445518]], [
    [9733231344669328735, 5548733193108641819, 4705172363568415797, 11781209478868943448, 1919228145651407633, 1775330446546392353, 10724807573345526551, 1967283232905637602, 6515773239107448421, 13653806088615625161, 643546966244998855, 10681809698512937744], [17285057401469898965, 10304573974850975125, 6328338977297187411, 4517129014502432919, 17921369186519858830, 2457736372262443587, 195867948177829059, 7938937722311000187, 14218929416258863338, 9347673468375432500, 3241841897702419736, 10746911945805174976], [1554628878835337516, 1315962507125352689, 15980006650457474654, 14025335940556292136, 11996715072966883839, 10263117305964118734, 6103778675720005639, 14493309045974402926, 636546665555841134, 1447835596568559102, 1820676179077403493, 17611680291342768101], [15752743012715710409, 1069204384403491832, 8681410974737286725, 10279912839048608529, 12466206848981967349, 12108307333641394964, 7017488702758899440, 4210106327330151040, 12443030702696066290, 6741007069741674078, 813532297964263359, 13158255591531498244], [7830903105857100924, 18251945699376260952, 2748043292979030692, 9029758625218703567, 11711418608702970485, 3958117126019910773, 14690711094563190232, 1352008166183212766, 10760151434863147786, 16955422982451864917, 3421285272335313725, 14137670255833520067], [12047044389829388399, 571103914872873630, 12367260525713275925, 4493706752595869745, 6270347175400406400, 5993393662627087109, 11626517494770647206, 6041994049220883424, 7971253973256725577, 14542039214001557552, 599550088197781209, 3751281844625774621], [18000340782513786819, 17117735421902891198, 825812718962249352, 8924611489215641424, 3599683406219071161, 8528158238098480016, 16086948782942490971, 5064266944641258838, 15880497664380128242, 15774298213143908000, 5071939610338034840, 15770931848393261410], [9658832362643474197, 18033244835173753647, 4101885028868187697, 105887552555968243, 2952608566257631572, 1095731799474328072, 13444506094656192753, 5712280710246162929, 6475958422144764849, 14859003958311422233, 18013536275004226312, 741850955103306816]], [[7006919629650631586, 5537601628452959580, 7212076025103765952, 10245773489411584391, 7807270704703322700, 2203923223528622308, 3993938768572151545, 13193841193728067072, 137634461210737815, 11300160437631887555, 4328741338547670889, 16284673274074039125], [14717278398306541497, 10189170804253038287, 1741480310047288860, 9572790705058443772, 4653065447777421814, 16862512143720489260, 13854148416645798068, 12797120931827438905, 16301626116157083014, 13250959920764001060, 10870349129804602659, 6009411360479418063], [3759147821560899156, 10773766556087375738, 2295572981190360670, 4254658370350597514, 11154703230825797447, 11350160538808462040, 6579352032389884042, 9801984944620249509, 8101329473071636433, 6391125925636527785, 11893773129367555692, 16786352726662643000], [2339136812480712409, 8171404571975137867, 7006815446249165913, 9002194230252505803, 14093890993276811521, 2413849616086358459, 16140486973683360730, 952716377275843125, 10307401455320959342, 17709783684534609601, 10515836417812756409, 2118370427717003616], [10652201621160070918, 15046276837028797247, 11703523505500271688, 12265858968543297487, 1966013264906485105, 10764472217572857485, 15826103915358434175, 7777016262533949872, 15597945584849495984, 17421698395269522576, 2655112251932262547, 1664623629088386009], [6686061357415315782, 11410326515682703060, 7664824483665637543, 8596947157730227727, 17230487002487586809, 11748623996858567638, 14332706359819641862, 13053077707435720712, 9208209397405214641, 12000851756890913542, 17690662213184560896, 13741921823224515564], [4916639549318050784, 5245652587905115594, 16738096241532632571, 12190988591391638850, 18307305243272547679, 13348216565398599441, 2345221132844026477, 5341351442877541548, 7380526113918485205, 17801854134402114873, 890307752407036614, 7435739250916998388], [8689096783713743979, 3151592226914620421, 16614433031463627664, 4471500400672391738, 2112487408439498509, 5755384923320960563, 1148490323301658496, 8028929252276898592, 7678111343260614140, 2737534649755955796, 8961022104883265201, 5880954026813340011]], [[7616914967537244050, 7365803020768918243, 8711920488976059619, 8938790624474449040, 1159159104162528454, 16949256903685896013, 12473408401660304914, 10905308386699668977, 17925791636244140455, 9288990354238109189, 15173017305619320627, 3463884327747587051], [11859829041479461221, 3629964463178909179, 9871567050322488464, 14657457708816829588, 4152347064914825707, 14839124408983216972, 16476290425232237273, 3724207094362160388, 14582395040476960107, 11551336631247364675, 18376036630900844554, 17052013930078737531], [12394137988941655005, 6674425122712002108, 10753659570829623166, 6418776207487767533, 17797727469836248119, 1515800202582718216, 1740912449353622785, 16672218112507242588, 4032132732989464596, 2929698391297755863, 9474286119892527210, 17087629547700286766], [1308081652790024712, 230501589390101400, 6303549647552995706, 18164677049654481248, 14180488224975822649, 9023806624284850871, 15860803726873828651, 14638384725208860442, 14821721451569336683, 11951376201960229682, 2899717178035499511, 10617241643398221930], [8167379152646388710, 2017451277858508104, 1205158668245396952, 14067723394688549768, 9277712353641366755, 16973050690199374724, 10523853458743005118, 8460978452920310890, 4884642775040807175, 270580780234877650, 12172516839198928151, 9633778864419401898], [11028821325278624208, 10330420171989894507, 12280290454179212181, 13416687020400751431, 10155547210140796629, 2032485900619015456, 14733536338504429370, 5415206329611435123, 4579118454145583424, 6148675580352751078, 8026759258572882707, 5001308161000419825], [307162144960338366, 5403723290971859906, 8390662671866308813, 9758824080385858152, 974994808658216282, 16146690164614366068, 11175953905457728618, 1620320475813026201, 4923271553630224983, 1147472878557554449, 8201712344122064432, 5618594440038450106], [9603298805104121809, 6862051559275089008, 12939581300414102791, 12505087044275509296, 1701661582820968570, 4439875090798297524, 4461877569401315594, 4224471956132743449, 8898657515345699643, 17393476357479495248, 8399594708527604053, 10006319982923178493]], [[2555416427821776030, 11402924978444658325, 12941203519022988107, 5311175269429115704, 2773823741371004728, 11253220130998607824, 8416440214424612145, 10249472772577991048, 2084226548005411333, 10590523218113339458, 15288312366426920670, 13270472079063015591], [17781269279280225446, 13015292421708890517, 15342531837049364923, 13681235415385618305, 11788274640615749814, 8687637348604723495, 5803769027927405788, 7121551599680162986, 17296664960917118046, 7456147676597847385, 2492660745651716303, 5425349426979739575], [16334486434132542503, 14591539152589566374, 17302994393845051411, 6131703842960426874, 9067986825273227479, 11408332851191607709, 10954327950070293060, 3386563186304236250, 2478318980704765835, 6668746760754594437, 342560441454420260, 9190223454038750216], [12668938522591992844, 9741476227319238324, 6890621764172383629, 5424339090479052114, 6127703160145610211, 308064909272341656, 13993541688018413137, 10880366299923602509, 15840093449820427478, 16921252653733870444, 9854779170231874705, 11099366986477949240], [3078358950631700073, 6258801842645824120, 13050112696410388346, 3752858604713647119, 14200871668514327381, 3097139536349110293, 4383879905928334233, 3724663656796115326, 12290011123439205282, 11735787420955473676, 6788452111004226644, 1841877522774376961], [13796859120857865020, 5558369248921807556, 8363944458246729175, 2666885242527112949, 1241145176945632240, 10315241685965717872, 16758852625868778192, 15086522952413569712, 2430254104369320087, 17933427592729961399, 9949436930775163011, 8805948802964418229], [16552022403549484528, 3009499922975509181, 4735203310083606941, 2431757487473540923, 6721085760516283975, 13995921374600251446, 6233528110197926270, 3892704558279470070, 7539171844680129677, 11157089102175406956, 8358168820526681882, 13738541267119909974], [18346136916279031454, 1764327637720352020, 14565932671983186982, 14222284630315978850, 4678386085323381197, 17061206254994332795, 6260301950936826740, 12622793439466874773, 2001185040820435755, 9393970415083662987, 4175315046250555234, 14179846691355520120]]]


m = {k: v for v, k in enumerate('PNBRQKpnbrqk')}
m_inv = {v: k for v, k in enumerate('PNBRQKpnbrqk')}
alpa = 'abcdefgh'



new_t = []
# flatten the array to make it easier to search
for i in range(len(t)):
    for j in range(len(t[i])):
        for k in range(len(t[i][j])):
            new_t.append(t[i][j][k])


def find(el, l=t):
    for i in range(len(l)):
        for j in range(len(l[i])):
            for k in range(len(l[i][j])):
                if el == l[i][j][k]:
                    return i,j,k
    return None


def get_move(res):
    for i in range(len(new_t)):
        for j in range(len(new_t)-1):
            if new_t[i] ^ new_t[j] == res:
                # print(f'{i} - {j}')
                c1, r1, p1 = find(new_t[i])
                c2, r2, _ = find(new_t[j])
                # print(f"Start Pos: {r1} {c1}")
                # print(f"End Pos: {r2} {c2}")
                # print(f"Piece Moved: {m_inv[p1]}")
                print(f"Possible Move a: {m_inv[p1]}{alpa[r1]}{8-c1}")
                print(f"Possible Move b: {m_inv[p1]}{alpa[r2]}{8-c2}")
                return
    print(f"A piece must have been taken!")


if __name__ == "__main__":
    hashes = [int(x,16) for x in open("hashes.txt", 'r').read().split("\n")]
    for i, (h1, h2) in enumerate(zip(hashes, hashes[1::])):
        print(f"-------Turn {i}-------")
        get_move(h1 ^ h2)
