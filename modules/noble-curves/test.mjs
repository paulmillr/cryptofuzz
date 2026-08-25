import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const bundle = fs.readFileSync(new URL('./noble-curves.js', import.meta.url), 'utf8');
const idSource = fs.readFileSync(new URL('./ids.js', import.meta.url), 'utf8');
const ids = Object.fromEntries(
  [...idSource.matchAll(/export const Is(\w+) = function\(id\) \{ return id == BigInt\("(\d+)"\); \}/g)]
    .map((match) => [match[1], match[2]])
);

function run(operation, input) {
  const context = {
    FuzzerInput: JSON.stringify({ ...input, operation: ids[operation] }),
    FuzzerOutput: undefined,
  };
  vm.runInNewContext(bundle, context);
  return context.FuzzerOutput === undefined ? undefined : JSON.parse(context.FuzzerOutput);
}

const secp = run('ECC_PrivateToPublic', { curveType: ids.secp256k1, priv: '1' });
assert.deepEqual(secp, [
  '55066263022277343669578718895168534326250603453777594175500187360389116729240',
  '32670510020758816978083085130507043184471273380659243275938904335757337482424',
]);

const secpSignature = run('ECDSA_Sign', {
  curveType: ids.secp256k1,
  digestType: ids.SHA256,
  cleartext: '010203',
  priv: '1',
});
assert.ok(secpSignature);
assert.equal(run('ECDSA_Verify', {
  curveType: ids.secp256k1,
  digestType: ids.SHA256,
  cleartext: '010203',
  pub_x: secpSignature.pub[0],
  pub_y: secpSignature.pub[1],
  sig_r: secpSignature.signature[0],
  sig_s: secpSignature.signature[1],
}), true);

const secpDouble = run('ECC_Point_Dbl', {
  curveType: ids.secp256k1,
  a_x: secp[0],
  a_y: secp[1],
});
assert.deepEqual(secpDouble, run('ECC_PrivateToPublic', { curveType: ids.secp256k1, priv: '2' }));
assert.equal(run('ECC_ValidatePubkey', {
  curveType: ids.secp256k1,
  pub_x: secp[0],
  pub_y: secp[1],
}), true);
assert.equal(run('ECC_ValidatePubkey', {
  curveType: ids.secp256k1,
  pub_x: secp[0],
  pub_y: '1',
}), false);
assert.deepEqual(run('ECC_Point_Sub', {
  curveType: ids.secp256k1,
  a_x: secpDouble[0],
  a_y: secpDouble[1],
  b_x: secp[0],
  b_y: secp[1],
}), secp);
assert.equal(run('ECC_Point_Cmp', {
  curveType: ids.secp256k1,
  a_x: secp[0],
  a_y: secp[1],
  b_x: secpDouble[0],
  b_y: secpDouble[1],
}), false);

for (const curveType of [
  ids.secp256r1,
  ids.secp384r1,
  ids.secp521r1,
  ids.secp256k1,
  ids.brainpool256r1,
  ids.brainpool384r1,
  ids.brainpool512r1,
]) {
  const public2 = run('ECC_PrivateToPublic', { curveType, priv: '2' });
  const public3 = run('ECC_PrivateToPublic', { curveType, priv: '3' });
  assert.ok(public2);
  assert.equal(run('ECC_ValidatePubkey', {
    curveType,
    pub_x: public2[0],
    pub_y: public2[1],
  }), true);
  assert.equal(run('ECDH_Derive', {
    curveType,
    priv: '3',
    pub_x: public2[0],
    pub_y: public2[1],
  }), run('ECDH_Derive', {
    curveType,
    priv: '2',
    pub_x: public3[0],
    pub_y: public3[1],
  }));
}

const recovered = [0, 1, 2, 3].map((id) => run('ECDSA_Recover', {
  curveType: ids.secp256k1,
  digestType: ids.SHA256,
  cleartext: '010203',
  sig_r: secpSignature.signature[0],
  sig_s: secpSignature.signature[1],
  id: String(id),
}));
assert.ok(recovered.some((publicKey) => JSON.stringify(publicKey) === JSON.stringify(secpSignature.pub)));

const schnorrSignature = run('Schnorr_Sign', {
  curveType: ids.secp256k1,
  digestType: ids.NULL,
  cleartext: '00'.repeat(32),
  priv: '3',
  nonce: '0',
  nonceSource: '1',
});
assert.ok(schnorrSignature);
assert.equal(run('Schnorr_Verify', {
  curveType: ids.secp256k1,
  digestType: ids.NULL,
  cleartext: '00'.repeat(32),
  pub_x: schnorrSignature.pub[0],
  pub_y: '0',
  sig_r: schnorrSignature.signature[0],
  sig_s: schnorrSignature.signature[1],
}), true);

const edSignature = run('ECDSA_Sign', {
  curveType: ids.ed25519,
  digestType: ids.NULL,
  cleartext: '010203',
  priv: '1',
});
assert.ok(edSignature);
assert.equal(run('ECDSA_Verify', {
  curveType: ids.ed25519,
  digestType: ids.NULL,
  cleartext: '010203',
  pub_x: edSignature.pub[0],
  pub_y: '0',
  sig_r: edSignature.signature[0],
  sig_s: edSignature.signature[1],
}), true);
assert.ok(run('ECC_PrivateToPublic', { curveType: ids.x25519, priv: '1' }));
for (const curveType of [ids.x25519, ids.x448]) {
  const public2 = run('ECC_PrivateToPublic', { curveType, priv: '2' });
  const public3 = run('ECC_PrivateToPublic', { curveType, priv: '3' });
  assert.equal(run('ECDH_Derive', {
    curveType,
    priv: '3',
    pub_x: public2[0],
    pub_y: '0',
  }), run('ECDH_Derive', {
    curveType,
    priv: '2',
    pub_x: public3[0],
    pub_y: '0',
  }));
}

const blsCurve = ids.BLS12_381;
const dst = Buffer.from('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_').toString('hex');
const blsPublic = run('BLS_PrivateToPublic', { curveType: blsCurve, priv: '1' });
assert.ok(blsPublic);
const blsPublicG2 = run('BLS_PrivateToPublic_G2', { curveType: blsCurve, priv: '1' });
assert.ok(blsPublicG2);
assert.deepEqual(run('BLS_G2_Mul', {
  curveType: blsCurve,
  a_v: blsPublicG2[0][0],
  a_w: blsPublicG2[0][1],
  a_x: blsPublicG2[1][0],
  a_y: blsPublicG2[1][1],
  b: '2',
}), run('BLS_PrivateToPublic_G2', { curveType: blsCurve, priv: '2' }));
const blsSignature = run('BLS_Sign', {
  curveType: blsCurve,
  priv: '1',
  hashOrPoint: true,
  cleartext: '010203',
  aug: '',
  dest: dst,
});
assert.ok(blsSignature);
assert.equal(run('BLS_Verify', {
  curveType: blsCurve,
  cleartext: '010203',
  dest: dst,
  g1_x: blsSignature.pub[0],
  g1_y: blsSignature.pub[1],
  g2_v: blsSignature.signature[0][0],
  g2_w: blsSignature.signature[0][1],
  g2_x: blsSignature.signature[1][0],
  g2_y: blsSignature.signature[1][1],
}), true);

const compressedG1 = run('BLS_Compress_G1', {
  curveType: blsCurve,
  g1_x: blsPublic[0],
  g1_y: blsPublic[1],
});
assert.deepEqual(run('BLS_Decompress_G1', {
  curveType: blsCurve,
  compressed: compressedG1,
}), blsPublic);

const compressedG2 = run('BLS_Compress_G2', {
  curveType: blsCurve,
  g2_v: blsSignature.signature[0][0],
  g2_w: blsSignature.signature[0][1],
  g2_x: blsSignature.signature[1][0],
  g2_y: blsSignature.signature[1][1],
});
assert.deepEqual(run('BLS_Decompress_G2', {
  curveType: blsCurve,
  g1_x: compressedG2[0],
  g1_y: compressedG2[1],
}), blsSignature.signature);

const blsPairing = run('BLS_Pairing', {
  curveType: blsCurve,
  g1_x: blsPublic[0],
  g1_y: blsPublic[1],
  g2_v: blsPublicG2[0][0],
  g2_w: blsPublicG2[0][1],
  g2_x: blsPublicG2[1][0],
  g2_y: blsPublicG2[1][1],
});
assert.deepEqual(blsPairing, [
  '2819105605953691245277803056322684086884703000473961065716485506033588504203831029066448642358042597501014294104502',
  '1323968232986996742571315206151405965104242542339680722164220900812303524334628370163366153839984196298685227734799',
  '2987335049721312504428602988447616328830341722376962214011674875969052835043875658579425548512925634040144704192135',
  '3879723582452552452538684314479081967502111497413076598816163759028842927668327542875108457755966417881797966271311',
  '261508182517997003171385743374653339186059518494239543139839025878870012614975302676296704930880982238308326681253',
  '231488992246460459663813598342448669854473942105054381511346786719005883340876032043606739070883099647773793170614',
  '3993582095516422658773669068931361134188738159766715576187490305611759126554796569868053818105850661142222948198557',
  '1074773511698422344502264006159859710502164045911412750831641680783012525555872467108249271286757399121183508900634',
  '2727588299083545686739024317998512740561167011046940249988557419323068809019137624943703910267790601287073339193943',
  '493643299814437640914745677854369670041080344349607504656543355799077485536288866009245028091988146107059514546594',
  '734401332196641441839439105942623141234148957972407782257355060229193854324927417865401895596108124443575283868655',
  '2348330098288556420918672502923664952620152483128593484301759394583320358354186482723629999370241674973832318248497',
]);

assert.deepEqual(run('BLS_FinalExp', {
  curveType: blsCurve,
  fp12: [...Array(12)].map((_, index) => String(index + 1)),
}), [
  '1527232304282045392137411648865113209620704478563623588282878305743985554533336235038677303957729436944620028877872',
  '2214616994868523192069089570947919212164834045823642581342965259505816419069539460353792643428653103845922642714635',
  '2759640540208456675670566270963335481753342325954934468207669773590902738530895976345093088175613896978004958368713',
  '2277266659431041121028484064841340579381035860136702439997875754699229339203311954159811458859892780896136873665778',
  '1481950901985727221058258873072906553818582763407033395919769336889971618437037636635730610319675019554836791701978',
  '1087880173779995530199892327113197455870912877745949330245781901469317762706019881284800272211812074372160408986691',
  '783359347410401261313147601836040473211817313541238027125340289283576709716512974587134625066210138103447536204839',
  '3151329666589258496048685558259180475036855722294593035116078684527694931906398350802305998516963106573245829738494',
  '1978624858486646515522803941000736030184327504036607098170938999481116327037417543817124297653307923010761170662119',
  '1304574609248365948130848264021709454465214722243093865782379134402109908438205509063337165402190146907139624837227',
  '3135944763860490598362678924022762047563321711999120720457708119341581902790350689767756555257313295006053882909634',
  '3036387301436937038229430622332186733073305683188569504486188247266182617316744606566920282613794977922104562863870',
]);

const mappedG1 = run('BLS_MapToG1', { curveType: blsCurve, u: '1', v: '2' });
assert.deepEqual(mappedG1, [
  '1521072370624522634744479263597850674452549234393253377863234809894136260131888404789643999673769459955483490529833',
  '970178397105094616202147572046095165301570472630387716648463796099855465331935221961434465049500847992318937395831',
]);
assert.equal(run('BLS_IsG1OnCurve', {
  curveType: blsCurve,
  g1_x: mappedG1[0],
  g1_y: mappedG1[1],
}), true);
const mappedG2 = run('BLS_MapToG2', {
  curveType: blsCurve,
  u_x: '1',
  u_y: '2',
  v_x: '3',
  v_y: '4',
});
assert.deepEqual(mappedG2, [
  [
    '3884153552182001276900531256990835525605074966814028779077107139782623376440975491858024780172095776013189416375781',
    '2347628611752369337865578466008658346695727891510897594484346800563078103609535040943511752879250013765394883176392',
  ],
  [
    '879817751882351309315499508776137564774466582479414131417821006937705872801271132542695590718556236282431741888230',
    '2391547387754332078708783140928569472547922033264883468670452997639472286538182003036193224371883823008512261142705',
  ],
]);
assert.equal(run('BLS_IsG2OnCurve', {
  curveType: blsCurve,
  g2_v: mappedG2[0][0],
  g2_w: mappedG2[0][1],
  g2_x: mappedG2[1][0],
  g2_y: mappedG2[1][1],
}), true);

assert.deepEqual(run('BLS_G1_MultiExp', {
  curveType: blsCurve,
  points_scalars: [
    { x: blsPublic[0], y: blsPublic[1], scalar: '2' },
    { x: blsPublic[0], y: blsPublic[1], scalar: '3' },
  ],
}), run('BLS_G1_Mul', {
  curveType: blsCurve,
  a_x: blsPublic[0],
  a_y: blsPublic[1],
  b: '5',
}));

const bnCurve = ids.alt_bn128;
const bnG1 = ['1', '2'];
const bnG2 = run('BLS_PrivateToPublic_G2', { curveType: bnCurve, priv: '1' });
assert.ok(bnG2);
const bnPairing = run('BLS_Pairing', {
  curveType: bnCurve,
  g1_x: bnG1[0],
  g1_y: bnG1[1],
  g2_v: bnG2[0][0],
  g2_w: bnG2[0][1],
  g2_x: bnG2[1][0],
  g2_y: bnG2[1][1],
});
assert.equal(bnPairing.length, 12);
assert.equal(run('BLS_FinalExp', {
  curveType: bnCurve,
  fp12: [...Array(12)].map((_, index) => String(index + 1)),
}).length, 12);
assert.deepEqual(run('BLS_G1_MultiExp', {
  curveType: bnCurve,
  points_scalars: [
    { x: bnG1[0], y: bnG1[1], scalar: '2' },
    { x: bnG1[0], y: bnG1[1], scalar: '3' },
  ],
}), run('BLS_G1_Mul', {
  curveType: bnCurve,
  a_x: bnG1[0],
  a_y: bnG1[1],
  b: '5',
}));

assert.equal(run('BignumCalc_Mod_BLS12_381_P', {
  calcOp: ids.Add,
  bn0: '5',
  bn1: '7',
}), '12');

console.log('noble-curves adapter tests passed');
