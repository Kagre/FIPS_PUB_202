/**
* [FIPS_PUB_202]{@link https://github.com/Kagre/FIPS_PUB_202}
*
* @version 0.1
* @author Kaiser, Gregory
* @copyright Kaiser, Gregory 2016
* @license GPL3
*/

/*
Copyright 2016 Gregory Kaiser

This file is part of my FIPS_PUB_202 libarary.

My FIPS_PUB_202 library is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

My FIPS_PUB_202 library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with my FIPS_PUB_202 library.  If not, see <http://www.gnu.org/licenses/>.

wikkipedia.SHA3-224("")  6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
SHA3_224([]);            6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7

  Notation:
     b [25,50,100,200,400,800,1600] width of permutation
     w [1,2,4,8,16,32,64]           lane length
     l=log2(w) [0,1,2,3,4,5,6]
     nr = 12+2l where 2^l=w [12,14,16,18,20,22,24] number of rounds
     RC                             round constant


b 25 50 100 200 400 800 1600 Bits
w 1  2  4   8   16  32  64   b/(5x5)
l 0  1  2   3   4   5   6    log2(b/25)

*/
var dbg=false;

String.prototype.toUTF8ByteArray=function(){
   return this.split("").map(function(cv){return cv.charCodeAt(0);});
};
Array.prototype.fromUTF8ByteArray=function(){
   return this.map(function(cv){return String.fromCharCode(cv);}).join("");
};

Array.prototype.xor=function(B){
   //assumed: A and B are same length with no undefined elements.
   return this.map(function(cv,ndx){return cv^B[ndx];});
};

Number.prototype.toBits=function(w){
   var ret=this.toString(2).split('');
   if(w===undefined)return ret;
   return zString(w-ret.length).split('').concat(ret);
};

//assumed: M is a byte vector
function SHA3_224(M){return b2h(Keccak(448,M,[0,1],224));}
function SHA3_256(M){return b2h(Keccak(512,M,[0,1],256));}
function SHA3_384(M){return b2h(Keccak(768,M,[0,1],384));}
function SHA3_512(M){return b2h(Keccak(1024,M,[0,1],512));}

function SHAKE128(M,d){return b2h(Keccak(256,M,[1,1,1,1],d));}
function SHAKE256(M,d){return b2h(Keccak(512,M,[1,1,1,1],d));}

function RawSHAKE128(J,d){return b2h(Keccak(256,J,[1,1],d));}
function RawSHAKE256(J,d){return b2h(Keccak(512,J,[1,1],d));}

String.prototype.SHA3_224=function(){return b2h(Keccak(448,this.toUTF8ByteArray(),[0,1],224));}
String.prototype.SHA3_256=function(){return b2h(Keccak(512,this.toUTF8ByteArray(),[0,1],256));}
String.prototype.SHA3_384=function(){return b2h(Keccak(768,this.toUTF8ByteArray(),[0,1],384));}
String.prototype.SHA3_512=function(){return b2h(Keccak(1024,this.toUTF8ByteArray(),[0,1],512));}

String.prototype.SHAKE128=function(d){return b2h(Keccak(256,this.toUTF8ByteArray(),[1,1,1,1],d));}
String.prototype.SHAKE256=function(d){return b2h(Keccak(512,this.toUTF8ByteArray(),[1,1,1,1],d));}

String.prototype.RawSHAKE128=function(d){return b2h(Keccak(256,this.toUTF8ByteArray(),[1,1],d));}
String.prototype.RawSHAKE256=function(d){return b2h(Keccak(512,this.toUTF8ByteArray(),[1,1],d));}

function bitStringToState(S){
   var A=[],w=S.length/25,i,j,k;
   for(i=0;i<5;i++){
      A[i]=[];
      for(j=0;j<5;j++){
         A[i][j]=[];
         for(k=0;k<w;k++)A[i][j].push(S[w*(5*j+i)+k]);
      }
   }
   return A;
}
function StateToBitString(A){
   var S=[],w=A[0][0].length,i,j,k;
   for(j=0;j<5;j++){
      for(i=0;i<5;i++){
         for(k=0;k<w;k++)S.push(A[i][j][k]);
      }
   }
   return S;
}

//wrapper function to 1600 KECCAK
//  c   -- capacity N^r.0^c
//  N   -- Message
//  dom -- domain selection used in SHA3
//  d   -- ouput bit length
function Keccak(c,N,dom,d){
   var b=1600;
   return Sponge(
      function(S){return StateToBitString(KECCAK_f(b,bitStringToState(S)));},b,
      pad101,
      b-c,
      N,dom,
      d
   );
}

//SPONGE[f, pad, r](N, d)
//   f    -- underlying function maps b bits to b bits
//   b    -- b associated bit length of f
//   pad  -- padding rule, pad message to mod r bit length
//   r    -- bit rate, partition size of the message
//   N    -- message, byte vector
//   dom  -- message domain postfix, bit vector
//   d    -- output bit length
function Sponge(f,b,pad,r,N,dom,d){
   var buff=[]; // bit vector buffer
   
   // I know pullBits is convoluted, but its concept is a lot simpler than its implementation
   // the point behind pullBits is that you have a single source to pull the message bits from
   //    pullBits = N || dom || pad101
   var pullBits=(function(){
      var Nlen=N.length, Nndx=0; // current position in N byte vector
      return function(){
         if(Nndx==Nlen){
            pullBits=(function(){
               var Pdng=pad(r,Nlen*8+dom.length); // bit vector
               return function(){
                  return Pdng.splice(0,r-buff.length); // the third function pulls from the padding
               };
            })();
            return dom; // the second function pulls the domain
         }
         return N[Nndx++].toBits(8).reverse(); // the first function pulls from N till it's empty
      };
   })();

   //absorbing
   var c=b-r,tmp;
   var S=zString(b).split(''); // bit vector initalized to 00*0
   while(true){
      do{
         tmp=pullBits();
         buff=buff.concat(tmp);
      }while(buff.length<r && tmp.length!=0);
      if(buff.length<r)break;
      tmp=buff.splice(0,r).concat(zString(c).split(''));
      S=f(S.xor(tmp));
   }

   //squeezing
   var Z=[];
   while(true){
      Z=Z.concat(S.slice(0,r));
      if(Z.length>=d)break; // break early to not over-run computationally heavy f(S)
      S=f(S);
   }
   return Z.slice(0,d);
}

//wrapper for a specific family of KECCAK functions
function KECCAK_f(b,A){
   var nr={25:12,50:14,100:16,200:18,400:20,800:22,1600:24}[b];
   if(nr===undefined)return undefined;
   return KECCAK_p(b,nr,A);
}
// b   -- bit length must be in [25, 50, 100, 200, 400, 800, 1600]
// nr  -- number of rounds
// A   -- input state
function KECCAK_p(b,nr,A){
   var w={25:1,50:2,100:4,200:8,400:16,800:32,1600:64}[b];
   if(w===undefined)return undefined;
   var retA=A,ir;
   for(ir=0;ir<nr;ir++)
      retA=Round(w,retA,ir);
   return retA;
}

function Round(w,A,ir){
   var LaneNdx=(function(){
      var MAX=Math.floor(0x7FffFFff/w)*w;
      return function(z){
         if(z<0)return (z+MAX)%w;
         return z%w;
      };
   })();
   var ndx=function(n){
      //0X7FFFFFFD % 5 =0
      if(n<0) return (n+0x7FffFFfd)%5;
      return n%5;
   }

   var i,j,k;
   if(LogIt!==undefined && dbg){
      LogIt('Round: '+ir+' A.length:'+A.length+' A[0].length:'+A[0].length+' A[0][0].length:'+A[0][0].length);
      LogIt('A:\n<span style="font-family:Courier New">'+b2h(StateToBitString(A))+'</span>');
   }
   //Theta
   var C=[],D=[],ThetaA=[];
   for(i=0;i<5;i++){
      C[i]=[];
      for(k=0;k<w;k++){
         C[i].push(A[i][0][k]^A[i][1][k]^A[i][2][k]^A[i][3][k]^A[i][4][k]);
      }
   }
   for(i=0;i<5;i++){
      D[i]=[];
      for(k=0;k<w;k++){
         D[i].push(C[ndx(i-1)][k]^C[ndx(i+1)][LaneNdx(k-1)]);
      }
   }
   for(i=0;i<5;i++){
      ThetaA[i]=[];
      for(j=0;j<5;j++){
         ThetaA[i][j]=[];
         for(k=0;k<w;k++){
            ThetaA[i][j].push(A[i][j][k]^D[i][k]);
         }
      }
   }
   if(LogIt!==undefined && dbg)LogIt('ThetaA:\n<span style="font-family:Courier New">'+b2h(StateToBitString(ThetaA))+'</span>');

   //rho
   var RhoA=initState(w);
   for(k=0;k<w;k++)RhoA[0][0][k]=ThetaA[0][0][k];
   var x=1,y=0,t,tmpX;
   for(t=0;t<24;t++){
      for(k=0;k<w;k++)RhoA[x][y][k]=ThetaA[x][y][LaneNdx(k-(t+1)*(t+2)/2)];
      tmpX=x;x=y;y=ndx(2*tmpX+3*y);
   }
   if(LogIt!==undefined && dbg)LogIt('RhoA:\n<span style="font-family:Courier New">'+b2h(StateToBitString(RhoA))+'</span>');

   //pi
   var PiA=[];
   for(i=0;i<5;i++){
      PiA[i]=[];
      for(j=0;j<5;j++){
         PiA[i][j]=[];
         for(k=0;k<w;k++)PiA[i][j].push(RhoA[ndx(i+3*j)][i][k]);
      }
   }
   if(LogIt!==undefined && dbg)LogIt('PiA:\n<span style="font-family:Courier New">'+b2h(StateToBitString(PiA))+'</span>');

   //chi
   var ChiA=[];
   for(i=0;i<5;i++){
      ChiA[i]=[];
      for(j=0;j<5;j++){
         ChiA[i][j]=[];
         for(k=0;k<w;k++)ChiA[i][j].push(PiA[i][j][k]^((PiA[ndx(i+1)][j][k]^1)&PiA[ndx(i+2)][j][k]));
      }
   }
   if(LogIt!==undefined && dbg)LogIt('ChiA:\n<span style="font-family:Courier New">'+b2h(StateToBitString(ChiA))+'</span>');

   //iota
   var rc=function(t){
      if(t%255==0)return 1;
      var R=[1,0,0,0,0,0,0,0],i,mx;
      for(i=1,mx=t%255;i<=mx;i++){
         R=[0].concat(R);
         R[0]^=R[8];
         R[4]^=R[8];
         R[5]^=R[8];
         R[6]^=R[8];
         R=R.slice(0,8);
      }
      return R[0];
   };
   var IotaA=[],RC=[],l;
   for(i=0;i<5;i++){
      IotaA[i]=[];
      for(j=0;j<5;j++){
         IotaA[i][j]=[];
         for(k=0;k<w;k++)IotaA[i][j].push(ChiA[i][j][k]);
      }
   }
   RC=zString(w).split('');
   for(j=0,l={1:0,2:1,4:2,8:3,16:4,32:5,64:6}[w];j<=l;j++)
      RC[(1<<j)-1]=rc(j+7*ir);
   for(k=0;k<w;k++)IotaA[0][0][k]=IotaA[0][0][k]^RC[k];
   if(LogIt!==undefined && dbg)LogIt('IotaA:\n<span style="font-family:Courier New">'+b2h(StateToBitString(IotaA))+'</span>');

   return IotaA;
}

// String.repeat() not defined in IE
if(String.prototype.repeat===undefined){
   String.prototype.repeat=function(len){
      if (this=='') return '';
      if(len===undefined)return '';
      if(len<0)return '';
      var i=0,z=this;
      var ret='';
      for(i=len;i>0;i>>=1){
         if(i&1)ret+=z;
         z+=z;
      }
      return ret;
   };
}

function zString(len){
   if(len===undefined)return '';
   if(len<0)return '';
   return '0'.repeat(len);
}

var pad101=function(x,m){
   var MAX=Math.floor(0x7FffFFff/x)*x;
   var j=(MAX-m-2)%x;
   if(j==0) return [1,1];
   return [1].concat(zString(j).split(''),[1]);
}

function initState(w){
   var A=[],i,j,k;
   for(i=0;i<5;i++){
      A[i]=[];
      for(j=0;j<5;j++){
         A[i][j]=[];
         for(k=0;k<w;k++){
            A[i][j].push(0);
         }
      }
   }
   return A;
}

function BitsToHex(S){
   var i,len,ret='';
   for(i=0,len=S.length;i<len;i+=4){
      ret+=parseInt(S.slice(i,i+4).join(''),2).toString(16);
   }
   return ret;
}

//Algo 10
function h2b(H,n){
   var len=H.length;
   var i,m,h,T=[];
   for(i=0,m=len/2;i<m;i++){
      h=16*parseInt(H.charAt(i*2),16)+parseInt(H.charAt(i*2+1),16);
      T=T.concat(h.toBits(8).reverse());
   }
   if(n===undefined)return T;
   return T.slice(0,n);
}

//Algo 11
function b2h(S){
   var T=S.concat(zString((0x7FFFFFF8-S.length)%8).split(''));
   var m=Math.ceil(S.length/8);
   var i,h,H='';
   for(i=0;i<m;i++){
      h=parseInt(T.splice(0,8).reverse().join(''),2);
      H+=((i%16==0&&i!=0)?'\n':'')+((h<16)?'0':'')+h.toString(16)+' ';
   }
   return H;
}