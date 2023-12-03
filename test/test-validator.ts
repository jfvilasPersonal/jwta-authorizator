import { RequestContext } from '../src/model/RequestContext';
import { Validator } from '../src/model/Validator';
import { AzureB2c } from '../src/validators/AzureB2c';
// import { Cognito } from '../src/validators/Cognito';
import { IValidator } from '../src/validators/IValidator';


var val:Validator = {
  name:'eulennopro',
  type:'azure-b2c',
  tenant:'eulennopro',
  userflow:'B2C_1_password',
  verify:true,
  ivalidator:undefined
}

var a=new AzureB2c(val);
// var a=new AzureB2c('eulennopro','eulennopro','B2C_1_password', '');
// var c=new Cognito('cognoito', 'us-east-1','us-east-1_upKkn5Olp', '');
// var d=new AzureAd('ad', '695977ed-bd45-4142-b7fb-964533a79127', '');


var rc:RequestContext = {    
    uri: '',
    ruleset: []
};

var tokens:Array<string>=[];
var b2ce1='eyJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsiLCJ0eXAiOiJKV1QifQ.eyJpZHAiOiJMb2NhbEFjY291bnQiLCJvaWQiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJzdWIiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJleHRlbnNpb25fZXVsZW5fcGVybWlzc2lvbnMiOiJBRE1JTiIsInRmcCI6IkIyQ18xX3Bhc3N3b3JkIiwic2NwIjoicmVhZCIsImF6cCI6ImI4YWJhMTQ5LTU4MmYtNDY4Mi1hMmQwLTZlNGVmY2E5MTI2ZCIsInZlciI6IjEuMCIsImlhdCI6MTcwMDUwNTQ0MiwiYXVkIjoiYjhhYmExNDktNTgyZi00NjgyLWEyZDAtNmU0ZWZjYTkxMjZkIiwiZXhwIjoxNzAwNTA5MDQyLCJpc3MiOiJodHRwczovL2V1bGVubm9wcm8uYjJjbG9naW4uY29tLzJjNmQ0ZGVhLTk0N2EtNGY5Ni1hMGVjLTdhOWU0Nzg2MzNkOC92Mi4wLyIsIm5iZiI6MTcwMDUwNTQ0Mn0.mozLcRH0N7TSecTdlaH-YdCBuGQkBUtrxuhS7f96Zm_wotezV0m7FTVYSv3JgVS8FOcA5Du3Fqc3xTwT8_VcgO-lndyvFUF-QlpmemdY96KGqkGPNrZEFXxTUw1zFdk5KOAzOvQW-5UvAJxz27gOs5hWGQwunsCXCj5yMyufd6tjnP-3i6cK8csMD0xP5Lmn4J7JdjhVnhNYhQ5-0UoGkNNjCMmLcjP6tzs8cuv024Hae1CA59gSPVHW93f2iheHdnBFniniqiaxcrM2LXVd8asZt-YlAlg4UPefsxhor1nVNMZvWbjZ4jkaKcqt7fNH-0PZm-s1YkfAZ3M5pTgsaA';
var b2ce2='eyJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsiLCJ0eXAiOiJKV1QifQ.eyJpZHAiOiJMb2NhbEFjY291bnQiLCJvaWQiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJzdWIiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJleHRlbnNpb25fZXVsZW5fcGVybWlzc2lvbnMiOiJBRE1JTiIsInRmcCI6IkIyQ18xX3Bhc3N3b3JkIiwic2NwIjoicmVhZCIsImF6cCI6ImI4YWJhMTQ5LTU4MmYtNDY4Mi1hMmQwLTZlNGVmY2E5MTI2ZCIsInZlciI6IjEuMCIsImlhdCI6MTcwMDkwMzYxMywiYXVkIjoiYjhhYmExNDktNTgyZi00NjgyLWEyZDAtNmU0ZWZjYTkxMjZkIiwiZXhwIjoxNzAwOTA3MjEzLCJpc3MiOiJodHRwczovL2V1bGVubm9wcm8uYjJjbG9naW4uY29tLzJjNmQ0ZGVhLTk0N2EtNGY5Ni1hMGVjLTdhOWU0Nzg2MzNkOC92Mi4wLyIsIm5iZiI6MTcwMDkwMzYxM30.M3G1FEEQphQqJ-iVcJSf8TrqT-hktk4_hPYLAqF9_dbjTGcqmAuATqsOPUuh2VSi3aWCiiVBOUY6YFV3VbP2ol7-MWPSonBpLvi7gEdirW01Me4QLlVYXmql69XX4Lkcq4G84m077cqVx82AKjaTq9uT59xtW6zvA_IbW2MWDGKeTE5mvs8pYt8gX-ly1aNFvCs78bI_oHqvP_CgPqn-6NunZq_sAZGfTI2papdmYX5OmG4rXPMmpfTTTyBdVeIdCyDs9_xzuKQvUDiQu8zN_6tK9RcuaL7i9igAwH_18F_DQ6WEH8jl-qucgoc8OqdS444C-2cmK-J3PbWoYaPj2g';
var b2ct='eyJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsiLCJ0eXAiOiJKV1QifQ.eyJpZHAiOiJMb2NhbEFjY291bnQiLCJvaWQiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJzdWIiOiIzZTQ5YzE3OC03MDVmLTRkMTEtYjkxZC04ZjM5ZmI0MTdkMDEiLCJleHRlbnNpb25fZXVsZW5fcGVybWlzc2lvbnMiOiJBRE1JTiIsInRmcCI6IkIyQ18xX3Bhc3N3b3JkIiwic2NwIjoicmVhZCIsImF6cCI6ImI4YWJhMTQ5LTU4MmYtNDY4Mi1hMmQwLTZlNGVmY2E5MTI2ZCIsInZlciI6IjEuMCIsImlhdCI6MTcwMDkxMzU5OCwiYXVkIjoiYjhhYmExNDktNTgyZi00NjgyLWEyZDAtNmU0ZWZjYTkxMjZkIiwiZXhwIjoxNzAwOTE3MTk4LCJpc3MiOiJodHRwczovL2V1bGVubm9wcm8uYjJjbG9naW4uY29tLzJjNmQ0ZGVhLTk0N2EtNGY5Ni1hMGVjLTdhOWU0Nzg2MzNkOC92Mi4wLyIsIm5iZiI6MTcwMDkxMzU5OH0.i0uuMplxwH3YfcwwxKwEPCpUioTZXouON8wLmx4TmSTjOo8erW1zfIbjgh5qu9ci7SGf7ACuc7B1-OpCzxXXY2KKztGvWoeC3doBQHmaLj_A1PdPMkBiDZXRmL9dQ5JSre8-TXc8tetacMcLmL6nLPlrPvGXhJ3E0E950hl-n1Mm6rLefrPM_HeY6DiuJMCqXLGpa1BXcMBmrihQY-6Nc4tWRtRev_eWev0zOKyDdHy1mBPPCH1gWA7-x71y1AJU377sL-zeaeHjzoxl_jzvutCGZra1Fm3ibTBqVLgpntxMF1aBkxb6VEQlZ_YVUThkG-cUbpTkHgYxzhKPeASkzg';
var cgne1='eyJraWQiOiJzUitUSGZpeUdMZnJEV05rSXBxRlBTcE04a1JFSjRKYk54bVkzeEpwaUNFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2ZTBlNzRmMi0wM2M0LTRiZWMtODQ1Ny1lM2UzNjgzM2I4ZjgiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV91cEtrbjVPbHAiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIzMmdscWg3YnE4cnM3cW12YTJjM3RlMHBmMyIsImV2ZW50X2lkIjoiYTIxM2M0MzMtNjZhOC00ZTE2LTljMjEtZDQ4MGQwYjg3NzMwIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE3MDA5MDM1NjUsImV4cCI6MTcwMDkwNzE2NSwiaWF0IjoxNzAwOTAzNTY1LCJqdGkiOiIyMTZiNDE0NS0zMWFmLTQwMjUtOTRhMi1mZWM3OTM1NjM2ZGIiLCJ1c2VybmFtZSI6IjZlMGU3NGYyLTAzYzQtNGJlYy04NDU3LWUzZTM2ODMzYjhmOCJ9.r3g_NyuJxO58nKEEcuVMjXnFmk7bFk46i1AHi74NJB71f2o9mY9m0mRDgIi0-yikCE4aut1Ld5afV2eK3WoHeHBo1pj0oksZSz3RAN67AoLTVN1qcGdNLiVgsEdAquMx2JVgSSSM1vIIs1g3dqaqKuptlUb4zgQkywl5lQxvloMqIPQTwFymkfIpxxIWL8CsunhXpn4W44LbueZHwaOR_Tf7nlheXWSr_vFfaoJXf_FY8cd6vGS7fAZFWd6yxvd3HstjDk1IbQXbalu1XIDTXjPHeHUc8MsBl-9UqGOjNaKMn-AwHH2NqqdPs8C6ReDuyu1Vuhoa_Oq6M3-jrTGlGw';
var cgne2='eyJraWQiOiJzUitUSGZpeUdMZnJEV05rSXBxRlBTcE04a1JFSjRKYk54bVkzeEpwaUNFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2ZTBlNzRmMi0wM2M0LTRiZWMtODQ1Ny1lM2UzNjgzM2I4ZjgiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV91cEtrbjVPbHAiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIzMmdscWg3YnE4cnM3cW12YTJjM3RlMHBmMyIsImV2ZW50X2lkIjoiMTlhMWNkYzAtOTE1ZS00NWU0LTljM2QtMDE1ZTRjY2E2NDRjIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE3MDA5MDcyNDEsImV4cCI6MTcwMDkxMDg0MSwiaWF0IjoxNzAwOTA3MjQxLCJqdGkiOiIxMTdjNmM1MC1kYjc4LTRiNGQtYjI1Yi04YjE2NjEyMmFkYzgiLCJ1c2VybmFtZSI6IjZlMGU3NGYyLTAzYzQtNGJlYy04NDU3LWUzZTM2ODMzYjhmOCJ9.mM7S3IdxIqhvzdCCAnrQuNpHFI49YENcRjGcTpAP74HDQrgqTpWIODdxoGNGvKuJ3AtLFWIE1y3H8-59cnnpAJXPyIg0AuMGMJ_QQdp6swpifSF46yU8BTE_QkMyHyMVxUbpxcv0tbqogR9C7ncRpQOkZwHusRpGQSOgvzsDe18-_cldtF64vB-2AAYQJbRnkx6PfOLI6XzwA_ytP2Bf7vp8GbNhEqfOkc0ky0N-AnOOC4mG8fVbpEnxQ82W2N6QLF4sBWhQpCRry0L-lQTOyVzBZe3g6XKyn9WFOISj1HakGndKzfM3zbEa0szKZzmPpsbqJhDEZl2j-q7q9RiFTA';
var cgnt='eyJraWQiOiJzUitUSGZpeUdMZnJEV05rSXBxRlBTcE04a1JFSjRKYk54bVkzeEpwaUNFPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2ZTBlNzRmMi0wM2M0LTRiZWMtODQ1Ny1lM2UzNjgzM2I4ZjgiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV91cEtrbjVPbHAiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIzMmdscWg3YnE4cnM3cW12YTJjM3RlMHBmMyIsImV2ZW50X2lkIjoiNjMzOWNmNmUtZWUyNC00YmFmLWFiZjUtZDVjNjhlMDY5YmZhIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE3MDA5MTIxNDEsImV4cCI6MTcwMDkxNTc0MSwiaWF0IjoxNzAwOTEyMTQxLCJqdGkiOiI2ZTQzMTA4MC1hNjA2LTQ0N2MtODY4Ny05ZTM5YTgxN2M1ZTMiLCJ1c2VybmFtZSI6IjZlMGU3NGYyLTAzYzQtNGJlYy04NDU3LWUzZTM2ODMzYjhmOCJ9.Q7g1guQRQfTBRRqkfDzVGp8v54XHLJbxEWrLq1ZAMtVBV6i3Kq2nohB5fR37IlVO_ynQD1klzkNcXUYE3kmpDpgjHeMYPwBsX3E7RAQNmoqcEnaYA61VA-kdsQ37T9C4QPjsAqQrPSP3vLmEC9BS8HXNQznWiNZ-Pt776wJ96YSERDVidZU-D4D-pilHt5dGaJV8YNUKQ-x_XNsBmnI4E29gFxucUZkSVPU11H4aEENUVyGNwv2vUAVuOxwtsvqxImTUletxs7nEfRJTrmcTzJl4Ysu8EL4pVpf3M7wP1bTU3sfnjLVKcUnY5ueLsZT0hS1XFD3dEtnD3AY2aFLq0Q';
var aadt='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlQxU3QtZExUdnlXUmd4Ql82NzZ1OGtyWFMtSSIsImtpZCI6IlQxU3QtZExUdnlXUmd4Ql82NzZ1OGtyWFMtSSJ9.eyJhdWQiOiJhcGk6Ly8xODBhOTU2Yi0zYTQ1LTRjMjAtYmZkMy04MjRkYTljM2FiZGUiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82OTU5NzdlZC1iZDQ1LTQxNDItYjdmYi05NjQ1MzNhNzkxMjcvIiwiaWF0IjoxNzAwOTM0ODA2LCJuYmYiOjE3MDA5MzQ4MDYsImV4cCI6MTcwMDkzODk3OCwiYWNyIjoiMSIsImFpbyI6IkFUUUF5LzhWQUFBQWJwbkZvRW5Gelc1eTJQRGJYQ2x0Z3VrbWs4eFlFem85N0RNZlVFNktRNWRSMDZzck82SGs5VFBvajBvZzZhajIiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMTgwYTk1NmItM2E0NS00YzIwLWJmZDMtODI0ZGE5YzNhYmRlIiwiYXBwaWRhY3IiOiIxIiwiaXBhZGRyIjoiNzkuMTE2LjE5Mi4xMTAiLCJuYW1lIjoiamZ2aWxhcyIsIm9pZCI6ImU5OTJhN2QyLTkyMTAtNGQ3MC04OGIxLWQ4NjQ2ZDM0ODA0YiIsInJoIjoiMC5BWGtBN1hkWmFVVzlRa0czLTVaRk02ZVJKMnVWQ2hoRk9pQk12OU9DVGFuRHE5NlVBSUkuIiwic2NwIjoicmVhZCIsInN1YiI6IkNPODJLbHNuRl9oVXlSMEx6cE4wUVhWNHhTbEUtd2xqZHNOTHBndUpqMzgiLCJ0aWQiOiI2OTU5NzdlZC1iZDQ1LTQxNDItYjdmYi05NjQ1MzNhNzkxMjciLCJ1bmlxdWVfbmFtZSI6ImpmdmlsYXNAZGV2b3BzcGxleHVzLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6ImpmdmlsYXNAZGV2b3BzcGxleHVzLm9ubWljcm9zb2Z0LmNvbSIsInV0aSI6IklseWo2LWxEamtXbFQ4OERLNE55QVEiLCJ2ZXIiOiIxLjAifQ.grOTTvMrhBYiTydJAQUiiNYlQZm_Bcc6p2WRi5SHgwo9wnaDoifEAQl_P1DJbOyGmlWvwwfhhOucUUUVUFidrdYLbeFcYUCUW1jbDEtWRut47hlmnizivZQsohe_bL2Xy06HE12WcC6qKoyT6nUbbni4sohLNg2pjG2Gx2_FSIhITOCpfdQfMhilEauL6NC8gaYOIQp-xcFb9sL7nlJe-3pD538bNp3psgIMYwGu-bkROB1_IRYgyi_6JRjKdK2cA9yh02M_unt90KtmofdHPMKyGatqAI-sGAL65ttPi_fPcm9ZW4bI-sOz_bFn2u5UItsUfGK18BzCp93RjpftpQ';

tokens[0]=b2ce1;
tokens[1]=b2ce2;
tokens[2]=b2ct;
tokens[3]=cgne1;
tokens[4]=cgne2;
tokens[5]=cgnt;
tokens[6]=aadt;

async function try1(validator:IValidator, t:string) {

    console.log ("***************************************************************************************************************************");
    rc.token=t;
    delete rc.validationStatus;
    delete rc.validationError;
    var start=new Date().getTime();
    await validator.decodeAndValidateToken(rc);
    console.log(rc.validationStatus, (new Date().getTime()-start));
    return rc.validationStatus;

}

function delay(time:number) {
    return new Promise(resolve => setTimeout(resolve, time));
} 

async function main() {
    await delay(5000);
    console.log(a.cachedSigningKeys);
    // console.log(c.cachedSigningKeys);
    // console.log(d.cachedSigningKeys);


    var start=new Date().getTime();

    var validators:Array<IValidator>=[];
    validators.push(a);
    // validators.push(c);
    // validators.push(d);
    var tot=0;
    for (var val of validators) {
        tot+=(await try1(val,b2ce1))?1:0;
        tot+=(await try1(val,b2ce2))?1:0;
        tot+=(await try1(val,cgnt))?1:0;
        tot+=(await try1(val,b2ct))?1:0;
        tot+=(await try1(val,cgne1))?1:0;
        tot+=(await try1(val,cgne2))?1:0;
        tot+=(await try1(val,cgnt))?1:0;
        tot+=(await try1(val,aadt))?1:0;
    }
    
    console.log("TOTAL OK: ", tot);
    console.log("TOTAL ms:", new Date().getTime()-start);
}

main();

