import express from 'express';
import bodyParser from 'body-parser';
import { Buffer } from "buffer";
import { OverviewApi } from './api/overviewApi';
import { RequestContext } from './model/RequestContext';
import { Rule } from './model/Rule';
import { Validator } from './model/Validator';
import { Environment } from './model/Environment';
import { Status } from './model/Status';

import { ITokenDecoder } from './validators/ITokenDecoder';

import { AzureB2c } from './validators/AzureB2c';
import { Google } from './validators/Google';
import { AzureAd } from './validators/AzureAd';
import { Cognito } from './validators/Cognito';
import { KeyCloak } from './validators/KeyCloak';
import { BasicAuth } from './validators/BasicAuth';
import { Custom } from './validators/Custom';
import { NullValidator } from './validators/NullValidator';
import { Counter, register } from 'prom-client';

import { VERSION } from './version';

// we need access to kubernetes cluster for reading configmaps
import * as k8s from '@kubernetes/client-node';
import { CoreV1Api } from '@kubernetes/client-node';
import { Ruleset } from './model/Ruleset';


const app = express();
app.use(bodyParser.json());
const port = 3000;
var logLevel=9;

// access to kubernetes cluster
const kc = new k8s.KubeConfig();
kc.loadFromDefault();
const coreApi = kc.makeApiClient(CoreV1Api);


//prometheus
var promRequestsMetric:Counter;
var promValidMetric:Counter;


var env:Environment = {
  obkaName: '',
  obkaNamespace:'',
  obkaApi:false,
  obkaPrometheus:false,
  obkaValidators:new Map(),
  obkaRulesets:new Map()
};

var status:Status = {
  totalRequests:0,
  totalMicros:0
}

enum NextAction {
  FALSE=0,
  TRUE=1,
  CONTINUE=2
}

async function validateRule(rule:Rule, context:RequestContext):Promise<boolean> {
  //var validatorsArray=env.obkaValidators.get(env.obkaName) as Map<string, Validator>;
  var validatorsList:Map<string, Validator>=new Map();

  // si hay una lista especifica de validadores la preparamos, si no usamos todos los validadores definidos en el YAML
  if (rule.validators) {
    for (const v of rule.validators) {
      //if (env.obkaValidators.get(env.obkaName)?.get(v) as Validator!==undefined) {
    if (env.obkaValidators.get(v) as Validator!==undefined) {
        //validatorsList.set (v, env.obkaValidators.get(env.obkaName)?.get(v) as Validator);
        validatorsList.set (v, env.obkaValidators.get(v) as Validator);
      }
      else {
        log(3,"Unknown validator: "+v);
      }
    }
  }
  else {
    //validatorsList=validatorsArray;
    validatorsList=env.obkaValidators;
  }

  log(4,"Validators list to use for rule");
  log(4,validatorsList);
  for (const validator of validatorsList.values()) {
    log(5,">>> TESTING VALIDATOR "+validator.name);
    if (context.validationStatus) delete context.validationStatus;
    if (context.validationError) delete context.validationError;

    log(5,"Test 'unrestricted' ruletype");
    if (rule?.type==="unrestricted") {
      log(5,"RESULT of 'unrestricted' ruletype: true");
      return true;
    }

    log(5,"Test 'valid' ruletype with validator");
    log(5,validator);
    //var v = env.obkaValidators.get(env.obkaName)?.get(validator.name)?.decoder;
    var v = env.obkaValidators.get(validator.name)?.decoder;
    if (v===undefined) {
      //log(0,`Validator does not exist (undefined): ${env.obkaName}/${validator.name}`);
      log(0,`Validator does not exist (undefined): ${validator.name}`);
      continue;
    }

    log(1, "Validator type: "+ validator.type);

    if (context.token) {
      await v.decodeAndValidateToken(context);

      if (rule?.type==="valid") {
        log(5,"RESULT of 'valid' ruletype: "+context.validationStatus);
        if (context.validationStatus)
          return true;
        else
          continue;
      }


      switch (rule?.type) {
        
        // claim rule, we must evaluate policies
        case "claim":
          log(5,"Test 'claim' ruletype");
          // if we know the tokn is not valid we don't need to continue with other evlautions
          if (!context.validationStatus) {
            log(5,'token invalid');
            break;
          }

          var claimName=rule.name;
          var tokenClaimValue:string=(context.decoded as any)[claimName];
          log(5,"claimName: "+claimName);
          log(5,"claimValue: "+tokenClaimValue);

          switch (rule?.policy) {

            // present, the claim MUST exist (with any value)
            case 'present':
              if (tokenClaimValue!==undefined) return true;
              break;


            // not present, the claim name must not exist
            case 'notpresent':
              if (tokenClaimValue===undefined) return true;
              break;


            // is, the claim value must be ewqual to AT LEAST one of the vlaules in the value list
            case 'is':
              if (rule.options.includes('lowercase')) {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue===value.toLowerCase()) return true;
                });
              }
              else if (rule.options.includes('uppercase')) {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue===value.toUpperCase()) return true;
                });
              }
              else {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue===value) return true;
                });
              }
              break;


            // contains any, claim value must contain AT LEAST one values (at any position)
            case 'containsany':
              if (rule.options.includes('lowercase')) {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue.includes(value.toLowerCase())) return true;
                });
              }
              else if (rule.options.includes('uppercase')) {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue.includes(value.toUpperCase())) return true;
                });
              }
              else {
                rule.values.forEach( (value:string) => {
                  if (tokenClaimValue.includes(value)) return true;
                });
              }
              break;


            // contains all, claim value must contain ALL the values (at any position)
            case 'containsall':
              if (rule.options.includes('lowercase')) {
                var fulfill = rule.values.filter( (value:string) => {
                  if (tokenClaimValue.includes(value.toLowerCase())) return true;
                }).length;
                if (fulfill===rule.values.length) return true;
              }
              else if (rule.options.includes('uppercase')) {
                var fulfill = rule.values.filter( (value:string) => {
                  if (tokenClaimValue.includes(value.toUpperCase())) return true;
                }).length;
                if (fulfill===rule.values.length) return true;
              }
              else {
                var fulfill = rule.values.filter( (value:string) => {
                  if (tokenClaimValue.includes(value)) return true;
                }).length;
                if (fulfill===rule.values.length) return true;
              }
              break;


            // matches any, claim value must match at least one value
            case 'matchesany':
              rule.values.forEach( (value:string) => {
                var regex=new RegExp(value,'g');
                var numMatches = Array.from(tokenClaimValue.matchAll(regex)).length;
                if (numMatches>0) return true;
              });
              break;


            // matches all, claim value must match all values
            case 'matchesall':
              var fulfill = rule.values.filter( (value:string) => {
                var regex=new RegExp(value,'g');
                return Array.from(tokenClaimValue.matchAll(regex)).length>0;
              }).length;
              if (fulfill===rule.values.length) return true;
              break;


            // invalid policy
            default:
              log(0,"invalid policy: "+rule.policy);
              break;
        
          }
          break;


        // or rule, at least, one sub-rule must be true
        case 'or':
          log(5,"Test 'or' ruletype");
          for (const r of rule.subset) {
            if (await validateRule(r,context)) return true;
          }
          break;


        // and policy, all sub-rules must be true
        case 'and':
          log(5,"Test 'and' ruletype");
          var valid=0;
          for (const r of rule.subset) {
            if (await validateRule(r,context))
              valid++;
            else
              break;
          }
          if (valid==rule.subset.length) return true;
          break;


        default:
          // invalid rule type
          log(0,'Invalid rule tpye: '+rule.type);
          break;
      }
    }
    else {
      if (validator.type==="basicAuth") {
        log(1, "Get response header from basicAuth Validator");
        await v.decodeAndValidateToken(context);
        console.log(context.responseHeaders);
        return false;
      }
      else {
        log(5,"No token present, do not invoke validator");
      }
    }

  }
  return false;
}


async function decideNext(r:Rule, context:RequestContext):Promise<NextAction> {
  if (await validateRule(r,context)) {
    var ontrue = r.ontrue? r.ontrue.toLocaleLowerCase() : "accept";
    switch (ontrue) {
      case "accept":
        log(2, "NextAction ONTRUE: TRUE");
        return NextAction.TRUE;
      case "reject":
        log(2, "NextAction ONTRUE: FALSE");
        return NextAction.FALSE;
      case "continue":
        log(2, "NextAction ONTRUE: CONTINUE");
        return NextAction.CONTINUE;
      default:
        log (0,"Invalid ontrue: "+r.ontrue);
        return NextAction.FALSE;
    }
  }
  else {
    var onfalse = r.onfalse? r.onfalse.toLocaleLowerCase() : "continue";
    switch (onfalse) {
      case "accept":
        log(2, "NextAction ONFALSE: TRUE");
        return NextAction.TRUE;
      case "reject":
        log(2, "NextAction ONFALSE: FALSE");
        return NextAction.FALSE;
      case "continue":
        log(2, "NextAction ONFALSE: CONTINUE");
        return NextAction.CONTINUE;
      default:
        log (0,"Invalid onfalse: "+r.onfalse);
        return NextAction.FALSE;
    }
  }
}

async function validateRequest (context:RequestContext):Promise<boolean> {
  //Firstly we process all 'prefix' type rules
  log(2,"Search 'prefix' uri: "+context.requestUri);
  for (const r of context.rules as Array<Rule>) {
    // if (r.uritype==="prefix" && context.requestUri.startsWith(r.uri)) {
    //   r.totalExecuted++;
    //   log(3,"Test "+context.requestUri+" prefix")
    //   //if (await validateRule(r,context)) return true;
    //   switch (await decideNext(r,context)) {
    //     case NextAction.FALSE:
    //       return false;
    //     case NextAction.TRUE:
    //       r.totalValid++;
    //       return true;
    //     case NextAction.CONTINUE:
    //       r.totalValid++;
    //       continue;
    //   }
    // }
    if (r.uritype==="prefix") {
      for (var ruleUri of r.uris) {
        if (context.requestUri.startsWith(ruleUri)) {
          r.totalExecuted++;
          log(3, `Test ${context.requestUri} against prefix ruleUri: ${ruleUri}`)
          switch (await decideNext(r,context)) {
            case NextAction.FALSE:
              return false;
            case NextAction.TRUE:
              r.totalValid++;
              return true;
            case NextAction.CONTINUE:
              r.totalValid++;
              continue;
          }
        }
      }
    }
  }


  // then we process all 'regex' type rules
  log(2,"Search 'regex' uri: "+context.requestUri);
  // for-of is used beacause fo async fuctions inside 'forEach' or 'some'
  for (const r of context.rules as Array<Rule>) {
    // if (r.uritype==="regex") {
    //   log(3,"Test "+r.uri);
    //   var regex=new RegExp(r.uri,'g');
    //   log(3,"Test: "+context.requestUri + " = "+ r.uri);
    //   log(3,"Matches: "+Array.from(context.requestUri.matchAll(regex)).length);
    //   if (Array.from(context.requestUri.matchAll(regex)).length>0) {
    //     r.totalExecuted++;
    //     switch (await decideNext(r,context)) {
    //       case NextAction.FALSE:
    //         return false;
    //       case NextAction.TRUE:
    //         r.totalValid++;
    //         return true;
    //       case NextAction.CONTINUE:
    //         r.totalValid++;
    //         continue;
    //     }
    //   }
    // }
    if (r.uritype==="regex") {
      for (var ruleUri of r.uris) {
        log(3, `Test ${context.requestUri} against regex ruleUri: ${ruleUri}`)
        var regex=new RegExp(ruleUri,'g');
        log(3,"# matches: "+Array.from(context.requestUri.matchAll(regex)).length);
        if (Array.from(context.requestUri.matchAll(regex)).length>0) {
          r.totalExecuted++;
          switch (await decideNext(r,context)) {
            case NextAction.FALSE:
              return false;
            case NextAction.TRUE:
              r.totalValid++;
              return true;
            case NextAction.CONTINUE:
              r.totalValid++;
              continue;
          }
        }
  
      }
    }

  }


  // Finally we search for 'exact' rule uri
  log(2,"Search 'exact' uri: "+context.requestUri);
  for (const r of context.rules as Array<Rule>) {
    if (r.uritype==="exact") {
      for (var ruleUri of r.uris) {
        log(3, `Test ${context.requestUri} against exact ruleUri: ${ruleUri}`)
        if (context.requestUri===ruleUri) {
          r.totalExecuted++;
          switch (await decideNext(r,context)) {
            case NextAction.FALSE:
              return false;
            case NextAction.TRUE:
              r.totalValid++;
              return true;
            case NextAction.CONTINUE:
              r.totalValid++;
              continue;
          }
        }
      }
    } 
  }

  //+++ if no uri matches, we return false, what in fact will return 401 to ingress, what in fact will return 401 to browser: even if the uri resource doesn't exist
  return false;
}


function log(level:number, obj:any) {
  if (logLevel>=level) console.log(obj);
}


function redirLog() {
  console.log("Redirecting log");

  const origLog=console.log;

  console.log = (a) => {
    if (typeof(a)==='string' ) {
      if (a.startsWith('HttpError: HTTP request failed')) {
        a=a.substring(0,200);
      }
    }
    if (a && a.response!==undefined) {
      a={
          statusCode: a.response.statusCode,
          statuesMessage:a.response.statusMessage,
          method: a.response.request.method,
          path: a.response.request.path,
          body: a.response.body
        };
    }
    origLog(a);
  }
  console.error = (a:object) => {
    origLog("*********ERR*********");
    origLog(a);
  }
  console.debug = (a:object) => {
    origLog("*********DEB*********");
    origLog(a);
  } 
}


function readConfig() {
  log(0,"Reading config");
  env.obkaName=process.env.OBKA_NAME as any;
  env.obkaNamespace=process.env.OBKA_NAMESPACE as any;
  env.obkaValidators=new Map();
  env.obkaRulesets=new Map();

  // load validators
  log(1,"Loading validators");
  //env.obkaValidators.set(env.obkaName,new Map());
  var arrayVals = JSON.parse(process.env.OBKA_VALIDATORS as string) as Array<any>;
  log(1,arrayVals);
  arrayVals.forEach(validator  => {
    var type = Object.keys(validator)[0];
    var val:Validator = (validator as any)[type];
    val.type=type;
    log(1, `loading ${val.name}`);
    //env.obkaValidators.get(env.obkaName)?.set(val.name, val);
    env.obkaValidators.set(val.name, val);
  });
  console.log(env.obkaValidators);


  // load rulesets
  // env.obkaRulesets.set(env.obkaName,JSON.parse(process.env.OBKA_RULESETS as string) as Array<Rule>);
  log(1,"Loading rulesets");
  var arrayRulesets = JSON.parse(process.env.OBKA_RULESETS as string) as Array<Ruleset>;
  log(1,arrayRulesets);
  arrayRulesets.forEach(ruleset  => {
    log(1, `loading ${ruleset.name}`);

    // fix uri prefixes for ruleset: they must no end in '/'
    for (var i=0;i<ruleset.uriPrefix.length;i++) {
      while (ruleset.uriPrefix[i].endsWith('/')) ruleset.uriPrefix[i]=ruleset.uriPrefix[i].substring(0,ruleset.uriPrefix[i].length-1);
    }
    // remove duplicates using spread syntax and Set (Ser constructor removes duplicates)
    ruleset.uriPrefix = [... new Set(ruleset.uriPrefix)];
    
    // fix uris in each ruleset rule, creating always a strin array mergin 'uri' with 'uris'
    for (var r of ruleset.rules) {
      log(2, `reviewing rule ${JSON.stringify(r)}`);
      if (!r.uris) {
        log(3, `creating uris array`);
        r.uris=[];
      }
      if (r.uri!==null && r.uri!==undefined) {
        log(3, `merging uri ${r.uri}`);
        r.uris.push(r.uri);
        r.uri=undefined;
      }

      // fix uri prefixes for rule: they must no end in '/'
      for (var i=0;i<r.uris.length;i++) {
        log(4, `Fixing uri ${r.uris[i]}`);
        while (r.uris[i].endsWith('/')) r.uris[i]=r.uris[i].substring(0,r.uris[i].length-1);
      }
      // remove duplicates using spread syntax and Set (Ser constructor removes duplicates)
      r.uris = [... new Set(r.uris)];
    
      log(2, `result rule ${JSON.stringify(r)}`);
    }
    env.obkaRulesets.set(ruleset.name, ruleset);
  });
  console.log(env.obkaRulesets);


  log(0,"===================================================================================");
  log(0,"Environment parameters");
  log(0,env);
  log(0,"Validators");
  log(0,env.obkaValidators);
  log(0,"Rulesets");
  log(0,env.obkaRulesets);
  log(0,"===================================================================================");
  log(0,"Config read");
}


async function createAuthorizatorValidators(authorizator:string) {
  log(0,"Load validators");
  //var validatorNames = env.obkaValidators.get(authorizator)?.keys();
  var validatorNames = env.obkaValidators.keys();
  if (validatorNames) {
    for (const valName of validatorNames) {
      log(1,"Loading validator "+valName);
      //var val = env.obkaValidators.get(authorizator)?.get(valName);
      var val = env.obkaValidators.get(valName);
      if (val) {
        log(1,val);
        var decoder = await getValidator(authorizator,valName);
        val.decoder = (decoder as ITokenDecoder);
        log(1,val);
      }
      else {
        log(0, "Cannot load validator "+valName);
      }
    }
  }
}


async function getValidator(authorizator:string,name:string) {
  //var validator=env.obkaValidators.get(authorizator)?.get(name);
  var validator=env.obkaValidators.get(name);
  log(1, 'Obtaining validator: '+validator?.name+'/'+validator?.type);
  switch (validator?.type) {
    case 'azureB2c':
      return new AzureB2c(validator);
    case 'google':
      return new Google(validator);
    case 'azureAd':
      return new AzureAd(validator);
    case 'cognito':
      return new Cognito(validator);
    case 'keycloak':
      return new KeyCloak(validator);
    case 'basicAuth':
      console.log(`basicAuth store type: ${validator.storeType}`);
      var usersdb:any = {};
      if (validator.storeType==='secret') {
        if (validator.storeSecret!==undefined) {
          var ct = await coreApi.readNamespacedSecret(validator.storeSecret,env.obkaNamespace);
          var secretData = ct.body.data;
          var secretName = validator.storeSecret;
          var secret = {
            metadata: {
              name: validator.storeSecret,
              namespace: env.obkaNamespace
            },
            data: {}
          };

          if (secretData===undefined) {
            log(0,`No secret '${validator.storeSecret}' exists, we create an empty 'userdb' secret`);
            (secret as any).data[validator.storeKey] = 'e30=';   // {} in base64
            await coreApi.createNamespacedSecret(env.obkaNamespace, secret);
          }
          else {
            log(0,`Secret found, looking for key '${validator.storeKey}' in secret`);
            var value = Buffer.from(secretData[validator.storeKey], 'base64').toString('utf-8');
            usersdb=JSON.parse(value);
            log(1,`Read usersdb ${JSON.stringify(usersdb)}`);
          }

          if (validator.users!==undefined) {
            log(1,'Copying new users to usersdb');
            for (var user of validator.users) {
              log(1, user);
              var u:any=user;
              if (usersdb[u.name]===undefined) {
                log(1, `Added ${u.name}`);
                usersdb[u.name]=u.password;
              }
              else {
                log(1, `Skipped ${u.name}`);
              }
            }
            log(1, `Updating usersdb in secret`);
            (secret as any).data[validator.storeKey] = Buffer.from(JSON.stringify(usersdb), 'utf-8').toString('base64');
            await coreApi.replaceNamespacedSecret(secretName,env.obkaNamespace, secret);
          }
        }
        else {
          log(0,"No storeSecret provided");
          return new NullValidator(validator, false); 
        }
      }
      else {
        // we are working on an 'inline' validator
        // we read all users from validator and store them in a simpler format:  { 'user1': 'password1' , 'user2': 'password2'... }
        if (validator.users) {
          for (var usr of validator.users) {
            log(1, `Adding user ${JSON.stringify(usr)}`);
            usersdb[(usr as any).name] = (usr as any).password;
          }
        }
      }
      return new BasicAuth(validator, usersdb);
    case 'custom':
      log(0,"cm:"+validator.configMap);
      if (validator.configMap) {
        var content = await coreApi.readNamespacedConfigMap(validator.configMap,env.obkaNamespace);
        var data = content.body.data;
        if (data!==undefined) {
          var code=(data as any)[validator.key];
          console.log(code);
          validator.code=code;
          return new Custom(validator);
        }
      }
      else {
        log(0,"No configMap provided");
        return new NullValidator(validator, false); 
      }
    default:
      log(0, 'Unknown validator type: '+validator?.type);
      return new NullValidator((validator as Validator), false); 
  }
}


function listen() {
  app.listen(port, () => {
    log(0,`Oberkorn Authorizator listening at port ${port}`);
  });

  if (env.obkaApi) {
    log(0,`API interface enabled. Configuring API endpoint at /obk-authorizator/${env.obkaName}/api...`);
    //serve api
    var ca:OverviewApi = new OverviewApi(env, status);
    app.use(`/obk-authorizator/${env.obkaName}/api`, ca.routeApi);
  }


  // serve health endpoint
  app.get('/', (req, res) => {
    log(1,req.url);
    res.status(200).send('<blockquote><pre>**************************************************<br/>* Oberkorn Authorizator running at ' + Date.now() + " *<br/>**************************************************</pre></blockquote>");
  });


  // serve prometheus data
  if (env.obkaPrometheus) {
    log(0,'Configuring Prometheus endpoint');
    promRequestsMetric = new Counter ({
      name:'totalRequests',
      help:'Total number of requests in one Oberkorn authorizator'
    });
    
    promValidMetric = new Counter ({
      name:'totalValidRequests',
      help:'Total number of requests in one Oberkorn authorizator that has been answered positively (status code 200)'
    });
  
    app.get('/metrics', async (req, res) => {
      log(1,req.url);
      res.set('Content-Type', register.contentType);
      res.end(await register.metrics());
    });
  }


  // serve authrozation requests
  app.get('/validate/*', async (req, res) => {
    log(1,"***************************************************************************************************************************************************************");
    log(1,Date.now().toString() + " "+req.url);
    
    log(2,'===============================================');
    log(2,'Headers received');
    log(2,req.headers);
    log(2,'===============================================');

    // extarct original uri, it depends on the ingress provider
    var originalUri = req.headers["x-original-uri"] as string;
    if (!originalUri) originalUri = req.headers["x-forwarded-uri"] as string;
    log(2, `OriginalUri: ${originalUri} with authorization: ${req.headers["authorization"]}`);

    if (req.url.startsWith("/validate/")) {  //+++ this occurs always!!
      // var obkaName:string = req.url.substring(10);
      // log(1,'obkaName: '+obkaName);

      var authValue:string=req.headers["authorization"] as string;
      if (authValue && authValue.startsWith("Bearer ")) authValue=authValue.substring(7);
      if (authValue && authValue.startsWith("Basic ")) authValue=authValue.substring(6);

      // find ruleset to apply to this uri
      var ruleset:Ruleset|undefined=undefined;
      var localUri=undefined;
      for (var rs of env.obkaRulesets.values()) {
        for (var uriPrefix  of rs.uriPrefix) {
          var i = uriPrefix.length;
          if (originalUri.substring(0,i)===uriPrefix) {
            ruleset=rs;
            localUri=originalUri.substring(i);
            log(3,`Found valid ruleset: ${rs.name} with uri prefix ${uriPrefix} for local uri '${localUri}'`);
            break;
          }
        }
        if (localUri!==undefined) break;
      }


      if (ruleset===undefined) {
        log(1,`No ruleset found for uri ${originalUri}`);
        res.status(401).send({ valid:false });
        return;
      }

      // create context
      while (localUri?.endsWith("/")) localUri=localUri?.substring(0,localUri.length-1);
      var rc:RequestContext={
        rules: (ruleset!==undefined)? ruleset.rules : [],
        requestUri: (localUri as string),
        responseHeaders: new Map()
      };

      if (authValue) rc.token=authValue;
      log(3,"===============================");
      log(3,"RequestContext:");
      log(3,JSON.stringify(rc));

      var start=process.hrtime()
      log(2, "Start time: "+start.toString());
      var isOk = await validateRequest(rc);
      var end=process.hrtime()
      log(2, "End time: "+end.toString());
      var micros = ( (end[0] * 1000000 + end[1] / 1000) - (start[0] * 1000000 + start[1] / 1000));
      if (env.obkaPrometheus) promRequestsMetric.inc();
      log(2,`Request: ${originalUri}  Elapsed(us): ${micros}  Count: ${++status.totalRequests}`);
      status.totalMicros+=micros;
      if (isOk) {
        if (env.obkaPrometheus) promValidMetric.inc();
        res.status(200).send({ valid:true });
        log(3,{ valid:true });
        return;
      }
      else {
        if (rc.responseHeaders!==null) {
          rc.responseHeaders?.forEach( (v:string, k:string) => {
            console.log(k);
            console.log(v);
            res.set(k,v);
          });
        }
        res.status(401).send({ valid:false });
        log(3,{ valid:false });
        return;
      }
    }

  });
}



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
console.log('Oberkorn Authorizator is starting...');
console.log(`Oberkorn Authorizator version is ${VERSION}`);
if (process.env.OBKA_LOG_LEVEL!==undefined) logLevel= +process.env.OBKA_LOG_LEVEL;
env.obkaPrometheus = (process.env.OBKA_PROMETHEUS==='true');
env.obkaApi = (process.env.OBKA_API==='true');
console.log('Log level: '+logLevel);

// filter log messages
redirLog();

// read config
readConfig();

// instantiate validators
createAuthorizatorValidators(env.obkaName).then ( () => {
  // launch authorizator
  log(0,"OBK1500 Control is being given to Oberkorn authorizator");
  // launch listener
  listen();
}).
catch( (err) =>{
  log(0,"Cannot start Controller");
  log(0,err);
});

