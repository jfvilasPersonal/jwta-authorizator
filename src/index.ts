import express from 'express';
import bodyParser from 'body-parser';
import { RequestContext } from './model/RequestContext';
import { Rule } from './model/Rule';
import { Validator } from './model/Validator';
import { Environment } from './model/Environment';

import { IValidator } from './validators/IValidator';

import { AzureAd } from './validators/AzureAd';
import { AzureB2c } from './validators/AzureB2c';
import { Cognito } from './validators/Cognito';
import { KeyCloak } from './validators/KeyCloak';
import { BasicAuthList } from './validators/BasicAuthList';
import { NullValidator } from './validators/NullValidator';
import { Counter, register } from 'prom-client';



const app = express();
app.use(bodyParser.json());
const port = 3000;
const VERSION:string = "0.1.0";
var logLevel=9;
var totalRequests=0;


//prometheus
var promRequestsMetric:Counter;
var promValidMetric:Counter;


var env:Environment = {
  obkaName: '',
  obkaNamespace:'',
  obkaPrometheus:false,
  obkaValidators:new Map(),
  obkaRulesets:new Map()
};

enum NextAction {
  FALSE=0,
  TRUE=1,
  CONTINUE=2
}

async function validateRule(rule:Rule, context:RequestContext):Promise<boolean> {
  var validatorsArray=env.obkaValidators.get(env.obkaName) as Map<string, Validator>;
  var validatorsList:Map<string, Validator>=new Map();

  // si hay una lista especifica de validadores la preparamos, si no usamos todos los validadores definidos en el YAML
  if (rule.validators) {
    for (const v of rule.validators) {
      if (env.obkaValidators.get(env.obkaName)?.get(v) as Validator!==undefined) {
        validatorsList.set (v, env.obkaValidators.get(env.obkaName)?.get(v) as Validator);
      }
      else {
        log(3,"Unknown validator: "+v);
      }
    }
  }
  else {
    validatorsList=validatorsArray;
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
    var v = env.obkaValidators.get(env.obkaName)?.get(validator.name)?.ivalidator;
    if (v===undefined) {
      log(0,`IValidator does not exist (undefined): ${env.obkaName}/${validator.name}`);
      continue;
    }

    log(1, "Validtor type: "+ validator.type);

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
      if (validator.type==="basic-auth-list") {
        log(1, "obtener respnse header");
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
  //search for 'prefix' rule uri
  log(2,"Search 'prefix' uri: "+context.uri);
  for (const r of context.ruleset as Array<Rule>) {
    //+++ if a 'reject' behaviour has been fired, we should return
    if (r.uritype==="prefix" && context.uri.startsWith(r.uri)) {
      log(3,"Test "+context.uri+" prefix")
      //if (await validateRule(r,context)) return true;
      switch (await decideNext(r,context)) {
        case NextAction.FALSE:
          return false;
        case NextAction.TRUE:
          return true;
        case NextAction.CONTINUE:
          continue;
      }
    }
  }


  // search for 'regex' rule uri
  log(2,"Search 'regex' uri: "+context.uri);
  // for-of is used beacouse fo async fuction sinside 'forEach' or 'some'
  for (const r of context.ruleset as Array<Rule>) {
    if (r.uritype==="regex") {
      log(3,"Test "+r.uri);
      var regex=new RegExp(r.uri,'g');
      log(3,"Test: "+context.uri + " = "+ r.uri);
      log(3,"Matches: "+Array.from(context.uri.matchAll(regex)).length);
      if (Array.from(context.uri.matchAll(regex)).length>0) {
        switch (await decideNext(r,context)) {
          case NextAction.FALSE:
            return false;
          case NextAction.TRUE:
            return true;
          case NextAction.CONTINUE:
            continue;
        }
      }
    }
  }


  // search for 'exact' rule uri
  log(2,"Search 'exact' uri: "+context.uri);
  for (const r of context.ruleset as Array<Rule>) {
    if (r.uritype==="exact" && r.uri===context.uri) {
      log(3,"Test "+context.uri+" exact")
      switch (await decideNext(r,context)) {
        case NextAction.FALSE:
          return false;
        case NextAction.TRUE:
          return true;
        case NextAction.CONTINUE:
          continue;
      }
    }
  }


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

  // para poder tener shared authorizator, cargamos los rulesets con su nombre
  env.obkaRulesets.set(env.obkaName,JSON.parse(process.env.OBKA_RULESET as string) as Array<Rule>);


  // load validators
  log(1,"Loading validators");
  env.obkaValidators.set(env.obkaName,new Map());
  var arrayVals = JSON.parse(process.env.OBKA_VALIDATORS as string) as Array<any>;
  log(1,arrayVals);
  arrayVals.forEach(v  => {
    var type=Object.keys(v)[0];
    var val:Validator = (v as any)[type];
    val.type=type;
    env.obkaValidators.get(env.obkaName)?.set(val.name, val);
  });
  console.log(env.obkaValidators);


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


function createAuthorizatorValidators(authorizator:string) {
  log(0,"Load validators");
  var validatorNames = env.obkaValidators.get(authorizator)?.keys();
  if (validatorNames) {
    for (const v of validatorNames) {
      log(1,"Loading validator "+v);
      var val = env.obkaValidators.get(authorizator)?.get(v);
      if (val) {
        log(1,val);
        var ival = getValidator(authorizator,v);
        val.ivalidator = ival;
        log(1,val);
      }
      else {
        log(0, "Cannot load validator "+v);
      }
    }
  }
}



function getValidator(authorizator:string,name:string) : IValidator{
  var validator=env.obkaValidators.get(authorizator)?.get(name);
  log(1, 'Obtaining validator: '+validator?.type);
  switch (validator?.type) {
    case 'azure-b2c':
      return new AzureB2c(validator);
    case 'azure-ad':
      return new AzureAd(validator);
    case 'cognito':
      return new Cognito(validator);
    case 'keycloak':
      return new KeyCloak(validator);
    case 'basic-auth-list':
      return new BasicAuthList(validator);
    default:
    log(0, 'Unknown validator type: '+validator?.type);
    return new NullValidator(false);
  }
}


function listen() {
  app.listen(port, () => {
    log(0,`Oberkorn Authorizator listening at port ${port}`);
  });

  app.get('/', (req, res) => {
    log(1,req.url);
    res.status(200).send('**************************************************\n* Oberkorn Authorizator running at ' + Date.now().toString()+" *\n**************************************************\n");
  });


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


  app.get('/validate/*', async (req, res) => {
    log(1,"***************************************************************************************************************************************************************");
    log(1,Date.now().toString() + " "+req.url);
    
    log(2,'Headers received');
    log(2,req.headers);
    log(2,'================');

    // extarct original uri, it depends on the ingress provider
    var originalUri = req.headers["x-original-uri"] as string;
    if (!originalUri) originalUri = req.headers["x-forwarded-uri"] as string;
    log(2, 'originalUri: '+originalUri);
    log(2, 'Authorization: '+req.headers["authorization"]);

    if (req.url.startsWith("/validate/")) {
      var obkaName:string = req.url.substring(10);
      log(1,'obkaName: '+obkaName);

      var authValue:string=req.headers["authorization"] as string;
      if (authValue && authValue.startsWith("Bearer ")) authValue=authValue.substring(7);

      var rc:RequestContext={
        ruleset: env.obkaRulesets.get(obkaName) as Array<Rule>,
        uri: originalUri,
        responseHeaders: new Map()
      };
      if (authValue) rc.token=authValue;
      log(3,rc);

      var start=new Date();
      log(2, "Start time: "+start.toString());
      var isOk = await validateRequest(rc);
      var end=new Date();
      log(2, "End time: "+end.toString());
      var millis = (end.getTime() - start.getTime());
      if (env.obkaPrometheus) promRequestsMetric.inc();
      log(2, "Elpsed(ms): "+millis+"  ||  Count: "+(++totalRequests));
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
console.log('Log level: '+logLevel);

// filter log messages
redirLog();

// read config
readConfig();

// instantiate validators
createAuthorizatorValidators(env.obkaName);

// launch authorizator
log(0,"OBK1500 Control is being given to Oberkorn authorizator");

// launch listener
listen();
