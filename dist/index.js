"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const AzureAd_1 = require("./validators/AzureAd");
const AzureB2c_1 = require("./validators/AzureB2c");
const Cognito_1 = require("./validators/Cognito");
// import { Google } from './validators/Google';
// import { Github } from './validators/Github';
const NullValidator_1 = require("./validators/NullValidator");
const prom_client_1 = require("prom-client");
/* JWTA RoadMap*/
//+++ invalidate token de acuerdo a claims
//+++ invalidate token  de un usuario
//+++ refresh de cached signing keys schedulable (ahora es cada hora)
//+++ monitor, anallizar un usuario (ver sus tokens)
//+++ perfmon
//+++ monitoring, integrar con grafana
//+++ descargar de una ruta codigo js que implementa un validador
//implementar un mecanismo de licencia que descarga el codigo de una url si la licencia es correcta
const app = (0, express_1.default)();
app.use(body_parser_1.default.json());
const port = 3000;
var logLevel = 9;
var totalRequests = 0;
//prometheus
var promRequestsMetric;
var promValidMetric;
var env = {
    jwtaName: '',
    jwtaNamespace: '',
    jwtaPrometheus: false,
    jwtaValidators: new Map(),
    jwtaRulesets: new Map()
};
async function validateRule(rule, context) {
    var _a, _b, _c, _d;
    var validatorsArray = env.jwtaValidators.get(env.jwtaName);
    var validatorsList = new Map();
    // si hay una lista especifica de vallidadores la preparamos, si no usamos todos los validadores definidos en el CRD
    if (rule.validators) {
        for (const v of rule.validators) {
            if (((_a = env.jwtaValidators.get(env.jwtaName)) === null || _a === void 0 ? void 0 : _a.get(v)) !== undefined) {
                validatorsList.set(v, (_b = env.jwtaValidators.get(env.jwtaName)) === null || _b === void 0 ? void 0 : _b.get(v));
            }
            else {
                log(3, "Unknown validator: " + v);
            }
        }
    }
    else {
        validatorsList = validatorsArray;
    }
    log(4, "Validators list to use for rule");
    log(4, validatorsList);
    for (const validator of validatorsList.values()) {
        log(5, ">>> TESTING VALIDATOR " + validator.name);
        if (context.validationStatus)
            delete context.validationStatus;
        if (context.validationError)
            delete context.validationError;
        log(5, "Test 'unrestricted' ruletype");
        if ((rule === null || rule === void 0 ? void 0 : rule.type) === "unrestricted") {
            log(5, "RESULT of 'unrestricted' ruletype: true");
            return true;
        }
        log(5, "Test 'valid' ruletype with validator");
        log(5, validator);
        var v = (_d = (_c = env.jwtaValidators.get('ja-jfvilas')) === null || _c === void 0 ? void 0 : _c.get(validator.name)) === null || _d === void 0 ? void 0 : _d.ivalidator;
        if (v === undefined) {
            log(0, "IValidator not created (undefined): " + 'ja-jfvilas/' + validator.name);
            //return false;
            continue;
        }
        if (context.token) {
            await v.decodeAndValidateToken(context);
            if ((rule === null || rule === void 0 ? void 0 : rule.type) === "valid") {
                log(5, "RESULT of 'valid' ruletype: " + context.validationStatus);
                if (context.validationStatus)
                    return true;
                else
                    continue;
            }
            switch (rule === null || rule === void 0 ? void 0 : rule.type) {
                // claim rule, we must evaluate policies
                case "claim":
                    log(5, "Test 'claim' ruletype");
                    //si sabemos que el token no es valido, no hay que verificar nada mas
                    if (!context.validationStatus) {
                        log(5, 'token invalid');
                        //return false;
                        break;
                    }
                    var claimName = rule.name;
                    var tokenClaimValue = context.decoded[claimName];
                    log(5, "claimName: " + claimName);
                    log(5, "claimValue: " + tokenClaimValue);
                    switch (rule === null || rule === void 0 ? void 0 : rule.policy) {
                        // present, the claim MUST exist (with any value)
                        case 'present':
                            if (tokenClaimValue !== undefined)
                                return true;
                            //return false;
                            break;
                        // not present, the claim name must not exist
                        case 'notpresent':
                            if (tokenClaimValue === undefined)
                                return true;
                            //return false;
                            break;
                        // is, the claim value must be ewqual to AT LEAST one of the vlaules in the value list
                        case 'is':
                            if (rule.options.includes('lowercase')) {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue === value.toLowerCase())
                                        return true;
                                });
                            }
                            else if (rule.options.includes('uppercase')) {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue === value.toUpperCase())
                                        return true;
                                });
                            }
                            else {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue === value)
                                        return true;
                                });
                            }
                            //return false;
                            break;
                        // contains any, claim value must contain AT LEAST one values (at any position)
                        case 'containsany':
                            if (rule.options.includes('lowercase')) {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue.includes(value.toLowerCase()))
                                        return true;
                                });
                            }
                            else if (rule.options.includes('uppercase')) {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue.includes(value.toUpperCase()))
                                        return true;
                                });
                            }
                            else {
                                rule.values.forEach((value) => {
                                    if (tokenClaimValue.includes(value))
                                        return true;
                                });
                            }
                            //return false;
                            break;
                        // contains all, claim value must contain ALL the values (at any position)
                        case 'containsall':
                            if (rule.options.includes('lowercase')) {
                                var fulfill = rule.values.filter((value) => {
                                    if (tokenClaimValue.includes(value.toLowerCase()))
                                        return true;
                                }).length;
                                if (fulfill === rule.values.length)
                                    return true;
                            }
                            else if (rule.options.includes('uppercase')) {
                                var fulfill = rule.values.filter((value) => {
                                    if (tokenClaimValue.includes(value.toUpperCase()))
                                        return true;
                                }).length;
                                if (fulfill === rule.values.length)
                                    return true;
                            }
                            else {
                                var fulfill = rule.values.filter((value) => {
                                    if (tokenClaimValue.includes(value))
                                        return true;
                                }).length;
                                if (fulfill === rule.values.length)
                                    return true;
                            }
                            //return false;
                            break;
                        // matches any, claim value must match at least one value
                        case 'matchesany':
                            rule.values.forEach((value) => {
                                var regex = new RegExp(value, 'g');
                                var numMatches = Array.from(tokenClaimValue.matchAll(regex)).length;
                                if (numMatches > 0)
                                    return true;
                            });
                            //return false;
                            break;
                        // matches all, claim value must match all values
                        case 'matchesall':
                            var fulfill = rule.values.filter((value) => {
                                var regex = new RegExp(value, 'g');
                                return Array.from(tokenClaimValue.matchAll(regex)).length > 0;
                            }).length;
                            if (fulfill === rule.values.length)
                                return true;
                            //return false;
                            break;
                        // invalid policy
                        default:
                            log(0, "invalid policy: " + rule.policy);
                            //return false;
                            break;
                    }
                    break;
                // or rule, at least, one sub-rule must be true
                case 'or':
                    log(5, "Test 'or' ruletype");
                    for (const r of rule.subset) {
                        if (await validateRule(r, context))
                            return true;
                    }
                    break;
                //return false;
                // and policy, all sub-rules must be true
                case 'and':
                    log(5, "Test 'and' ruletype");
                    var valid = 0;
                    for (const r of rule.subset) {
                        if (await validateRule(r, context))
                            valid++;
                        else
                            break;
                    }
                    if (valid == rule.subset.length)
                        return true;
                    break;
                default:
                    // invalid rule type
                    log(0, 'Invalid rule tpye: ' + rule.type);
                    //return false;
                    break;
            }
        }
        else {
            log(5, "No token present, do not invoke validator");
        }
    }
    return false;
}
async function validateRequest(context) {
    //search for 'exact' rule uri
    log(2, "Search 'exact' uri: " + context.uri);
    for (const r of context.ruleset) {
        if (r.uritype === "exact" && r.uri === context.uri) {
            log(3, "Test " + context.uri + " exact");
            if (await validateRule(r, context))
                return true;
        }
    }
    //search for 'prefix' rule uri
    log(2, "Search 'prefix' uri: " + context.uri);
    for (const r of context.ruleset) {
        if (r.uritype === "prefix" && context.uri.startsWith(r.uri)) {
            log(3, "Test " + context.uri + " prefix");
            if (await validateRule(r, context))
                return true;
        }
    }
    // search for 'regex' rule uri
    log(2, "Search 'regex' uri: " + context.uri);
    // for-of is used beacouse fo async fuction sinside 'forEach' or 'some'
    for (const r of context.ruleset) {
        if (r.uritype === "regex") {
            log(3, "Test " + r.uri);
            var regex = new RegExp(r.uri, 'g');
            log(3, "Test: " + context.uri + " = " + r.uri);
            log(3, "Matches: " + Array.from(context.uri.matchAll(regex)).length);
            if (Array.from(context.uri.matchAll(regex)).length > 0) {
                if (await validateRule(r, context))
                    return true;
            }
        }
    }
    return false;
}
function log(level, obj) {
    if (logLevel >= level)
        console.log(obj);
}
function redirLog() {
    console.log("Redirecting log");
    const origLog = console.log;
    console.log = (a) => {
        if (typeof (a) === 'string') {
            if (a.startsWith('HttpError: HTTP request failed')) {
                a = a.substring(0, 200);
            }
        }
        if (a && a.response !== undefined) {
            a = {
                statusCode: a.response.statusCode,
                statuesMessage: a.response.statusMessage,
                method: a.response.request.method,
                path: a.response.request.path,
                body: a.response.body
            };
        }
        origLog(a);
    };
    console.error = (a) => {
        origLog("*********ERR*********");
        origLog(a);
    };
    console.debug = (a) => {
        origLog("*********DEB*********");
        origLog(a);
    };
}
function readConfig() {
    log(0, "Reading config");
    env.jwtaName = process.env.JWTA_NAME;
    env.jwtaNamespace = process.env.JWTA_NAMESPACE;
    env.jwtaValidators = new Map();
    env.jwtaRulesets = new Map();
    // para poder tener shared authorizator, cargamos los rulesets con su nombre
    env.jwtaRulesets.set(env.jwtaName, JSON.parse(process.env.JWTA_RULESET));
    // // cargar los validators
    // env.jwtaValidators.set(env.jwtaName,new Map());
    // var arrayVals = JSON.parse(process.env.JWTA_VALIDATORS as string) as Array<Validator>;
    // log(1,"***arrayVals***");
    // log(1,arrayVals);
    // arrayVals.forEach( v => {
    //   env.jwtaValidators.get(env.jwtaName)?.set(v.name, v);
    // })
    // console.log(env.jwtaValidators);
    // // cargar los balidators
    // log(1,"***arrayBals***");
    // env.jwtaBalidators.set(env.jwtaName,new Map());
    // var arrayBals = JSON.parse(process.env.JWTA_BALIDATORS as string) as Array<{}>;
    // log(1,arrayBals);
    // arrayBals.forEach(v  => {
    //   var type=Object.keys(v)[0];
    //   var val:Validator = (v as any)[type];
    //   val.type=type;
    //   env.jwtaBalidators.get(env.jwtaName)?.set(val.name, val);
    // });
    // console.log(env.jwtaBalidators);
    // cargar los balidators
    log(1, "***arrayVals***");
    env.jwtaValidators.set(env.jwtaName, new Map());
    var arrayVals = JSON.parse(process.env.JWTA_VALIDATORS);
    log(1, arrayVals);
    arrayVals.forEach(v => {
        var _a;
        var type = Object.keys(v)[0];
        var val = v[type];
        val.type = type;
        (_a = env.jwtaValidators.get(env.jwtaName)) === null || _a === void 0 ? void 0 : _a.set(val.name, val);
    });
    console.log(env.jwtaValidators);
    log(0, "===================================================================================");
    log(0, "Environment parameters");
    log(0, env);
    log(0, "Validators");
    log(0, env.jwtaValidators);
    log(0, "Rulesets");
    log(0, env.jwtaRulesets);
    log(0, "===================================================================================");
    log(0, "Config read");
}
function createAuthorizatorValidators(authorizator) {
    var _a, _b;
    log(0, "Load validators");
    var validatorNames = (_a = env.jwtaValidators.get(authorizator)) === null || _a === void 0 ? void 0 : _a.keys();
    if (validatorNames) {
        for (const v of validatorNames) {
            log(1, "Loading validator " + v);
            var val = (_b = env.jwtaValidators.get(authorizator)) === null || _b === void 0 ? void 0 : _b.get(v);
            if (val) {
                log(1, val);
                var ival = getValidator(authorizator, v);
                val.ivalidator = ival;
                log(1, val);
            }
            else {
                log(0, "Cannot load validator " + v);
            }
        }
    }
}
function getValidator(authorizator, name) {
    var _a;
    var validator = (_a = env.jwtaValidators.get(authorizator)) === null || _a === void 0 ? void 0 : _a.get(name);
    log(1, 'Obtaining validator: ' + (validator === null || validator === void 0 ? void 0 : validator.type));
    switch (validator === null || validator === void 0 ? void 0 : validator.type) {
        case 'azure-b2c':
            //return new AzureB2c(validator.name, validator.tenant, validator.userflow, '0 * * * *');
            return new AzureB2c_1.AzureB2c(validator);
        case 'azure-ad':
            return new AzureAd_1.AzureAd(validator);
        //return new AzureAd(validator.name, validator.tenant, '0 * * * *');
        case 'cognito':
            return new Cognito_1.Cognito(validator);
        //return new Cognito(validator.name, validator.region, validator.userpool, '0 * * * *');
        default:
            log(0, 'Unknown validator type: ' + (validator === null || validator === void 0 ? void 0 : validator.type));
            return new NullValidator_1.NullValidator(false);
    }
}
function listen() {
    app.listen(port, () => {
        log(0, `JWT Authorizator listening at port ${port}`);
    });
    app.get('/', (req, res) => {
        log(1, req.url);
        res.status(200).send('*********************************************\n* JWT Authorizator running at ' + Date.now().toString() + " *\n**********************************************\n");
    });
    if (env.jwtaPrometheus) {
        log(0, 'Configuring Prometheus endpoint');
        promRequestsMetric = new prom_client_1.Counter({
            name: 'totalRequests',
            help: 'Total number of requests in 1 JWT Authorizator'
        });
        promValidMetric = new prom_client_1.Counter({
            name: 'totalValidRequests',
            help: 'Total number of requests in 1 JWT Authorizator that has been answered positively (status code 200)'
        });
        app.get('/metrics', async (req, res) => {
            log(1, req.url);
            res.set('Content-Type', prom_client_1.register.contentType);
            res.end(await prom_client_1.register.metrics());
        });
    }
    app.post('/validate/*', async (req, res) => {
        log(1, "***************************************************************************************************************************************************************");
        log(1, Date.now().toString() + " " + req.url);
        var data = req.body;
        log(2, "Body received");
        log(2, data);
        log(2, "Headers received");
        log(2, req.headers);
        log(2, "Authorization: " + req.headers["authorization"]);
        if (req.url.startsWith("/validate/")) {
            var jwtaName = req.url.substring(10);
            log(1, "jwtaName: " + jwtaName);
            var authValue = req.headers["authorization"];
            if (authValue && authValue.startsWith("Bearer "))
                authValue = authValue.substring(7);
            var rc = {
                ruleset: env.jwtaRulesets.get(jwtaName),
                uri: req.headers["x-original-uri"]
            };
            if (authValue)
                rc.token = authValue;
            log(3, rc);
            var start = new Date();
            log(2, "Start time: " + start.toString());
            var isOk = await validateRequest(rc);
            var end = new Date();
            log(2, "End time: " + end.toString());
            var millis = (end.getTime() - start.getTime());
            if (env.jwtaPrometheus)
                promRequestsMetric.inc();
            log(2, "Elpsed(ms): " + millis + "  ||  Count: " + (++totalRequests));
            if (isOk) {
                if (env.jwtaPrometheus)
                    promValidMetric.inc();
                res.status(200).send({ valid: true });
                log(3, { valid: true });
                return;
            }
            else {
                res.status(401).send({ valid: false });
                log(3, { valid: false });
                return;
            }
        }
    });
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
console.log('JWT Authorizator is starting...');
if (process.env.JWTA_LOG_LEVEL !== undefined)
    logLevel = +process.env.JWTA_LOG_LEVEL;
env.jwtaPrometheus = (process.env.JWTA_PROMETHEUS === 'true');
console.log('Log level: ' + logLevel);
// filtrar log messages
redirLog();
// read config
readConfig();
// instantiate validators
createAuthorizatorValidators('ja-jfvilas');
// launch authorizator
log(0, "JWTA1500 Control is being given to JWT Authorizator");
//await testValidations();
listen();
