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
const KeyCloak_1 = require("./validators/KeyCloak");
const BasicAuthList_1 = require("./validators/BasicAuthList");
const NullValidator_1 = require("./validators/NullValidator");
const prom_client_1 = require("prom-client");
const app = (0, express_1.default)();
app.use(body_parser_1.default.json());
const port = 3000;
const VERSION = "0.1.0";
var logLevel = 9;
var totalRequests = 0;
//prometheus
var promRequestsMetric;
var promValidMetric;
var env = {
    obkaName: '',
    obkaNamespace: '',
    obkaPrometheus: false,
    obkaValidators: new Map(),
    obkaRulesets: new Map()
};
var NextAction;
(function (NextAction) {
    NextAction[NextAction["FALSE"] = 0] = "FALSE";
    NextAction[NextAction["TRUE"] = 1] = "TRUE";
    NextAction[NextAction["CONTINUE"] = 2] = "CONTINUE";
})(NextAction || (NextAction = {}));
async function validateRule(rule, context) {
    var _a, _b, _c, _d;
    var validatorsArray = env.obkaValidators.get(env.obkaName);
    var validatorsList = new Map();
    // si hay una lista especifica de validadores la preparamos, si no usamos todos los validadores definidos en el YAML
    if (rule.validators) {
        for (const v of rule.validators) {
            if (((_a = env.obkaValidators.get(env.obkaName)) === null || _a === void 0 ? void 0 : _a.get(v)) !== undefined) {
                validatorsList.set(v, (_b = env.obkaValidators.get(env.obkaName)) === null || _b === void 0 ? void 0 : _b.get(v));
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
        var v = (_d = (_c = env.obkaValidators.get(env.obkaName)) === null || _c === void 0 ? void 0 : _c.get(validator.name)) === null || _d === void 0 ? void 0 : _d.ivalidator;
        if (v === undefined) {
            log(0, `IValidator does not exist (undefined): ${env.obkaName}/${validator.name}`);
            continue;
        }
        log(1, "Validtor type: " + validator.type);
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
                    // if we know the tokn is not valid we don't need to continue with other evlautions
                    if (!context.validationStatus) {
                        log(5, 'token invalid');
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
                            break;
                        // not present, the claim name must not exist
                        case 'notpresent':
                            if (tokenClaimValue === undefined)
                                return true;
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
                            break;
                        // matches any, claim value must match at least one value
                        case 'matchesany':
                            rule.values.forEach((value) => {
                                var regex = new RegExp(value, 'g');
                                var numMatches = Array.from(tokenClaimValue.matchAll(regex)).length;
                                if (numMatches > 0)
                                    return true;
                            });
                            break;
                        // matches all, claim value must match all values
                        case 'matchesall':
                            var fulfill = rule.values.filter((value) => {
                                var regex = new RegExp(value, 'g');
                                return Array.from(tokenClaimValue.matchAll(regex)).length > 0;
                            }).length;
                            if (fulfill === rule.values.length)
                                return true;
                            break;
                        // invalid policy
                        default:
                            log(0, "invalid policy: " + rule.policy);
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
                    break;
            }
        }
        else {
            if (validator.type === "basic-auth-list") {
                log(1, "obtener respnse header");
                await v.decodeAndValidateToken(context);
                console.log(context.responseHeaders);
                return false;
            }
            else {
                log(5, "No token present, do not invoke validator");
            }
        }
    }
    return false;
}
async function decideNext(r, context) {
    if (await validateRule(r, context)) {
        var ontrue = r.ontrue ? r.ontrue.toLocaleLowerCase() : "accept";
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
                log(0, "Invalid ontrue: " + r.ontrue);
                return NextAction.FALSE;
        }
    }
    else {
        var onfalse = r.onfalse ? r.onfalse.toLocaleLowerCase() : "continue";
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
                log(0, "Invalid onfalse: " + r.onfalse);
                return NextAction.FALSE;
        }
    }
}
async function validateRequest(context) {
    //search for 'prefix' rule uri
    log(2, "Search 'prefix' uri: " + context.uri);
    for (const r of context.ruleset) {
        //+++ if a 'reject' behaviour has been fired, we should return
        if (r.uritype === "prefix" && context.uri.startsWith(r.uri)) {
            log(3, "Test " + context.uri + " prefix");
            //if (await validateRule(r,context)) return true;
            switch (await decideNext(r, context)) {
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
    log(2, "Search 'regex' uri: " + context.uri);
    // for-of is used beacouse fo async fuction sinside 'forEach' or 'some'
    for (const r of context.ruleset) {
        if (r.uritype === "regex") {
            log(3, "Test " + r.uri);
            var regex = new RegExp(r.uri, 'g');
            log(3, "Test: " + context.uri + " = " + r.uri);
            log(3, "Matches: " + Array.from(context.uri.matchAll(regex)).length);
            if (Array.from(context.uri.matchAll(regex)).length > 0) {
                switch (await decideNext(r, context)) {
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
    log(2, "Search 'exact' uri: " + context.uri);
    for (const r of context.ruleset) {
        if (r.uritype === "exact" && r.uri === context.uri) {
            log(3, "Test " + context.uri + " exact");
            switch (await decideNext(r, context)) {
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
    env.obkaName = process.env.OBKA_NAME;
    env.obkaNamespace = process.env.OBKA_NAMESPACE;
    env.obkaValidators = new Map();
    env.obkaRulesets = new Map();
    // para poder tener shared authorizator, cargamos los rulesets con su nombre
    env.obkaRulesets.set(env.obkaName, JSON.parse(process.env.OBKA_RULESET));
    // load validators
    log(1, "Loading validators");
    env.obkaValidators.set(env.obkaName, new Map());
    var arrayVals = JSON.parse(process.env.OBKA_VALIDATORS);
    log(1, arrayVals);
    arrayVals.forEach(v => {
        var _a;
        var type = Object.keys(v)[0];
        var val = v[type];
        val.type = type;
        (_a = env.obkaValidators.get(env.obkaName)) === null || _a === void 0 ? void 0 : _a.set(val.name, val);
    });
    console.log(env.obkaValidators);
    log(0, "===================================================================================");
    log(0, "Environment parameters");
    log(0, env);
    log(0, "Validators");
    log(0, env.obkaValidators);
    log(0, "Rulesets");
    log(0, env.obkaRulesets);
    log(0, "===================================================================================");
    log(0, "Config read");
}
function createAuthorizatorValidators(authorizator) {
    var _a, _b;
    log(0, "Load validators");
    var validatorNames = (_a = env.obkaValidators.get(authorizator)) === null || _a === void 0 ? void 0 : _a.keys();
    if (validatorNames) {
        for (const v of validatorNames) {
            log(1, "Loading validator " + v);
            var val = (_b = env.obkaValidators.get(authorizator)) === null || _b === void 0 ? void 0 : _b.get(v);
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
    var validator = (_a = env.obkaValidators.get(authorizator)) === null || _a === void 0 ? void 0 : _a.get(name);
    log(1, 'Obtaining validator: ' + (validator === null || validator === void 0 ? void 0 : validator.type));
    switch (validator === null || validator === void 0 ? void 0 : validator.type) {
        case 'azure-b2c':
            return new AzureB2c_1.AzureB2c(validator);
        case 'azure-ad':
            return new AzureAd_1.AzureAd(validator);
        case 'cognito':
            return new Cognito_1.Cognito(validator);
        case 'keycloak':
            return new KeyCloak_1.KeyCloak(validator);
        case 'basic-auth-list':
            return new BasicAuthList_1.BasicAuthList(validator);
        default:
            log(0, 'Unknown validator type: ' + (validator === null || validator === void 0 ? void 0 : validator.type));
            return new NullValidator_1.NullValidator(false);
    }
}
function listen() {
    app.listen(port, () => {
        log(0, `Oberkorn Authorizator listening at port ${port}`);
    });
    app.get('/', (req, res) => {
        log(1, req.url);
        res.status(200).send('**************************************************\n* Oberkorn Authorizator running at ' + Date.now().toString() + " *\n**************************************************\n");
    });
    if (env.obkaPrometheus) {
        log(0, 'Configuring Prometheus endpoint');
        promRequestsMetric = new prom_client_1.Counter({
            name: 'totalRequests',
            help: 'Total number of requests in one Oberkorn authorizator'
        });
        promValidMetric = new prom_client_1.Counter({
            name: 'totalValidRequests',
            help: 'Total number of requests in one Oberkorn authorizator that has been answered positively (status code 200)'
        });
        app.get('/metrics', async (req, res) => {
            log(1, req.url);
            res.set('Content-Type', prom_client_1.register.contentType);
            res.end(await prom_client_1.register.metrics());
        });
    }
    app.get('/validate/*', async (req, res) => {
        var _a;
        log(1, "***************************************************************************************************************************************************************");
        log(1, Date.now().toString() + " " + req.url);
        log(2, 'Headers received');
        log(2, req.headers);
        log(2, '================');
        // extarct original uri, it depends on the ingress provider
        var originalUri = req.headers["x-original-uri"];
        if (!originalUri)
            originalUri = req.headers["x-forwarded-uri"];
        log(2, 'originalUri: ' + originalUri);
        log(2, 'Authorization: ' + req.headers["authorization"]);
        if (req.url.startsWith("/validate/")) {
            var obkaName = req.url.substring(10);
            log(1, 'obkaName: ' + obkaName);
            var authValue = req.headers["authorization"];
            if (authValue && authValue.startsWith("Bearer "))
                authValue = authValue.substring(7);
            var rc = {
                ruleset: env.obkaRulesets.get(obkaName),
                uri: originalUri,
                responseHeaders: new Map()
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
            if (env.obkaPrometheus)
                promRequestsMetric.inc();
            log(2, "Elpsed(ms): " + millis + "  ||  Count: " + (++totalRequests));
            if (isOk) {
                if (env.obkaPrometheus)
                    promValidMetric.inc();
                res.status(200).send({ valid: true });
                log(3, { valid: true });
                return;
            }
            else {
                if (rc.responseHeaders !== null) {
                    (_a = rc.responseHeaders) === null || _a === void 0 ? void 0 : _a.forEach((v, k) => {
                        console.log(k);
                        console.log(v);
                        res.set(k, v);
                    });
                }
                res.status(401).send({ valid: false });
                log(3, { valid: false });
                return;
            }
        }
    });
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
console.log('Oberkorn Authorizator is starting...');
console.log(`Oberkorn Authorizator version is ${VERSION}`);
if (process.env.OBKA_LOG_LEVEL !== undefined)
    logLevel = +process.env.OBKA_LOG_LEVEL;
env.obkaPrometheus = (process.env.OBKA_PROMETHEUS === 'true');
console.log('Log level: ' + logLevel);
// filter log messages
redirLog();
// read config
readConfig();
// instantiate validators
createAuthorizatorValidators(env.obkaName);
// launch authorizator
log(0, "OBK1500 Control is being given to Oberkorn authorizator");
// launch listener
listen();
