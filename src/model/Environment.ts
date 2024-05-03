import { Ruleset } from './Ruleset';
import { Validator } from './Validator';

export type Environment = {
  obkaName:string,
  obkaNamespace:string,
  obkaApi:boolean,
  obkaPrometheus:boolean,
  //obkaValidators:Map<string, Map<string, Validator>>,
  obkaValidators:Map<string, Validator>,
  obkaRulesets: Map<string, Ruleset>;
}

