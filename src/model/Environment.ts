import { Rule } from './Rule';
import { Validator } from './Validator';

export type Environment = {
  obkaName:string,
  obkaNamespace:string,
  obkaPrometheus:boolean,
  obkaValidators:Map<string, Map<string, Validator>>,
  obkaRulesets: Map<string, Array<Rule>>;
}
