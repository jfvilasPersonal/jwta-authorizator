import { Rule } from './Rule';
import { Validator } from './Validator';

export type Environment = {
  jwtaName:string,
  jwtaNamespace:string,
  jwtaPrometheus:boolean,
  jwtaValidators:Map<string, Map<string, Validator>>,
  jwtaRulesets: Map<string, Array<Rule>>;
}
