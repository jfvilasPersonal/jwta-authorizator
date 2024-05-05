import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { Basic } from './Basic';
import * as k8s from '@kubernetes/client-node';

export class Custom extends Basic implements ITokenDecoder {
  validFunction:boolean = false;
  namespace:string='';
  configMap?:string;
  configMapKey:string;
  code?:string;
  coreApi?: k8s.CoreV1Api = undefined;
  authorize = function(a?:object) { return "$$INVALID$$" };

  constructor (val:Validator, coreApi:k8s.CoreV1Api, namespace:string) {
    super(val);
    this.type="custom";
    this.namespace=namespace;
    this.coreApi=coreApi;  
    this.code=val.code;
    this.configMapKey=val.configMapkey
  }

  init = async () => {

    if (this.configMap) {
      var content:any = await this.coreApi?.readNamespacedConfigMap(this.configMap,this.namespace);
      var data = content.body.data;
      if (data!==undefined) {
        var code=(data as any)[this.configMapKey];
        this.code=code;

        if (this.code) {
          // we use a simple prototype function to check if code contains a valid authorize function.
          try {
            eval ("this.authorize = "+this.code.trim());
            if (this.authorize.length!==1) {
                console.log("Error, Invalid signature of authorize funciton ");
                return false;
            }
            else {
                console.log("Authorize function is valid");
                this.validFunction=true;
                return true;
            }
          }
          catch (ex) {
              console.log("Error, Invalid syntax on Authorize function");
              console.log(ex);
              return false;
          }
        }
        else {
          console.log("Error, no JavaScript code has been provided");
          return false;
        }
    
      }
      else {
        console.log(`No data on configmap ${this.configMap}`);
        return false;
      }
    }
    else {
      console.log('No configMap provided');
      return false;
    }

  }

  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      this.totalRequests++;
      console.log("Decode token Custom");
      if (!context.validationStatus) {
        if (this.validFunction) {
          //validate token
          try {
              console.log("Invoking custom authorize function");
              var requestData= {
                uri: context.requestUri,
                token: context.token
              };
              context.decoded = this.authorize(requestData);
              if (context.decoded) context.validationStatus=true;
            }
            catch (ex) {
              context.validationError="Error invoking authorize function"+(ex as string);
              context.validationStatus=false;     
            }
            return;
        }
        else {
          context.validationError="No valid authorize function has been provided";
          context.validationStatus=false;     
        }
      }
      else {
        console.log(`***${this.type}/${this.name} token already decoded***`);
      }

    }
    catch (err) {
      console.log(`***${this.type}/${this.name} decoding err***`);
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }
  }
  
}