import express from 'express';
import { Environment } from '../model/Environment';
import { Status } from '../model/Status';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from '../validators/ITokenDecoder';

export class ValidatorApi {
  public route = express.Router();
  private vals:Map<string,Validator>;

  constructor (validators:Map<string,Validator>) {
    this.vals=validators;

    this.route.route('/:vname')
      .get( (req, res) => {
        res.status(200).json(this.vals.get(req.params.vname));
      })

    this.route.route('/:vname/stats')
      .get( (req, res) => {
        var a = this.vals.get(req.params.vname)?.decoderInstance;
        res.status(200).json( { name:req.params.vname, totalRequests:a?.totalRequests, totalOkRequests:a?.totalOkRequests, totalMicros:a?.totalMicros } );
      })

  }

}
