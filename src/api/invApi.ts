import express from 'express';
import { Validator } from '../model/Validator';

export class InvApi {
  public route = express.Router();
  private vals:Map<string,Validator>;

  constructor (validators:Map<string,Validator>) {
    this.vals=validators;

    const initInvalidation = (val:Validator) => {
      if (!val.decoderInstance.invalidation?.enabled) {
        val.decoderInstance.invalidation.enabled=true;
        val.decoderInstance.invalidation.aud=[];
        val.decoderInstance.invalidation.claim=[];
        val.decoderInstance.invalidation.iss=[];
        val.decoderInstance.invalidation.sub=[];
      }
    }

    //+++ use '.all' and next() to simplify
    this.route.route('/sub')
      .post( (req, res) => {
        var vname=req.body.validator;
        var subject=req.body.subject;
        var val=this.vals.get(vname);
        if (val) {
          initInvalidation(val);
          if (val.decoderInstance.invalidation.sub.indexOf(subject)<0) val.decoderInstance.invalidation.sub.push(subject);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/iss')
      .post( (req, res) => {
        var vname=req.body.validator;
        var iss=req.body.iss;
        var val=this.vals.get(vname);
        if (val) {
          initInvalidation(val);
          if (val.decoderInstance.invalidation.sub.indexOf(iss)<0) val.decoderInstance.invalidation.sub.push(iss);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/aud')
      .post( (req, res) => {
        var vname=req.body.validator;
        var aud=req.body.aud;
        var val=this.vals.get(vname);
        if (val) {
          initInvalidation(val);
          if (val.decoderInstance.invalidation.sub.indexOf(aud)<0) val.decoderInstance.invalidation.sub.push(aud);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/claim')
      .post( (req, res) => {
        var vname=req.body.validator;
        var claim=req.body.claim;
        var val=this.vals.get(vname);
        if (val) {
          initInvalidation(val);
          if (val.decoderInstance.invalidation.sub.indexOf(claim)<0) val.decoderInstance.invalidation.sub.push(claim);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/')
      .post( (req, res) => {
        var vname=req.body.validator;
        var val=this.vals.get(vname);
        if (val) {
          res.status(200).json({ ok:true, ...val.decoderInstance.invalidation });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

  }
}
