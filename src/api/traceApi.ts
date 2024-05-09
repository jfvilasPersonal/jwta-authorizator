import express from 'express';
import { Validator } from '../model/Validator';
import { Filter } from '../model/Filter';
import { RequestContext } from '../model/RequestContext';

export class TraceApi {
  public route = express.Router();
  private vals:Map<string,Validator>;

  constructor (validators:Map<string,Validator>) {
    this.vals=validators;

    this.route.route('/status')
      .post( (req, res) => {
        console.log(vname);
        console.log(this.vals);
        var vname=req.body.validator;
        var val=this.vals.get(vname);
        if (val) {
          res.status(200).json({ ok:true, ...val.decoderInstance.filter });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/subject')
      .post( (req, res) => {
        console.log(req.body);
        var vname=req.body.validator;
        var val=this.vals.get(vname);
        if (val!==undefined) {
          var reqFilt=req.body as Filter;
          val.decoderInstance.filter.maxEvents=reqFilt.maxEvents;
          val.decoderInstance.filter.sub = reqFilt.sub;
          val.decoderInstance.filter.events = [];
          val.decoderInstance.filter.status = true;
          res.status(200).json({ ok:true, id:Date.now() });
        }
        else {
          res.status(200).json({ ok:false, err:'validator inexistent1'});
        }
      });

    this.route.route('/events')
      .post( (req, res) => {
        var vname=req.body.validator;
        var id=req.body.id;
        console.log(vname);
        console.log(req.body);
        console.log(this.vals);
        var val=this.vals.get(vname);
        if (val!==undefined) {
          var events:RequestContext[]=[];
          val.decoderInstance.filter.events.forEach( ev => {
            if (ev.epoch>id) events.push(ev);
          });
          res.json({ ok:true, events:events });
        }
        else {
          res.status(200).json({ ok:false, err:'validator inexistent2'});
        }
      });


    this.route.route('/stop')
      .post( (req, res) => {
        var vname=req.body.validator;
        var val=this.vals.get(vname);
        if (val!==undefined) {
          val.decoderInstance.filter.status = false;
          val.decoderInstance.filter.events = [];
          res.json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'validator inexistent'});
        }
      })



  }

}
