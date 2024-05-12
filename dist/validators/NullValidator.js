"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NullValidator = void 0;
const BasicDecoder_1 = require("./BasicDecoder");
class NullValidator extends BasicDecoder_1.BasicDecoder {
    constructor(val, returnValue) {
        super(val);
        this.returnValue = false;
        this.decodeAndValidateToken = async (context) => {
            this.totalRequests++;
            var start = process.hrtime();
            if (this.returnValue) {
                this.totalOkRequests++;
                this.applyFilter(context, context.decoded.subject, 'SigninOK');
            }
            else {
                this.applyFilter(context, context.decoded.subject, 'SigninError');
            }
            context.validationStatus = this.returnValue;
            var end = process.hrtime();
            var microSeconds = ((end[0] * 1000000 + end[1] / 1000) - (start[0] * 1000000 + start[1] / 1000));
            this.totalMicros += microSeconds;
        };
        console.log(`Instancing NullValidator with '${returnValue}' return value`);
        this.returnValue = returnValue;
    }
}
exports.NullValidator = NullValidator;
