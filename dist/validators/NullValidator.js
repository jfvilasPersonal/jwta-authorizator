"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NullValidator = void 0;
const Basic_1 = require("./Basic");
class NullValidator extends Basic_1.Basic {
    constructor(val, returnValue) {
        super(val);
        this.returnValue = false;
        this.decodeAndValidateToken = async (context) => {
            this.totalRequests++;
            context.validationStatus = this.returnValue;
        };
        console.log(`Instancing NullValidator with '${returnValue}' return value`);
        this.returnValue = returnValue;
    }
}
exports.NullValidator = NullValidator;
