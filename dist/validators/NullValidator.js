"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NullValidator = void 0;
class NullValidator {
    constructor(returnValue) {
        this.returnValue = false;
        this.decodeAndValidateToken = async (context) => {
            context.validationStatus = this.returnValue;
        };
        console.log('Instancing NullValidator');
        this.returnValue = returnValue;
    }
}
exports.NullValidator = NullValidator;
