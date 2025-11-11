import { ValidationError } from "class-validator";
import { IValidationFormatResult } from "../interfaces/IValidateErrorFormat";

export function formatValidationErrors(errors: ValidationError[]): IValidationFormatResult {
    const fields: Record<string, string> = {};
    const message: string[] = [];

    for (const err of errors) {
        const constraints = err.constraints || {};
        const messages = Object.values(constraints);

        if (messages.length > 0) {
            fields[err.property] = messages[0]; // First message per field
            message.push(...messages);         // All messages for `message` array
        }
    }

    return {
        success: false,
        fields,
        message
    };
}