
export interface IValidationFormatResult {
    success: false;
    fields: Record<string, string>;
    message: string[];
}