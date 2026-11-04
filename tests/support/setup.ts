import { resolve } from 'node:path';
import jestOpenAPI from 'jest-openapi';

// Adds expect(response).toSatisfyApiSpec(): status code, content type and body checked
// against openapi/openapi.yaml.
jestOpenAPI(resolve(__dirname, '..', '..', 'openapi', 'openapi.yaml'));
