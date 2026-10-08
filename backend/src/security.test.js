const { escapeCsv, newToken, sha256, signWebhook } = require('./security');
const { validateSchema, validateSubmission } = require('./app');
test('creates unguessable endpoint tokens',()=>{ const token=newToken(); expect(token).toMatch(/^ff_/); expect(token.length).toBeGreaterThan(30); });
test('hashes tokens',()=>expect(sha256('token')).not.toContain('token'));
test('neutralizes spreadsheet formulas',()=>expect(escapeCsv('=CMD()')).toContain("'=CMD()"));
test('signs webhook payloads',()=>expect(signWebhook('secret','body')).toMatch(/^sha256=/));
test('validates unique schemas',()=>{ expect(validateSchema([{name:'email',type:'email',required:true}])).toBe(true); expect(validateSchema([{name:'x',type:'text'},{name:'x',type:'text'}])).toBe(false); });
test('filters and validates submissions',()=>{ const schema=[{name:'email',type:'email',required:true}]; expect(validateSubmission(schema,{email:'a@b.com'})).toEqual({email:'a@b.com'}); expect(()=>validateSubmission(schema,{email:'bad'})).toThrow(); });
