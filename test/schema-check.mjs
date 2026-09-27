// A small JSON Schema checker for the keywords schema/pqc-scan.schema.json
// uses, so that the tests can hold every report to the published schema
// without a dependency. A keyword it does not know is an error, never
// silently ignored: the schema cannot grow a rule these tests skip.
const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', '$defs']);
const KNOWN = new Set(['$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties', 'items', 'minimum', 'pattern', 'maxLength']);

/** @returns {string[]} the errors, empty when `value` matches */
export function check(schema, value, root = schema, at = '$') {
  const errors = [];
  for (const key of Object.keys(schema)) {
    if (!ANNOTATIONS.has(key) && !KNOWN.has(key)) errors.push(`${at}: the checker does not know "${key}"`);
  }
  if (schema.$ref) {
    const target = schema.$ref.replace(/^#\//, '').split('/').reduce((s, k) => s[k], root);
    return errors.concat(check(target, value, root, at));
  }
  if ('const' in schema && value !== schema.const) errors.push(`${at}: expected ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${at}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  if (schema.type) {
    const types = [].concat(schema.type);
    if (!types.some((t) => isType(value, t))) return errors.concat(`${at}: ${JSON.stringify(value)} is not ${types.join(' or ')}`);
  }
  if (typeof value === 'number' && 'minimum' in schema && value < schema.minimum) errors.push(`${at}: below ${schema.minimum}`);
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${at}: does not match ${schema.pattern}`);
    if ('maxLength' in schema && [...value].length > schema.maxLength) errors.push(`${at}: longer than ${schema.maxLength}`);
  }
  if (Array.isArray(value) && schema.items) value.forEach((v, i) => errors.push(...check(schema.items, v, root, `${at}[${i}]`)));
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const k of schema.required ?? []) if (!(k in value)) errors.push(`${at}: missing ${k}`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) errors.push(...check(schema.properties[k], v, root, `${at}.${k}`));
      else if (schema.additionalProperties === false) errors.push(`${at}: unexpected ${k}`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') errors.push(...check(schema.additionalProperties, v, root, `${at}.${k}`));
    }
  }
  return errors;
}

function isType(value, type) {
  switch (type) {
    case 'null': return value === null;
    case 'array': return Array.isArray(value);
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
    case 'integer': return Number.isInteger(value);
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    default: return typeof value === type;
  }
}
