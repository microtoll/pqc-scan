// A JSON Schema checker for the keywords the CycloneDX 1.6 schema uses
// (test/schemas/bom-1.6.schema.json), so that every bill of materials the
// tests write is held to the published schema without a dependency. It is
// the sibling of schema-check.mjs, which checks the scanner's own report
// schema with a smaller keyword set; the rule is the same: a keyword the
// checker does not know is an error, never silently ignored. A `format`
// other than date-time, and a reference into another schema file (SPDX
// licences, JSON signatures), are errors too: they are never reached by a
// bill of materials this package writes, and if one were, the test would say
// so rather than pass it.
const ANNOTATIONS = new Set(['$schema', '$id', '$comment', 'title', 'description', 'definitions', 'examples', 'default', 'deprecated', 'meta:enum']);
const KNOWN = new Set([
  '$ref', 'type', 'const', 'enum', 'required', 'properties', 'additionalProperties', 'items', 'additionalItems',
  'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'format', 'uniqueItems', 'minItems', 'maxItems',
  'oneOf', 'anyOf', 'allOf',
]);
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** @returns {string[]} the errors, empty when `value` matches */
export function check(schema, value, root = schema, at = '$') {
  const errors = [];
  for (const key of Object.keys(schema)) {
    if (!ANNOTATIONS.has(key) && !KNOWN.has(key)) errors.push(`${at}: the checker does not know "${key}"`);
  }
  if (schema.$ref) {
    if (!schema.$ref.startsWith('#/')) return errors.concat(`${at}: reference into another schema file (${schema.$ref}) is not checked`);
    const target = schema.$ref.slice(2).split('/').reduce((s, k) => s[k], root);
    return errors.concat(check(target, value, root, at));
  }
  if ('const' in schema && value !== schema.const) errors.push(`${at}: expected ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${at}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  if (schema.type) {
    const types = [].concat(schema.type);
    if (!types.some((t) => isType(value, t))) return errors.concat(`${at}: ${JSON.stringify(value)} is not ${types.join(' or ')}`);
  }
  if (typeof value === 'number') {
    if ('minimum' in schema && value < schema.minimum) errors.push(`${at}: below ${schema.minimum}`);
    if ('maximum' in schema && value > schema.maximum) errors.push(`${at}: above ${schema.maximum}`);
  }
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${at}: does not match ${schema.pattern}`);
    if ('minLength' in schema && [...value].length < schema.minLength) errors.push(`${at}: shorter than ${schema.minLength}`);
    if ('maxLength' in schema && [...value].length > schema.maxLength) errors.push(`${at}: longer than ${schema.maxLength}`);
    if (schema.format === 'date-time' && !DATE_TIME.test(value)) errors.push(`${at}: not a date-time`);
    else if (schema.format && schema.format !== 'date-time') errors.push(`${at}: the checker does not know format "${schema.format}"`);
  }
  if (Array.isArray(value)) {
    if ('minItems' in schema && value.length < schema.minItems) errors.push(`${at}: fewer than ${schema.minItems} items`);
    if ('maxItems' in schema && value.length > schema.maxItems) errors.push(`${at}: more than ${schema.maxItems} items`);
    if (schema.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) errors.push(`${at}: items are not unique`);
    if (Array.isArray(schema.items)) {
      value.forEach((v, i) => {
        if (i < schema.items.length) errors.push(...check(schema.items[i], v, root, `${at}[${i}]`));
        else if (schema.additionalItems === false) errors.push(`${at}[${i}]: unexpected item`);
        else if (schema.additionalItems && typeof schema.additionalItems === 'object') errors.push(...check(schema.additionalItems, v, root, `${at}[${i}]`));
      });
    } else if (schema.items) {
      value.forEach((v, i) => errors.push(...check(schema.items, v, root, `${at}[${i}]`)));
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const k of schema.required ?? []) if (!(k in value)) errors.push(`${at}: missing ${k}`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) errors.push(...check(schema.properties[k], v, root, `${at}.${k}`));
      else if (schema.additionalProperties === false) errors.push(`${at}: unexpected ${k}`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') errors.push(...check(schema.additionalProperties, v, root, `${at}.${k}`));
    }
  }
  if (schema.allOf) for (const s of schema.allOf) errors.push(...check(s, value, root, at));
  if (schema.anyOf && !schema.anyOf.some((s) => check(s, value, root, at).length === 0)) errors.push(`${at}: matches none of anyOf`);
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((s) => check(s, value, root, at).length === 0).length;
    if (matches !== 1) errors.push(`${at}: matches ${matches} of oneOf, not exactly one`);
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
