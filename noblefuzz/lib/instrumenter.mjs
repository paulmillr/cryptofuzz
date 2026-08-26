import { parse } from 'acorn';

const BITMAP_BITS = 22;
const BITMAP_MASK = (1 << BITMAP_BITS) - 1;

function featureId(filename, kind, offset) {
  const value = `${filename}\0${kind}\0${offset}`;
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0 & BITMAP_MASK;
}

function walk(node, visit) {
  if (node === null || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
    if (Array.isArray(value)) {
      for (const child of value) walk(child, visit);
    } else if (value !== null && typeof value === 'object') {
      walk(value, visit);
    }
  }
}

function directiveEnd(block) {
  let position = block.start + 1;
  for (const statement of block.body) {
    if (statement.type !== 'ExpressionStatement' || typeof statement.directive !== 'string') break;
    position = statement.end;
  }
  return position;
}

export function instrumentSource(source, filename = 'source.js') {
  const ast = parse(source, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    allowHashBang: true,
    allowAwaitOutsideFunction: true,
  });
  const edits = new Map();
  const instrumented = new Set();
  const insert = (position, text) => {
    const list = edits.get(position) ?? [];
    list.push(text);
    edits.set(position, list);
  };
  const hitExpression = (kind, position) => `globalThis.__noblefuzzHit(${featureId(filename, kind, position)})`;
  const hit = (kind, position) => `${hitExpression(kind, position)};`;
  const blockEntry = (block, kind, directives = false) => {
    const key = `${kind}:${block.start}`;
    if (instrumented.has(key)) return;
    instrumented.add(key);
    insert(directives ? directiveEnd(block) : block.start + 1, hit(kind, block.start));
  };
  const destination = (statement, kind) => {
    if (statement === null) return;
    if (statement.type === 'BlockStatement') {
      blockEntry(statement, kind);
    } else {
      insert(statement.start, `{${hit(kind, statement.start)}`);
      insert(statement.end, '}');
    }
  };
  const expressionDestination = (expression, kind) => {
    insert(expression.start, `(${hitExpression(kind, expression.start)},`);
    insert(expression.end, ')');
  };

  walk(ast, (node) => {
    switch (node.type) {
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        if (node.body.type === 'BlockStatement') blockEntry(node.body, 'function', true);
        else expressionDestination(node.body, 'function-expression');
        break;
      case 'IfStatement':
        destination(node.consequent, 'if-true');
        destination(node.alternate, 'if-false');
        break;
      case 'ForStatement':
      case 'ForInStatement':
      case 'ForOfStatement':
      case 'WhileStatement':
      case 'DoWhileStatement':
        destination(node.body, 'loop-body');
        break;
      case 'ConditionalExpression':
        expressionDestination(node.consequent, 'conditional-true');
        expressionDestination(node.alternate, 'conditional-false');
        break;
      case 'LogicalExpression':
        expressionDestination(node.right, `logical-${node.operator}`);
        break;
      case 'SwitchCase': {
        const searchStart = node.test === null ? node.start + 7 : node.test.end;
        const searchEnd = node.consequent[0]?.start ?? node.end;
        const colon = source.indexOf(':', searchStart);
        if (colon !== -1 && colon < searchEnd) insert(colon + 1, hit(node.test === null ? 'switch-default' : 'switch-case', node.start));
        break;
      }
      case 'CatchClause':
        blockEntry(node.body, 'catch');
        break;
      case 'TryStatement':
        if (node.finalizer !== null) blockEntry(node.finalizer, 'finally');
        break;
    }
  });

  let result = source;
  for (const [position, values] of [...edits.entries()].sort((a, b) => b[0] - a[0])) {
    result = `${result.slice(0, position)}${values.join('')}${result.slice(position)}`;
  }
  return result;
}

export class GuidanceTracker {
  constructor() {
    this.marks = new Uint16Array(1 << BITMAP_BITS);
    this.epoch = 0;
    this.active = false;
    this.touched = [];
    this.hit = (id) => {
      if (!this.active) return;
      const index = id & BITMAP_MASK;
      if (this.marks[index] === this.epoch) return;
      this.marks[index] = this.epoch;
      this.touched.push(index);
    };
  }

  begin() {
    if (++this.epoch > 0xffff) {
      this.marks.fill(0);
      this.epoch = 1;
    }
    this.touched.length = 0;
    this.active = true;
  }

  finish() {
    this.active = false;
    return this.touched.map((id) => `js:${id.toString(16)}`);
  }
}
