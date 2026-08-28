/**
 * A tiny async test harness. Deliberately dependency free so the suite runs
 * inside the app on a real device rather than under jest on a host machine.
 */

export type Status = 'pass' | 'fail' | 'skip';

export type TestResult = {
  group: string;
  name: string;
  status: Status;
  ms: number;
  error?: string;
};

type TestFn = () => void | Promise<void>;

type Test = {name: string; fn: TestFn; skip: boolean};
type Group = {name: string; tests: Test[]};

const groups: Group[] = [];
let current: Group | null = null;

export function describe(name: string, body: () => void) {
  // Replace rather than append when a group of the same name is registered
  // again, so a Fast Refresh re-import does not duplicate every test (and the
  // duplicated group names do not collide as React keys).
  const group: Group = {name, tests: []};
  const existing = groups.findIndex(g => g.name === name);
  if (existing >= 0) groups[existing] = group;
  else groups.push(group);

  current = group;
  body();
  current = null;
}

export function it(name: string, fn: TestFn) {
  if (!current) throw new Error(`it("${name}") called outside describe()`);
  current.tests.push({name, fn, skip: false});
}

it.skip = (name: string, fn: TestFn) => {
  if (!current) throw new Error(`it.skip("${name}") called outside describe()`);
  current.tests.push({name, fn, skip: true});
};

it.if = (condition: boolean) => (condition ? it : it.skip);

function stringify(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value);
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function deepEqual(a: any, b: any): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    return (
      ka.length === kb.length && ka.every(k => deepEqual(a[k], (b as any)[k]))
    );
  }
  return false;
}

export function expect(actual: any) {
  return {
    toBe(expected: any) {
      if (actual !== expected) {
        throw new Error(
          `expected ${stringify(expected)} but got ${stringify(actual)}`,
        );
      }
    },
    toEqual(expected: any) {
      if (!deepEqual(actual, expected)) {
        throw new Error(
          `expected ${stringify(expected)} but got ${stringify(actual)}`,
        );
      }
    },
    notToBe(expected: any) {
      if (actual === expected) {
        throw new Error(`expected something other than ${stringify(expected)}`);
      }
    },
    toBeTruthy() {
      if (!actual) throw new Error(`expected truthy but got ${stringify(actual)}`);
    },
    toBeDefined() {
      if (actual === undefined || actual === null) {
        throw new Error(`expected a value but got ${stringify(actual)}`);
      }
    },
    toBeNull() {
      if (actual !== null && actual !== undefined) {
        throw new Error(`expected null but got ${stringify(actual)}`);
      }
    },
    toHaveLength(n: number) {
      if (actual?.length !== n) {
        throw new Error(`expected length ${n} but got ${actual?.length}`);
      }
    },
    toBeGreaterThan(n: number) {
      if (!(actual > n)) throw new Error(`expected ${actual} > ${n}`);
    },
    toMatch(re: RegExp) {
      if (typeof actual !== 'string' || !re.test(actual)) {
        throw new Error(`expected ${stringify(actual)} to match ${re}`);
      }
    },
  };
}

/**
 * Asserts that a promise rejects, and returns the error so the caller can make
 * further assertions about the message. Most of this suite exists to check that
 * failures arrive with a message that says what actually went wrong, so a bare
 * "it rejected" is rarely enough.
 */
export async function rejects(
  fn: () => Promise<unknown>,
  match?: RegExp,
): Promise<Error> {
  let error: Error | undefined;
  try {
    await fn();
  } catch (e) {
    error = e as Error;
  }
  if (!error) throw new Error('expected the call to reject, but it resolved');
  const message = error.message ?? '';
  if (!message || message === 'null' || message === 'undefined') {
    throw new Error(
      `rejected without a usable message (message=${stringify(message)})`,
    );
  }
  if (match && !match.test(message)) {
    throw new Error(
      `rejected with ${stringify(message)}, which does not match ${match}`,
    );
  }
  return error;
}

/** Fails if the promise has not settled within `ms`. Catches hung promises. */
export function within<T>(ms: number, promise: Promise<T>): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(
        () => reject(new Error(`promise did not settle within ${ms}ms`)),
        ms,
      ),
    ),
  ]);
}

export function registeredGroups(): string[] {
  return groups.map(g => g.name);
}

export function totalTests(): number {
  return groups.reduce((n, g) => n + g.tests.length, 0);
}

export async function run(
  onResult: (result: TestResult) => void,
  only?: string,
): Promise<TestResult[]> {
  const results: TestResult[] = [];
  for (const group of groups) {
    if (only && group.name !== only) continue;
    for (const test of group.tests) {
      const started = Date.now();
      let result: TestResult;
      if (test.skip) {
        result = {group: group.name, name: test.name, status: 'skip', ms: 0};
      } else {
        try {
          // Every test gets a ceiling so a hung native promise reports as a
          // failure instead of stalling the whole run.
          await within(120000, Promise.resolve().then(test.fn));
          result = {
            group: group.name,
            name: test.name,
            status: 'pass',
            ms: Date.now() - started,
          };
        } catch (e) {
          result = {
            group: group.name,
            name: test.name,
            status: 'fail',
            ms: Date.now() - started,
            error: (e as Error)?.message || String(e),
          };
        }
      }
      results.push(result);
      onResult(result);
      // Yield so the UI can paint between tests.
      await new Promise<void>(r => setTimeout(() => r(), 0));
    }
  }
  return results;
}
