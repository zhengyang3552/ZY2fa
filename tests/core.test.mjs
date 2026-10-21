/**
 * ZY2fa · core tests
 *
 * Zero dependencies — run with:  node --test tests/
 *
 * Covers the parts where a silent bug would produce wrong verification codes:
 *   · base32 decoding            (RFC 4648)
 *   · TOTP/HOTP truncation       (RFC 4226 §5.3, RFC 6238 Appendix B vectors)
 *   · otpauth:// parsing         (Key Uri Format, including malformed input)
 *   · account normalisation      (untrusted input, import merging)
 *   · vault encryption           (PIN round-trip, wrong PIN, corrupt data)
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  base32Decode, normalizeSecret, generateHOTP, generateTOTP, stepAt,
  parseOtpAuthUri, buildOtpAuthUri, TotpError,
} from '../js/totp.js';

import {
  normalizeAccount, parseImportPayload, mergeAccounts, buildBackup,
  validatePin, filterAndSort, ValidationError,
} from '../js/store.js';

/* ---------------------------------------------------------------- helpers */

/** ASCII → base32, used to build the RFC's ASCII secrets. */
function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

const ascii = (s) => new TextEncoder().encode(s);

/* --------------------------------------------------------------- base32 */

describe('base32', () => {
  test('decodes the well-known example', () => {
    const bytes = base32Decode('JBSWY3DPEHPK3PXP');
    assert.equal(new TextDecoder().decode(bytes.subarray(0, 5)), 'Hello');
    assert.equal(bytes.length, 10);
  });

  test('is case- and separator-insensitive', () => {
    const a = base32Decode('JBSWY3DPEHPK3PXP');
    const b = base32Decode('jbsw y3dp-ehpk3pxp');
    assert.deepEqual([...a], [...b]);
  });

  test('normalizeSecret strips padding and whitespace', () => {
    assert.equal(normalizeSecret('  jbsw y3dp ehpk3pxp == '), 'JBSWY3DPEHPK3PXP');
  });

  test('rejects invalid characters with a useful message', () => {
    assert.throws(() => base32Decode('JBSWY3DP1HPK3PXP'), (err) => {
      assert.ok(err instanceof TotpError);
      assert.equal(err.code, 'SECRET_CHARSET');
      assert.match(err.message, /1/);
      return true;
    });
  });

  test('rejects secrets that are too short', () => {
    assert.throws(() => base32Decode('JBSW'), (err) => err.code === 'SECRET_SHORT');
  });

  test('rejects an empty secret', () => {
    assert.throws(() => base32Decode('   '), (err) => err.code === 'SECRET_EMPTY');
  });
});

/* ------------------------------------------------------- RFC 6238 vectors */

describe('TOTP — RFC 6238 Appendix B test vectors', () => {
  const secrets = {
    SHA1: ascii('12345678901234567890'),
    SHA256: ascii('12345678901234567890123456789012'),
    SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };

  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];

  for (const [time, sha1, sha256, sha512] of vectors) {
    test(`T=${time}`, async () => {
      const counter = Math.floor(time / 30);
      for (const [algorithm, expected] of [
        ['SHA1', sha1],
        ['SHA256', sha256],
        ['SHA512', sha512],
      ]) {
        const code = await generateHOTP(
          { secretBytes: secrets[algorithm], algorithm, digits: 8 },
          counter,
        );
        assert.equal(code, expected, `${algorithm} @ ${time}`);
      }
    });
  }

  test('6 digits is the 8-digit value truncated and zero-padded', async () => {
    const full = await generateHOTP({ secretBytes: secrets.SHA1, algorithm: 'SHA1', digits: 8 }, Math.floor(59 / 30));
    const short = await generateHOTP({ secretBytes: secrets.SHA1, algorithm: 'SHA1', digits: 6 }, Math.floor(59 / 30));
    assert.equal(full, '94287082');
    assert.equal(short, '287082'); // last 6 digits of the 8-digit value
  });

  test('generateTOTP aligns with the time step and reports remaining seconds', async () => {
    const secretBytes = secrets.SHA1;
    const at = 59_000; // 59s → step 1, ends at 60s
    const result = await generateTOTP({ secretBytes, algorithm: 'SHA1', digits: 8, period: 30 }, at);
    assert.equal(result.counter, 1);
    assert.equal(result.remaining, 1);
    assert.equal(result.code, '94287082');
  });

  test('a code is stable for the whole step and changes on the next one', async () => {
    const account = { secretBytes: secrets.SHA1, algorithm: 'SHA1', digits: 6, period: 30 };
    const start = 1_700_000_000_000;
    const a = await generateTOTP(account, start);
    // Stay inside the same time step: remaining - 1 seconds still fits.
    const within = await generateTOTP(account, start + (a.remaining - 1) * 1000);
    const next = await generateTOTP(account, start + a.remaining * 1000);
    assert.equal(a.code, within.code);
    assert.notEqual(a.code, next.code);
  });
});

describe('stepAt', () => {
  test('counts down within a step', () => {
    assert.deepEqual(stepAt(30, 0), { counter: 0, remaining: 30 });
    assert.deepEqual(stepAt(30, 1_000), { counter: 0, remaining: 29 });
    assert.deepEqual(stepAt(30, 30_000), { counter: 1, remaining: 30 });
  });

  test('supports non-default periods', () => {
    assert.deepEqual(stepAt(60, 61_000), { counter: 1, remaining: 59 });
  });
});

/* ------------------------------------------------------------- otpauth:// */

describe('parseOtpAuthUri', () => {
  test('parses a full Key Uri', () => {
    const parsed = parseOtpAuthUri(
      'otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60',
    );
    assert.equal(parsed.issuer, 'GitHub');
    assert.equal(parsed.label, 'me@example.com');
    assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(parsed.algorithm, 'SHA256');
    assert.equal(parsed.digits, 8);
    assert.equal(parsed.period, 60);
    assert.deepEqual(parsed.warnings, []);
  });

  test('falls back to the label prefix when issuer is absent', () => {
    const parsed = parseOtpAuthUri('otpauth://totp/Acme%20Corp:alice?secret=JBSWY3DPEHPK3PXP');
    assert.equal(parsed.issuer, 'Acme Corp');
    assert.equal(parsed.label, 'alice');
  });

  test('defaults omitted parameters', () => {
    const parsed = parseOtpAuthUri('otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP');
    assert.equal(parsed.algorithm, 'SHA1');
    assert.equal(parsed.digits, 6);
    assert.equal(parsed.period, 30);
  });

  test('accepts a bare secret', () => {
    const parsed = parseOtpAuthUri('JBSWY3DP EHPK3PXP');
    assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(parsed.warnings.length, 1);
  });

  test('rejects HOTP with an explanation', () => {
    assert.throws(
      () => parseOtpAuthUri('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1'),
      (err) => err.code === 'URI_HOTP',
    );
  });

  test('rejects a missing secret', () => {
    assert.throws(
      () => parseOtpAuthUri('otpauth://totp/Example:bob'),
      (err) => err.code === 'URI_NO_SECRET',
    );
  });

  test('rejects a non-otpauth URL', () => {
    assert.throws(
      () => parseOtpAuthUri('https://example.com/setup?secret=ABC'),
      (err) => err.code === 'URI_SCHEME',
    );
  });

  test('rejects empty input', () => {
    assert.throws(() => parseOtpAuthUri('   '), (err) => err.code === 'URI_EMPTY');
  });

  test('downgrades unknown algorithm/digits instead of failing', () => {
    const parsed = parseOtpAuthUri(
      'otpauth://totp/Ex:bob?secret=JBSWY3DPEHPK3PXP&algorithm=MD5&digits=7',
    );
    assert.equal(parsed.algorithm, 'SHA1');
    assert.equal(parsed.digits, 6);
    assert.equal(parsed.warnings.length, 2);
  });

  test('round-trips through buildOtpAuthUri', () => {
    const original = {
      issuer: 'GitHub', label: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA256', digits: 8, period: 60,
    };
    const parsed = parseOtpAuthUri(buildOtpAuthUri(original));
    assert.equal(parsed.issuer, original.issuer);
    assert.equal(parsed.label, original.label);
    assert.equal(parsed.algorithm, original.algorithm);
    assert.equal(parsed.digits, original.digits);
    assert.equal(parsed.period, original.period);
  });
});

/* ------------------------------------------------------------------ store */

describe('account normalisation', () => {
  const base = { issuer: '  GitHub ', label: ' me@example.com ', secret: 'jbswy3dpehpk3pxp' };

  test('trims text and canonicalises the secret', () => {
    const account = normalizeAccount(base);
    assert.equal(account.issuer, 'GitHub');
    assert.equal(account.label, 'me@example.com');
    assert.equal(account.secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(account.algorithm, 'SHA1');
    assert.equal(account.digits, 6);
    assert.equal(account.period, 30);
    assert.ok(account.id.length >= 8);
  });

  test('rejects a missing issuer in strict mode', () => {
    assert.throws(
      () => normalizeAccount({ ...base, issuer: '', label: '' }),
      (err) => err instanceof ValidationError && err.field === 'issuer',
    );
  });

  test('substitutes a placeholder issuer in lenient mode', () => {
    const account = normalizeAccount({ ...base, issuer: '', label: '' }, { lenient: true });
    assert.equal(account.issuer, '未命名服务');
  });

  test('rejects a malformed secret', () => {
    assert.throws(
      () => normalizeAccount({ ...base, secret: 'not-base32!' }),
      (err) => err instanceof ValidationError && err.field === 'secret',
    );
  });

  test('clamps the period into a usable range', () => {
    assert.equal(normalizeAccount({ ...base, period: 9000 }).period, 300);
    assert.equal(normalizeAccount({ ...base, period: 1 }).period, 5);
    assert.equal(normalizeAccount({ ...base, period: 'abc' }).period, 30);
  });

  test('keeps only supported digit counts', () => {
    assert.equal(normalizeAccount({ ...base, digits: 7 }).digits, 6);
    assert.equal(normalizeAccount({ ...base, digits: 8 }).digits, 8);
  });
});

describe('import payloads', () => {
  const account = {
    issuer: 'GitHub', label: 'me', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1', digits: 6, period: 30, createdAt: 1, updatedAt: 1,
  };

  test('accepts a ZY2fa backup object', () => {
    const payload = JSON.stringify(buildBackup([normalizeAccount(account)]));
    const { accounts, skipped } = parseImportPayload(payload);
    assert.equal(accounts.length, 1);
    assert.equal(skipped.length, 0);
  });

  test('accepts a bare array', () => {
    const { accounts } = parseImportPayload(JSON.stringify([account]));
    assert.equal(accounts.length, 1);
  });

  test('accepts newline-separated otpauth URIs', () => {
    const text = [
      'otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP',
      '# a comment',
      'otpauth://totp/B:b?secret=KRSXG5CTMVRXEZLU',
    ].join('\n');
    const { accounts } = parseImportPayload(text);
    assert.equal(accounts.length, 2);
  });

  test('reports bad rows individually instead of failing the file', () => {
    const text = JSON.stringify([
      account,
      { ...account, secret: '!!!invalid!!!' },
      { ...account, secret: '' },
    ]);
    const { accounts, skipped } = parseImportPayload(text);
    assert.equal(accounts.length, 1);
    assert.equal(skipped.length, 2);
  });

  test('refuses encrypted payloads with a clear message', () => {
    assert.throws(
      () => parseImportPayload(JSON.stringify({ encrypted: true, accounts: [] })),
      (err) => /加密/.test(err.message),
    );
  });

  test('rejects broken JSON', () => {
    assert.throws(() => parseImportPayload('{ "accounts": [ '), (err) => /JSON/.test(err.message));
  });

  test('rejects an empty payload', () => {
    assert.throws(() => parseImportPayload('   '), (err) => /为空/.test(err.message));
  });

  test('rejects an object without an accounts array', () => {
    assert.throws(
      () => parseImportPayload(JSON.stringify({ foo: 1 })),
      (err) => /accounts/.test(err.message),
    );
  });
});

describe('mergeAccounts', () => {
  const make = (label, secret = 'JBSWY3DPEHPK3PXP') =>
    normalizeAccount({ issuer: 'GitHub', label, secret });

  test('adds new records with fresh ids', () => {
    const incoming = [make('me')];
    const { accounts, added, duplicates } = mergeAccounts([], incoming);
    assert.equal(accounts.length, 1);
    assert.equal(added, 1);
    assert.equal(duplicates, 0);
    assert.notEqual(accounts[0].id, incoming[0].id);
  });

  test('skips exact duplicates', () => {
    const existing = [make('me')];
    const { added, duplicates } = mergeAccounts(existing, [make('me')]);
    assert.equal(added, 0);
    assert.equal(duplicates, 1);
  });

  test('keeps same secret under a different label', () => {
    const existing = [make('me')];
    const { added } = mergeAccounts(existing, [make('work')]);
    assert.equal(added, 1);
  });
});

describe('filterAndSort', () => {
  const list = [
    { issuer: 'Zebra', label: 'b', createdAt: 1 },
    { issuer: 'apple', label: 'c', createdAt: 3 },
    { issuer: 'Google', label: 'a', createdAt: 2 },
  ];

  test('sorts newest first by default', () => {
    const result = filterAndSort(list, { sort: 'created' });
    assert.deepEqual(result.map((r) => r.issuer), ['apple', 'Google', 'Zebra']);
  });

  test('sorts case-insensitively by issuer', () => {
    const result = filterAndSort(list, { sort: 'name' });
    assert.deepEqual(result.map((r) => r.issuer), ['apple', 'Google', 'Zebra']);
  });

  test('filters on issuer and label', () => {
    assert.equal(filterAndSort(list, { query: 'goog' }).length, 1);
    assert.equal(filterAndSort(list, { query: 'b' }).length, 1);
    assert.equal(filterAndSort(list, { query: 'zzz' }).length, 0);
  });
});

describe('validatePin', () => {
  test('accepts a compliant pin', () => {
    assert.equal(validatePin('123456'), '123456');
  });

  test('rejects short, empty and mismatched pins', () => {
    assert.throws(() => validatePin('12345'), (e) => e.field === 'pin');
    assert.throws(() => validatePin(''), (e) => e.field === 'pin');
    assert.throws(() => validatePin('123456', { confirm: '123457' }), (e) => e.field === 'confirm');
  });
});

/* ------------------------------------------------------------------ vault */

describe('vault', () => {
  /**
   * localStorage stand-in. Browsers expose stored keys as own *enumerable*
   * properties of the Storage object (which is why `Object.keys(localStorage)`
   * works), so the shim mirrors that instead of hiding values in a Map.
   */
  const makeStorage = () => {
    const store = {
      getItem(key) {
        return Object.prototype.hasOwnProperty.call(this, key) ? this[key] : null;
      },
      setItem(key, value) {
        Object.defineProperty(this, key, {
          value: String(value),
          enumerable: true,
          configurable: true,
          writable: true,
        });
      },
      removeItem(key) {
        delete this[key];
      },
      clear() {
        Object.keys(this).forEach((k) => delete this[k]);
      },
      key(i) {
        return Object.keys(this)[i] ?? null;
      },
    };
    Object.defineProperty(store, 'length', { get: () => Object.keys(store).length });
    return store;
  };

  const setup = async () => {
    globalThis.localStorage = makeStorage();
    const mod = await import(`../js/vault.js?t=${Math.random()}`);
    return { ...mod, Vault: mod.Vault };
  };

  const accounts = [
    normalizeAccount({ issuer: 'GitHub', label: 'me', secret: 'JBSWY3DPEHPK3PXP' }),
  ];

  test('starts empty when nothing is stored', async () => {
    const { Vault } = await setup();
    const vault = new Vault();
    const result = await vault.init();
    assert.equal(result.mode, 'empty');
    assert.deepEqual(result.accounts, []);
    assert.equal(vault.isLocked, false);
  });

  test('round-trips plain accounts', async () => {
    const { Vault } = await setup();
    const first = new Vault();
    await first.init();
    await first.save(accounts);

    const second = new Vault();
    const loaded = await second.init();
    assert.equal(loaded.mode, 'plain');
    assert.equal(loaded.accounts.length, 1);
    assert.equal(loaded.accounts[0].secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(loaded.accounts[0].secretBytes, undefined);
  });

  test('encrypts with a PIN and requires it to read back', async () => {
    const { Vault } = await setup();
    const first = new Vault();
    await first.init();
    await first.enablePin('correct-horse', accounts);

    const stored = JSON.parse(globalThis.localStorage.getItem('zy2fa.vault.v1'));
    assert.equal(stored.mode, 'pin');
    assert.ok(stored.cipher.data.length > 0);
    // The secret must not appear anywhere in the stored payload.
    assert.ok(!JSON.stringify(stored).includes('JBSWY3DPEHPK3PXP'));

    const second = new Vault();
    const state = await second.init();
    assert.equal(state.mode, 'pin');
    assert.equal(state.locked, true);
    assert.equal(second.isLocked, true);

    await assert.rejects(() => second.unlock('wrong-pin'), (err) => err.code === 'PIN_WRONG');

    const { accounts: decrypted } = await second.unlock('correct-horse');
    assert.equal(decrypted.length, 1);
    assert.equal(decrypted[0].secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(second.isLocked, false);
  });

  test('refuses to save while locked', async () => {
    const { Vault } = await setup();
    const first = new Vault();
    await first.init();
    await first.enablePin('correct-horse', accounts);

    const second = new Vault();
    await second.init();
    await assert.rejects(() => second.save(accounts), (err) => err.code === 'LOCKED');
  });

  test('disablePin returns to plain text', async () => {
    const { Vault } = await setup();
    const vault = new Vault();
    await vault.init();
    await vault.enablePin('correct-horse', accounts);
    await vault.disablePin('correct-horse', accounts);

    assert.equal(vault.isEncrypted, false);
    const stored = JSON.parse(globalThis.localStorage.getItem('zy2fa.vault.v1'));
    assert.equal(stored.mode, 'plain');
    assert.equal(stored.accounts.length, 1);
  });

  test('quarantines unreadable data instead of throwing', async () => {
    const { Vault } = await setup();
    globalThis.localStorage.setItem('zy2fa.vault.v1', '{not json');

    const vault = new Vault();
    const result = await vault.init();
    assert.equal(result.mode, 'empty');
    assert.equal(result.recovered, '{not json');
    assert.equal(globalThis.localStorage.getItem('zy2fa.vault.v1'), null);
    assert.equal(vault.recoveryCount(), 1);
  });

  test('drops individual invalid rows but keeps the rest', async () => {
    const { Vault } = await setup();
    globalThis.localStorage.setItem(
      'zy2fa.vault.v1',
      JSON.stringify({
        v: 1,
        mode: 'plain',
        accounts: [
          { issuer: 'Ok', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
          { issuer: 'Bad', secret: '####', algorithm: 'SHA1', digits: 6, period: 30 },
        ],
      }),
    );

    const vault = new Vault();
    const result = await vault.init();
    assert.equal(result.accounts.length, 1);
    assert.equal(result.accounts[0].issuer, 'Ok');
    assert.equal(vault.issues.length, 1);
  });

  test('wipe removes everything', async () => {
    const { Vault } = await setup();
    const vault = new Vault();
    await vault.init();
    await vault.save(accounts);
    await vault.wipe();

    assert.equal(globalThis.localStorage.getItem('zy2fa.vault.v1'), null);
    assert.equal(vault.recoveryCount(), 0);
  });
});
