import { canonicalizationService } from '../../src/services/crypto/canonicalization.service';
import { NoticeCanonicalPayload } from '../../src/types';

describe('Phase 2 — Canonicalization Service Tests', () => {
  const baseNotice: NoticeCanonicalPayload = {
    institutionId: 'inst-univ-delhi-01',
    title: 'Final Examination Schedule Spring 2026',
    content: 'All undergraduate examinations commence on May 15, 2026.',
    issuedAt: '2026-04-01T10:00:00.000Z',
    expiresAt: '2026-06-30T23:59:59.000Z',
    metadata: {
      department: 'Examinations Branch',
      semester: 6,
      tags: ['exam', 'datesheet', 'undergraduate'],
      isUrgent: false,
    },
  };

  // TEST 1 — Deterministic canonicalization
  it('TEST 1: should produce exact same canonical string across multiple runs', () => {
    const run1 = canonicalizationService.canonicalizeNoticePayload(baseNotice);
    const run2 = canonicalizationService.canonicalizeNoticePayload(baseNotice);
    const run3 = canonicalizationService.canonicalizeNoticePayload({ ...baseNotice });

    expect(run1).toBe(run2);
    expect(run2).toBe(run3);
    expect(typeof run1).toBe('string');
  });

  // TEST 2 — Object key ordering
  it('TEST 2: should produce identical canonical output regardless of top-level key insertion order', () => {
    const permutedOrder: NoticeCanonicalPayload = {
      expiresAt: '2026-06-30T23:59:59.000Z',
      content: 'All undergraduate examinations commence on May 15, 2026.',
      metadata: {
        department: 'Examinations Branch',
        semester: 6,
        tags: ['exam', 'datesheet', 'undergraduate'],
        isUrgent: false,
      },
      title: 'Final Examination Schedule Spring 2026',
      issuedAt: '2026-04-01T10:00:00.000Z',
      institutionId: 'inst-univ-delhi-01',
    };

    const canonical1 = canonicalizationService.canonicalizeNoticePayload(baseNotice);
    const canonical2 = canonicalizationService.canonicalizeNoticePayload(permutedOrder);

    expect(canonical1).toBe(canonical2);
  });

  // TEST 3 — Nested object ordering
  it('TEST 3: should recursively sort nested object properties deterministically', () => {
    const nestedObj1 = {
      z: 'last',
      a: 'first',
      m: {
        gamma: 3,
        alpha: 1,
        beta: 2,
        sub: {
          y: true,
          x: false,
        },
      },
    };

    const nestedObj2 = {
      m: {
        sub: {
          x: false,
          y: true,
        },
        beta: 2,
        alpha: 1,
        gamma: 3,
      },
      a: 'first',
      z: 'last',
    };

    const str1 = canonicalizationService.canonicalize(nestedObj1);
    const str2 = canonicalizationService.canonicalize(nestedObj2);

    expect(str1).toBe(str2);
    expect(str1).toBe('{"a":"first","m":{"alpha":1,"beta":2,"gamma":3,"sub":{"x":false,"y":true}},"z":"last"}');
  });

  // TEST 4 — Array preservation
  it('TEST 4: should strictly preserve array item ordering (never sort arrays)', () => {
    const arrayObj1 = { list: ['banana', 'apple', 'cherry'] };
    const arrayObj2 = { list: ['apple', 'banana', 'cherry'] };

    const str1 = canonicalizationService.canonicalize(arrayObj1);
    const str2 = canonicalizationService.canonicalize(arrayObj2);

    expect(str1).toBe('{"list":["banana","apple","cherry"]}');
    expect(str2).toBe('{"list":["apple","banana","cherry"]}');
    expect(str1).not.toBe(str2);
  });

  // TEST 5 — Different content
  it('TEST 5: should produce different canonical string when content is altered', () => {
    const alteredNotice: NoticeCanonicalPayload = {
      ...baseNotice,
      content: 'All undergraduate examinations commence on May 16, 2026.', // Changed date
    };

    const strOriginal = canonicalizationService.canonicalizeNoticePayload(baseNotice);
    const strAltered = canonicalizationService.canonicalizeNoticePayload(alteredNotice);

    expect(strOriginal).not.toBe(strAltered);
  });

  // TEST 8 — Timestamp consistency
  it('TEST 8: should normalize equivalent Date objects, timestamp strings, and epoch numbers consistently', () => {
    const isoString = '2026-03-31T23:59:59.000Z';
    const dateObj = new Date(isoString);
    const epochMs = dateObj.getTime();

    const payloadWithIso: NoticeCanonicalPayload = {
      institutionId: 'inst-01',
      title: 'Notice',
      content: 'Content',
      issuedAt: isoString,
      expiresAt: isoString,
    };

    const payloadWithEpoch: NoticeCanonicalPayload = {
      institutionId: 'inst-01',
      title: 'Notice',
      content: 'Content',
      issuedAt: epochMs as any,
      expiresAt: dateObj as any,
    };

    const canonicalIso = canonicalizationService.canonicalizeNoticePayload(payloadWithIso);
    const canonicalEpoch = canonicalizationService.canonicalizeNoticePayload(payloadWithEpoch);

    expect(canonicalIso).toBe(canonicalEpoch);
    expect(canonicalIso).toBe(
      '{"content":"Content","expiresAt":"2026-03-31T23:59:59.000Z","institutionId":"inst-01","issuedAt":"2026-03-31T23:59:59.000Z","title":"Notice"}'
    );
  });

  // TEST 9 — Empty / edge values
  it('TEST 9: should handle empty strings, nulls, booleans, negative zeros, and empty containers safely', () => {
    const edgeObj = {
      emptyStr: '',
      nullVal: null,
      boolTrue: true,
      boolFalse: false,
      zero: 0,
      negZero: -0,
      emptyArr: [],
      emptyObj: {},
      nestedArrWithNull: [1, null, 'text', false],
    };

    const canonical = canonicalizationService.canonicalize(edgeObj);
    expect(canonical).toBe(
      '{"boolFalse":false,"boolTrue":true,"emptyArr":[],"emptyObj":{},"emptyStr":"","negZero":0,"nestedArrWithNull":[1,null,"text",false],"nullVal":null,"zero":0}'
    );
  });

  it('should ignore undefined properties in objects and serialize undefined as null in arrays', () => {
    const objWithUndefined = {
      b: 2,
      a: undefined,
      c: 'valid',
      arr: [1, undefined, 3],
    };

    const canonical = canonicalizationService.canonicalize(objWithUndefined);
    expect(canonical).toBe('{"arr":[1,null,3],"b":2,"c":"valid"}');
  });

  it('should reject non-finite numbers', () => {
    expect(() => canonicalizationService.canonicalize({ val: Infinity })).toThrow(/non-finite number/);
    expect(() => canonicalizationService.canonicalize({ val: NaN })).toThrow(/non-finite number/);
  });

  it('should validate required fields when building canonical notice payload', () => {
    expect(() =>
      canonicalizationService.canonicalizeNoticePayload({
        institutionId: '',
        title: 'Title',
        content: 'Content',
        issuedAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2026-02-01T00:00:00.000Z',
      })
    ).toThrow(/institutionId/);
  });
});
