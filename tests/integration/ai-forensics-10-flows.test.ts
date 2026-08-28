import request from 'supertest';
import { app } from '../../src/app';

describe('Phase 3 — AI & Forensic Integration: 10 Core Verification Flows', () => {
  // ---------------------------------------------------------------------------
  // 1. Genuine Internship Notice
  // ---------------------------------------------------------------------------
  test('1. Genuine internship notice -> LOW AI risk, official domain, honest non-phishing classification', async () => {
    const payload = {
      source: 'email',
      sender: 'placement@kiit.ac.in',
      subject: 'Campus Internship Drive 2026: Microsoft & Cisco Applications Open',
      body: 'Dear Students, applications for summer internships are open until August 31st on https://kiit.ac.in/internships.',
      urls: ['https://kiit.ac.in/internships'],
      domains: ['kiit.ac.in'],
      demoKey: 'verified',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.aiRisk.level).toBe('LOW');
    expect(report.authenticity.status).toBe('VERIFIED');
    expect(report.finalAssessment.verdict).toBe('VERIFIED');
  });

  // ---------------------------------------------------------------------------
  // 2. Fake Internship Notice (Fee Demand / Suspicious TLD)
  // ---------------------------------------------------------------------------
  test('2. Fake internship notice -> HIGH AI risk due to upfront fee demand and untrusted TLD', async () => {
    const payload = {
      source: 'email',
      sender: 'recruitment@internship-opportunities.xyz',
      subject: 'Guaranteed Selection: Remote AI Internship (Stipend Rs 45,000/month)',
      body: 'To confirm your seat, pay a refundable processing fee of Rs 1,200 immediately at http://internship-stipend.xyz/pay.',
      urls: ['http://internship-stipend.xyz/pay'],
      domains: ['internship-stipend.xyz'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.aiRisk.level).toBe('HIGH');
    expect(report.messageAnalysis.payment_pressure).toBe(true);
    expect(report.finalAssessment.verdict).toBe('HIGH_RISK');
  });

  // ---------------------------------------------------------------------------
  // 3. Suspicious Credential Request
  // ---------------------------------------------------------------------------
  test('3. Suspicious credential request -> Flagged for password/OTP harvesting', async () => {
    const payload = {
      source: 'email',
      sender: 'security-alert@banking-update.net',
      subject: 'URGENT: Re-verify your account credentials immediately',
      body: 'Your account access is restricted. Please enter your password and OTP at https://portal-security-auth.com/login.',
      urls: ['https://portal-security-auth.com/login'],
      domains: ['portal-security-auth.com'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.aiRisk.level).toBe('HIGH');
    expect(report.messageAnalysis.credential_solicitation).toBe(true);
    expect(report.messageAnalysis.indicators.some((i: any) => i.type === 'CREDENTIAL_REQUEST')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 4. Suspicious URL (Bare IP Host)
  // ---------------------------------------------------------------------------
  test('4. Suspicious URL with bare IP host -> Bare IP detected and flagged HIGH risk', async () => {
    const payload = {
      source: 'email',
      sender: 'admin@notice-server.org',
      subject: 'Circular Remittance Verification',
      body: 'Access document here: http://185.220.101.5/doc/view',
      urls: ['http://185.220.101.5/doc/view'],
      domains: ['185.220.101.5'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.urlAnalysis.analyzed_urls[0].is_ip_host).toBe(true);
    expect(report.urlAnalysis.high_risk_urls.length).toBeGreaterThan(0);
  });

  // ---------------------------------------------------------------------------
  // 5. Screenshot / OCR Input
  // ---------------------------------------------------------------------------
  test('5. Screenshot OCR Input -> OCR is AVAILABLE, headers & GeoIP gracefully NOT_AVAILABLE', async () => {
    const payload = {
      source: 'screenshot',
      ocrText: 'KIIT University Placement Circular\nPlease visit https://kiit.ac.in/placements for registration.\nContact: placement@kiit.ac.in',
      ocrEvidence: {
        raw_text: 'KIIT University Placement Circular...',
        confidence: 94.8,
        urls: [{ raw_url: 'https://kiit.ac.in/placements', normalized_url: 'https://kiit.ac.in/placements', domain: 'kiit.ac.in' }],
        emails: [{ raw_email: 'placement@kiit.ac.in', normalized_email: 'placement@kiit.ac.in', domain: 'kiit.ac.in' }],
        domains: ['kiit.ac.in'],
      },
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.ocr.status).toBe('AVAILABLE');
    expect(report.forensics.status).toBe('NOT_AVAILABLE');
    expect(report.geolocation.status).toBe('NOT_AVAILABLE');
    expect(report.authenticity.status).toBe('NOT_AVAILABLE');
  });

  // ---------------------------------------------------------------------------
  // 6. Valid Institutional Signature
  // ---------------------------------------------------------------------------
  test('6. Valid Institutional Signature -> Ed25519 validated and marked VERIFIED', async () => {
    const payload = {
      source: 'notice',
      sender: 'placement@kiit.ac.in',
      subject: 'Autonomous Notice with Valid Cryptographic Signature',
      body: 'Official communication signed with institutional key.',
      demoKey: 'verified',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.authenticity.status).toBe('VERIFIED');
    expect(report.authenticity.is_authentic).toBe(true);
    expect(report.finalAssessment.verdict).toBe('VERIFIED');
  });

  // ---------------------------------------------------------------------------
  // 7. Invalid / Tampered Signature (Content Mismatch)
  // ---------------------------------------------------------------------------
  test('7. Invalid / Tampered Signature -> Mismatched content hash marked TAMPERED', async () => {
    const payload = {
      source: 'notice',
      sender: 'controller@kiit.ac.in',
      subject: 'Exam Notice (Tampered Content)',
      body: 'Modified fee remittance details: send funds to external account.',
      demoKey: 'tampered',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.authenticity.status).toBe('TAMPERED');
    expect(report.authenticity.is_authentic).toBe(false);
    expect(report.finalAssessment.verdict).toBe('TAMPERED');
    expect(report.finalAssessment.threat_level).toBe('CRITICAL');
  });

  // ---------------------------------------------------------------------------
  // 8. Revoked Notice
  // ---------------------------------------------------------------------------
  test('8. Revoked Notice -> Superseded circular explicitly flagged as REVOKED', async () => {
    const payload = {
      source: 'notice',
      sender: 'registrar@kiit.ac.in',
      subject: 'Post-Matric Scholarship Circular (Superseded)',
      body: 'Notice that was once signed but has now been revoked in the registry.',
      demoKey: 'revoked',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.authenticity.status).toBe('REVOKED');
    expect(report.finalAssessment.verdict).toBe('REVOKED');
  });

  // ---------------------------------------------------------------------------
  // 9. Missing Headers
  // ---------------------------------------------------------------------------
  test('9. Missing Headers -> Transport forensics & GeoIP honestly marked NOT_AVAILABLE', async () => {
    const payload = {
      source: 'email',
      text: 'Routine email notification without RFC822 transport headers.',
      sender: 'admissions@university.edu.in',
      urls: ['https://university.edu.in'],
      domains: ['university.edu.in'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.forensics.status).toBe('NOT_AVAILABLE');
    expect(report.geolocation.status).toBe('NOT_AVAILABLE');
    expect(report.finalAssessment.whatWeCouldNotVerify).toContain(
      'Email routing headers and SPF/DKIM records.'
    );
  });


  // ---------------------------------------------------------------------------
  // 10. Unknown Institution (Unsigned / Unregistered External Key)
  // ---------------------------------------------------------------------------
  test('10. Unknown Institution -> Cryptographic verification honestly marked NOT_AVAILABLE', async () => {
    const payload = {
      source: 'email',
      sender: 'info@unknown-external-college.org',
      subject: 'External Workshop Invitation',
      body: 'Join our public seminar next week at https://unknown-external-college.org.',
      urls: ['https://unknown-external-college.org'],
      domains: ['unknown-external-college.org'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);
    expect(res.status).toBe(200);

    const report = res.body.data;
    expect(report.authenticity.status).toBe('NOT_AVAILABLE');
    expect(report.authenticity.is_authentic).toBe(false);
    expect(report.finalAssessment.verdict).toBe('UNVERIFIED');
    expect(report.finalAssessment.whatWeCouldNotVerify).toContain(
      'Digital signature is NOT_AVAILABLE for external plain communications.'
    );
  });
});
