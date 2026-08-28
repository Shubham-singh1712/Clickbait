import request from 'supertest';
import { app } from '../../src/app';


describe('Unified Evidence Orchestrator Integration Tests (SIH 2026)', () => {
  // ---------------------------------------------------------------------------
  // FLOW 1: Genuine Institutional Notice
  // Expected: VERIFIED, LOW risk, valid signature
  // ---------------------------------------------------------------------------
  test('FLOW 1: Genuine Institutional Notice -> VERIFIED (LOW risk)', async () => {
    const payload = {
      source: 'email',
      sender: 'placement@kiit.ac.in',
      subject: 'Campus Placement Drive 2026: Schedule & Registration',
      body: 'Dear Students, registration for campus recruitment is open at https://kiit.ac.in/placements/drives-2026.',
      urls: ['https://kiit.ac.in/placements/drives-2026'],
      domains: ['kiit.ac.in'],
      demoKey: 'verified',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.finalAssessment.verdict).toBe('VERIFIED');
    expect(report.authenticity.status).toBe('VERIFIED');
    expect(report.authenticity.is_authentic).toBe(true);
    expect(report.aiRisk.level).toBe('LOW');
    expect(report.finalAssessment.whatWeVerified).toContain(
      'Ed25519 digital signature is mathematically valid.'
    );
  });

  // ---------------------------------------------------------------------------
  // FLOW 2: Suspicious Phishing Message
  // Expected: HIGH_RISK, bare IP, credential harvesting, signature NOT_AVAILABLE
  // ---------------------------------------------------------------------------
  test('FLOW 2: Suspicious Phishing Message -> HIGH_RISK (Cryptographic NOT_AVAILABLE)', async () => {
    const payload = {
      source: 'raw_email',
      sender: 'noreply@sbi.co.in',
      subject: 'URGENT: Your SBI Account Will Be Suspended Within 24 Hours',
      body: 'Please verify your password and KYC details immediately: http://185.220.101.5/sbi-verify/login',
      rawEmail: `Received: from mail.evil-phish.com (185.220.101.5) by mx.google.com;
Authentication-Results: mx.google.com; spf=fail; dkim=fail;
From: SBI Alert <noreply@sbi.co.in>
Subject: URGENT: Your SBI Account Will Be Suspended Within 24 Hours

Please verify your password and KYC details immediately: http://185.220.101.5/sbi-verify/login`,
      urls: ['http://185.220.101.5/sbi-verify/login'],
      domains: ['185.220.101.5', 'sbi-update-security.xyz'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.finalAssessment.verdict).toBe('HIGH_RISK');
    expect(report.aiRisk.level).toBe('HIGH');
    expect(report.authenticity.status).toBe('NOT_AVAILABLE');
    expect(report.authenticity.is_authentic).toBe(false);
    expect(report.geolocation.status).toBe('AVAILABLE');
    expect(report.geolocation.origin_ip).toBe('185.220.101.5');
    expect(report.finalAssessment.whatWeCouldNotVerify).toContain(
      'Institutional digital signature (NOT_AVAILABLE).'
    );
  });

  // ---------------------------------------------------------------------------
  // FLOW 3: Modified Institutional Notice
  // Expected: TAMPERED, hash mismatch, CRITICAL threat
  // ---------------------------------------------------------------------------
  test('FLOW 3: Modified Institutional Notice -> TAMPERED (Hash Mismatch)', async () => {
    const payload = {
      source: 'notice',
      sender: 'controller@kiit.ac.in',
      subject: 'Autonomous Examination Fee Notice (Modified Content)',
      body: 'Modified fee remittance details: pay Rs 5,000 to external UPI.',
      demoKey: 'tampered',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.finalAssessment.verdict).toBe('TAMPERED');
    expect(report.authenticity.status).toBe('TAMPERED');
    expect(report.finalAssessment.threat_level).toBe('CRITICAL');
    expect(report.finalAssessment.whyTheSystemRecommends).toContain('Cryptographic hash mismatch');
  });

  // ---------------------------------------------------------------------------
  // FLOW 4: Revoked Notice
  // Expected: REVOKED, signature was valid but notice is revoked in registry
  // ---------------------------------------------------------------------------
  test('FLOW 4: Revoked Notice -> REVOKED Status', async () => {
    const payload = {
      source: 'notice',
      sender: 'registrar@kiit.ac.in',
      subject: 'Post-Matric Scholarship Circular (Superseded)',
      demoKey: 'revoked',
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.finalAssessment.verdict).toBe('REVOKED');
    expect(report.authenticity.status).toBe('REVOKED');
    expect(report.authenticity.checks.not_revoked).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // FLOW 5: Screenshot Notice
  // Expected: OCR AVAILABLE, Headers/GeoIP NOT_AVAILABLE, AI analysis computed
  // ---------------------------------------------------------------------------
  test('FLOW 5: Screenshot Notice -> OCR Available, Headers Gracefully NOT_AVAILABLE', async () => {
    const payload = {
      source: 'screenshot',
      ocrText: `OFFICIAL NOTIFICATION
KIIT Training & Placement Cell
Please verify profile on official portal: https://kiit.ac.in/placements
Contact: placement@kiit.ac.in`,
      urls: ['https://kiit.ac.in/placements'],
      domains: ['kiit.ac.in'],
      ocrEvidence: {
        raw_text: 'OFFICIAL NOTIFICATION...',
        confidence: 94.2,
      },
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.ocr.status).toBe('AVAILABLE');
    expect(report.forensics.status).toBe('NOT_AVAILABLE');
    expect(report.geolocation.status).toBe('NOT_AVAILABLE');
    expect(report.authenticity.status).toBe('NOT_AVAILABLE');
    expect(report.finalAssessment.verdict).toBe('UNVERIFIED');
    expect(report.finalAssessment.whatWeCouldNotVerify).toContain(
      'Digital signature is NOT_AVAILABLE for external plain communications.'
    );
  });

  // ---------------------------------------------------------------------------
  // FLOW 6: EML Email with Headers
  // Expected: Headers extracted, GeoIP resolved, SPF/DKIM checked
  // ---------------------------------------------------------------------------
  test('FLOW 6: EML Email -> Headers Parsed, GeoIP Resolved, Authentication Checked', async () => {
    const payload = {
      source: 'eml',
      sender: 'placement@kiit.ac.in',
      subject: 'Placement Circular 2026',
      rawEmail: `Received: from mailrelay.kiit.ac.in (14.140.120.10) by mx.google.com;
Authentication-Results: mx.google.com; spf=pass; dkim=pass;
From: KIIT Placement <placement@kiit.ac.in>
Subject: Placement Circular 2026

Registration is open at https://kiit.ac.in/placements`,
      urls: ['https://kiit.ac.in/placements'],
      domains: ['kiit.ac.in'],
    };

    const res = await request(app).post('/api/verify/unified').send(payload);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const report = res.body.data;
    expect(report.forensics.status).toBe('AVAILABLE');
    expect(report.forensics.spf_status).toBe('pass');
    expect(report.geolocation.status).toBe('AVAILABLE');
    expect(report.geolocation.country).toBe('India');
    expect(report.geolocation.city).toBe('Bhubaneswar');
  });
});
