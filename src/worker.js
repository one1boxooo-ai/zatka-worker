import forge from "node-forge";

function randomHex(len = 16) {
  const chars = "abcdef0123456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function pemToBase64(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, "")
    .replace(/-----END CERTIFICATE REQUEST-----/g, "")
    .replace(/\n/g, "")
    .replace(/\r/g, "");
}

export default {
  async fetch(request) {

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, OTP, Accept-Version",
      "Content-Type": "application/json"
    };

    const json = (body, status = 200) =>
      new Response(JSON.stringify(body, null, 2), {
        status,
        headers: corsHeaders
      });

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return json({ ok: false, error: "POST required" }, 405);
    }

    try {

      const body = await request.json();

      const company = body.company_name;
      const vat = body.vat_number;
      const city = body.city;
      const address = body.address;
      const branch = body.branch_name;
      const otp = body.otp;

      const egs_unit_serial = body.egs_unit_serial || randomHex(8);

      const egs_serial =
        body.egs_serial_number ||
        `1-onebox|2-V.24|3-${egs_unit_serial}`;

      const common_name = `TST-${vat}`;

      /* توليد مفتاح ECDSA */

      const ec = forge.pki.ec;
      const keypair = ec.generateKeyPair({ namedCurve: "secp256k1" });

      const csr = forge.pki.createCertificationRequest();

      csr.publicKey = keypair.publicKey;

      csr.setSubject([
        { name: "commonName", value: common_name },
        { name: "organizationName", value: company },
        { name: "organizationalUnitName", value: branch },
        { name: "localityName", value: city },
        { type: "2.5.4.5", value: vat }
      ]);

      csr.sign(keypair.privateKey, forge.md.sha256.create());

      const csrPem = forge.pki.certificationRequestToPem(csr);

      const csrBase64 = pemToBase64(csrPem);

      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

      const zatca = await fetch(
        "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/compliance",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            OTP: otp,
            "Accept-Version": "V2"
          },
          body: JSON.stringify({
            csr: csrBase64
          })
        }
      );

      const text = await zatca.text();

      let parsed = null;

      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }

      return json({

        ok: zatca.ok,

        csr: csrPem,

        private_key: privateKeyPem,

        zatca: parsed

      });

    } catch (err) {

      return json({

        ok: false,
        error: err.message

      }, 500);

    }
  }
};
