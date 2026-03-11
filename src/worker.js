import forge from "node-forge";

export default {
  async fetch(request) {

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return new Response(
        JSON.stringify({ ok: false, error: "POST required" }),
        { headers: corsHeaders }
      );
    }

    try {

      const body = await request.json();

      const company_name = body.company_name;
      const vat_number = body.vat_number;
      const city = body.city;
      const address = body.address;
      const branch_name = body.branch_name;
      const otp = body.otp;

      // توليد مفاتيح RSA
      const keys = forge.pki.rsa.generateKeyPair(2048);

      // إنشاء CSR
      const csr = forge.pki.createCertificationRequest();
      csr.publicKey = keys.publicKey;

      csr.setSubject([
        { name: "commonName", value: `TST-${vat_number}` },
        { name: "organizationName", value: company_name },
        { name: "organizationalUnitName", value: branch_name },
        { name: "localityName", value: city }
      ]);

      csr.sign(keys.privateKey);

      const csrPem = forge.pki.certificationRequestToPem(csr);
      const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);

      return new Response(
        JSON.stringify({
          ok: true,
          message: "CSR generated successfully",
          csr: csrPem,
          private_key: privateKeyPem
        }),
        { headers: corsHeaders }
      );

    } catch (error) {

      return new Response(
        JSON.stringify({
          ok: false,
          error: error.message
        }),
        { headers: corsHeaders }
      );

    }
  }
};
