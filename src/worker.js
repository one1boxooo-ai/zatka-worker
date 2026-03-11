import forge from "node-forge";

function randomHex(len = 16) {
  const chars = "abcdef0123456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

export default {
  async fetch(request) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json; charset=utf-8",
    };

    const json = (body, status = 200) =>
      new Response(JSON.stringify(body, null, 2), {
        status,
        headers: corsHeaders,
      });

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return json({ ok: false, error: "POST required" }, 405);
    }

    try {
      const body = await request.json();

      const company_name = String(body.company_name || "").trim();
      const vat_number = String(body.vat_number || "").trim();
      const city = String(body.city || "").trim();
      const address = String(body.address || "").trim();
      const branch_name = String(body.branch_name || "Main Branch").trim();
      const otp = String(body.otp || "").trim();

      const invoice_type = String(body.invoice_type || "1100").trim();
      const common_name = String(
        body.common_name || `TST-${vat_number || "DEVICE"}`
      ).trim();

      const egs_manufacturer = String(
        body.egs_manufacturer || "onebox"
      ).trim();

      const egs_model = String(
        body.egs_model || "V.24"
      ).trim();

      const egs_unit_serial = String(
        body.egs_unit_serial || randomHex(16)
      ).trim();

      const egs_serial_number = String(
        body.egs_serial_number ||
          `1-${egs_manufacturer}|2-${egs_model}|3-${egs_unit_serial}`
      ).trim();

      if (!company_name) {
        return json({ ok: false, error: "company_name is required" }, 400);
      }

      if (!vat_number) {
        return json({ ok: false, error: "vat_number is required" }, 400);
      }

      if (!city) {
        return json({ ok: false, error: "city is required" }, 400);
      }

      if (!address) {
        return json({ ok: false, error: "address is required" }, 400);
      }

      // ملاحظة: otp الآن فقط نرجعه في preview إن وجد
      // لاحقًا سنستخدمه عند ربط إرسال CSR إلى ZATCA
      const keys = forge.pki.rsa.generateKeyPair(2048);

      const csr = forge.pki.createCertificationRequest();
      csr.publicKey = keys.publicKey;

      csr.setSubject([
        { name: "commonName", value: common_name },
        { name: "organizationName", value: company_name },
        { name: "organizationalUnitName", value: branch_name },
        { name: "localityName", value: city },
        { shortName: "serialNumber", value: vat_number },
      ]);

      csr.sign(keys.privateKey, forge.md.sha256.create());

      const csrPem = forge.pki.certificationRequestToPem(csr);
      const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);

      return json({
        ok: true,
        message: "CSR generated successfully",
        generated_values: {
          company_name,
          vat_number,
          city,
          address,
          branch_name,
          otp_present: !!otp,
          invoice_type,
          common_name,
          egs_manufacturer,
          egs_model,
          egs_unit_serial,
          egs_serial_number,
        },
        csr: csrPem,
        private_key: privateKeyPem,
      });
    } catch (error) {
      return json(
        {
          ok: false,
          error: error?.message || String(error),
        },
        500
      );
    }
  },
};
