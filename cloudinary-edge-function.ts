// =====================================================================
// SnapVault — Supabase Edge Function "cloudinary"  (OPTIONAL but recommended)
//
// Why it exists: deleting files from Cloudinary (and signed uploads) needs the
// Cloudinary API SECRET, which must never be placed in index.html. It lives here,
// on the server, as a Supabase secret.
//
// Deploy (dashboard):  Edge Functions → Deploy a new function → name it exactly "cloudinary"
//                      → paste this file → Deploy.
//                      Then open the function's Details and turn OFF "Verify JWT with legacy secret".
//                      (Newer Supabase projects sign logins with keys that this switch cannot check, so leaving it on
//                      rejects every real sign-in with a 401. It is safe to turn off: this code verifies the caller itself
//                      with auth.getUser() below, and only admins may delete.)
// Secrets:             Edge Functions → Secrets → add
//                        CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
//   (or CLI)           supabase secrets set CLOUDINARY_CLOUD_NAME=... CLOUDINARY_API_KEY=... CLOUDINARY_API_SECRET=...
//   SUPABASE_URL and SUPABASE_ANON_KEY are provided to Edge Functions automatically.
//
// Actions:  { action: "sign" }                      → signature for a signed upload
//           { action: "delete", photo_ids: [...] }  → PERMANENTLY deletes photos AND videos from Cloudinary and from the photos table
// Permissions: "delete" is for ADMINS only. A member's delete in the app just moves the item to the admin
//              Trash (database function trash_photos), so the file stays in Cloudinary until an admin removes it.
// A database row is removed only after Cloudinary confirmed its file is gone, so a failed item stays in the Trash and can be retried.
// =====================================================================
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

async function sha1(s: string) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    console.log("---- cloudinary function: request received ----");
    const cloud = Deno.env.get("CLOUDINARY_CLOUD_NAME");
    const key = Deno.env.get("CLOUDINARY_API_KEY");
    const secret = Deno.env.get("CLOUDINARY_API_SECRET");
    // never log the secret itself — only whether each is present, plus the non-secret values
    console.log("secrets present:", {
      cloud_name: cloud || "(missing)",
      api_key: key ? `set (${key.length} chars)` : "(missing)",
      api_secret: secret ? `set (${secret.length} chars)` : "(missing)",
    });
    if (!cloud || !key || !secret) {
      console.error("Cloudinary secrets are not configured");
      return json({ error: "Cloudinary secrets are not configured" }, 500);
    }

    const authHeader = req.headers.get("Authorization") ?? "";
    const jwt = authHeader.replace(/^Bearer\s+/i, "");
    const sb = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      {
        global: { headers: { Authorization: authHeader } },
      },
    );

    const {
      data: { user },
      error: userErr,
    } = await sb.auth.getUser(jwt);
    console.log("auth.getUser:", user ? `ok (${user.id})` : "no user", userErr?.message || "");
    if (!user) return json({ error: "Unauthorized" }, 401);

    const { data: me, error: meErr } = await sb
      .from("profiles")
      .select("username, role, status")
      .eq("id", user.id)
      .single();
    console.log("profile lookup:", me, meErr?.message || "");
    if (!me || me.status !== "approved")
      return json({ error: "Account not approved" }, 403);

    const body = await req.json().catch(() => ({}));
    console.log("action:", body?.action, "payload:", body);

    // ---- signed upload ----
    if (body.action === "sign") {
      const timestamp = Math.floor(Date.now() / 1000);
      const folder = `snapvault/${me.username}`;
      const tags = "snapvault";
      // parameters must be sorted alphabetically, then the secret appended
      const signature = await sha1(
        `folder=${folder}&tags=${tags}&timestamp=${timestamp}${secret}`,
      );
      console.log("sign: issued signature for folder", folder, "timestamp", timestamp);
      return json({
        signature,
        timestamp,
        api_key: key,
        folder,
        tags,
        cloud_name: cloud,
      });
    }

    // ---- delete ----
    if (body.action === "delete") {
      if (me.role !== "admin") {
        console.warn("delete blocked: caller is not an admin", me.username, me.role);
        return json({ error: "Not allowed" }, 403);
      }
      const ids: string[] = (
        Array.isArray(body.photo_ids) ? body.photo_ids : []
      ).slice(0, 100);
      console.log("delete requested for", ids.length, "id(s):", ids);
      if (!ids.length) return json({ ok: true, deleted: 0, cloud_failed: 0 });

      // RLS: admins can read every row, including the ones in the Trash
      const { data: rows, error } = await sb
        .from("photos")
        .select("id, public_id, url")
        .in("id", ids);
      console.log(
        "rows found:",
        rows?.length ?? 0,
        error?.message || "",
        JSON.stringify(rows),
      );
      if (error) return json({ error: error.message }, 400);
      if (!rows?.length) return json({ ok: true, deleted: 0, cloud_failed: 0 });

      let failed = 0;
      let cloudError = ""; // first Cloudinary-reported reason a destroy call failed, if any
      const removed: string[] = []; // ids whose Cloudinary file is gone
      await Promise.all(
        rows.map(async (r) => {
          const timestamp = Math.floor(Date.now() / 1000);
          const signature = await sha1(
            `invalidate=true&public_id=${r.public_id}&timestamp=${timestamp}${secret}`,
          );
          const fd = new FormData();
          fd.append("public_id", r.public_id);
          fd.append("timestamp", String(timestamp));
          fd.append("invalidate", "true");
          fd.append("api_key", key);
          fd.append("signature", signature);
          // videos live under /video/upload/ and must be destroyed with the video resource type
          const rt = String(r.url ?? "").includes("/video/upload/")
            ? "video"
            : "image";
          console.log("destroying", rt, r.public_id, "via", `${cloud}/${rt}/destroy`);
          try {
            const res = await fetch(
              `https://api.cloudinary.com/v1_1/${cloud}/${rt}/destroy`,
              { method: "POST", body: fd },
            );
            const j = await res.json().catch(() => ({}));
            console.log(
              "cloudinary response for",
              r.public_id,
              "status",
              res.status,
              "body",
              JSON.stringify(j),
            );
            if (res.ok && ["ok", "not found"].includes(j.result)) {
              removed.push(r.id);
            } else {
              failed++;
              const reason = j?.error?.message || `HTTP ${res.status}`;
              // logged so it shows up in Supabase → Edge Functions → cloudinary → Logs
              console.error("Cloudinary destroy failed", r.public_id, reason);
              if (!cloudError) cloudError = reason;
            }
          } catch (e) {
            failed++;
            console.error("Cloudinary destroy request errored", r.public_id, e);
            if (!cloudError) cloudError = String((e as Error)?.message ?? e);
          }
        }),
      );

      console.log(
        "delete summary: removed=",
        removed.length,
        "failed=",
        failed,
        "cloudError=",
        cloudError,
      );

      if (removed.length) {
        const { error: delErr } = await sb
          .from("photos")
          .delete()
          .in("id", removed);
        console.log("db delete of removed rows:", delErr?.message || "ok");
        if (delErr) return json({ error: delErr.message }, 400);
      }
      return json({
        ok: true,
        deleted: removed.length,
        deleted_ids: removed,
        cloud_failed: failed,
        cloud_error: cloudError || undefined,
      });
    }

    console.warn("unknown action:", body?.action);
    return json({ error: "Unknown action" }, 400);
  } catch (e) {
    console.error("unhandled error in cloudinary function:", e);
    return json({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
