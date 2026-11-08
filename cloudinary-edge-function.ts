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
    const cloud = Deno.env.get("CLOUDINARY_CLOUD_NAME");
    const key = Deno.env.get("CLOUDINARY_API_KEY");
    const secret = Deno.env.get("CLOUDINARY_API_SECRET");
    if (!cloud || !key || !secret)
      return json({ error: "Cloudinary secrets are not configured" }, 500);

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
    } = await sb.auth.getUser(jwt);
    if (!user) return json({ error: "Unauthorized" }, 401);

    const { data: me } = await sb
      .from("profiles")
      .select("username, role, status")
      .eq("id", user.id)
      .single();
    if (!me || me.status !== "approved")
      return json({ error: "Account not approved" }, 403);

    const body = await req.json().catch(() => ({}));

    // ---- signed upload ----
    if (body.action === "sign") {
      const timestamp = Math.floor(Date.now() / 1000);
      const folder = `snapvault/${me.username}`;
      const tags = "snapvault";
      // parameters must be sorted alphabetically, then the secret appended
      const signature = await sha1(
        `folder=${folder}&tags=${tags}&timestamp=${timestamp}${secret}`,
      );
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
      if (me.role !== "admin") return json({ error: "Not allowed" }, 403);
      const ids: string[] = (
        Array.isArray(body.photo_ids) ? body.photo_ids : []
      ).slice(0, 100);
      if (!ids.length) return json({ ok: true, deleted: 0, cloud_failed: 0 });

      // RLS: admins can read every row, including the ones in the Trash
      const { data: rows, error } = await sb
        .from("photos")
        .select("id, public_id, url")
        .in("id", ids);
      if (error) return json({ error: error.message }, 400);
      if (!rows?.length) return json({ ok: true, deleted: 0, cloud_failed: 0 });

      let failed = 0;
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
          try {
            const res = await fetch(
              `https://api.cloudinary.com/v1_1/${cloud}/${rt}/destroy`,
              { method: "POST", body: fd },
            );
            const j = await res.json().catch(() => ({}));
            if (res.ok && ["ok", "not found"].includes(j.result))
              removed.push(r.id);
            else failed++;
          } catch {
            failed++;
          }
        }),
      );

      if (removed.length) {
        const { error: delErr } = await sb
          .from("photos")
          .delete()
          .in("id", removed);
        if (delErr) return json({ error: delErr.message }, 400);
      }
      return json({
        ok: true,
        deleted: removed.length,
        deleted_ids: removed,
        cloud_failed: failed,
      });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 500);
  }
});
