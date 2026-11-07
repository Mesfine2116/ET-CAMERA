// =====================================================================
// SnapVault — Supabase Edge Function "cloudinary"  (OPTIONAL but recommended)
//
// Why it exists: deleting files from Cloudinary (and signed uploads) needs the
// Cloudinary API SECRET, which must never be placed in index.html. It lives here,
// on the server, as a Supabase secret.
//
// Deploy (dashboard):  Edge Functions → Deploy a new function → name it exactly "cloudinary"
//                      → paste this file → Deploy.   (Keep "Verify JWT" ON.)
// Secrets:             Edge Functions → Secrets → add
//                        CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
//   (or CLI)           supabase secrets set CLOUDINARY_CLOUD_NAME=... CLOUDINARY_API_KEY=... CLOUDINARY_API_SECRET=...
//   SUPABASE_URL and SUPABASE_ANON_KEY are provided to Edge Functions automatically.
//
// Actions:  { action: "sign" }                      → signature for a signed upload
//           { action: "delete", photo_ids: [...] }  → deletes photos AND videos from Cloudinary and from the photos table
// Permissions follow the database: members can only delete their own photos, admins any.
// =====================================================================
import { createClient } from 'npm:@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } })

async function sha1(s: string) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const cloud = Deno.env.get('CLOUDINARY_CLOUD_NAME')
    const key = Deno.env.get('CLOUDINARY_API_KEY')
    const secret = Deno.env.get('CLOUDINARY_API_SECRET')
    if (!cloud || !key || !secret) return json({ error: 'Cloudinary secrets are not configured' }, 500)

    const authHeader = req.headers.get('Authorization') ?? ''
    const jwt = authHeader.replace(/^Bearer\s+/i, '')
    const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user } } = await sb.auth.getUser(jwt)
    if (!user) return json({ error: 'Unauthorized' }, 401)

    const { data: me } = await sb.from('profiles').select('username, role, status').eq('id', user.id).single()
    if (!me || me.status !== 'approved') return json({ error: 'Account not approved' }, 403)

    const body = await req.json().catch(() => ({}))

    // ---- signed upload ----
    if (body.action === 'sign') {
      const timestamp = Math.floor(Date.now() / 1000)
      const folder = `snapvault/${me.username}`
      const tags = 'snapvault'
      // parameters must be sorted alphabetically, then the secret appended
      const signature = await sha1(`folder=${folder}&tags=${tags}&timestamp=${timestamp}${secret}`)
      return json({ signature, timestamp, api_key: key, folder, tags, cloud_name: cloud })
    }

    // ---- delete ----
    if (body.action === 'delete') {
      const ids: string[] = (Array.isArray(body.photo_ids) ? body.photo_ids : []).slice(0, 100)
      if (!ids.length) return json({ ok: true, deleted: 0, cloud_failed: 0 })

      // RLS: only returns rows the caller may delete (own photos, or any for admins)
      const { data: rows, error } = await sb.from('photos').select('id, public_id, url').in('id', ids)
      if (error) return json({ error: error.message }, 400)
      if (!rows?.length) return json({ ok: true, deleted: 0, cloud_failed: 0 })

      let failed = 0
      await Promise.all(rows.map(async (r) => {
        const timestamp = Math.floor(Date.now() / 1000)
        const signature = await sha1(`invalidate=true&public_id=${r.public_id}&timestamp=${timestamp}${secret}`)
        const fd = new FormData()
        fd.append('public_id', r.public_id)
        fd.append('timestamp', String(timestamp))
        fd.append('invalidate', 'true')
        fd.append('api_key', key)
        fd.append('signature', signature)
        // videos live under /video/upload/ and must be destroyed with the video resource type
        const rt = String(r.url ?? '').includes('/video/upload/') ? 'video' : 'image'
        try {
          const res = await fetch(`https://api.cloudinary.com/v1_1/${cloud}/${rt}/destroy`, { method: 'POST', body: fd })
          const j = await res.json().catch(() => ({}))
          if (!res.ok || !['ok', 'not found'].includes(j.result)) failed++
        } catch { failed++ }
      }))

      const { error: delErr } = await sb.from('photos').delete().in('id', rows.map((r) => r.id))
      if (delErr) return json({ error: delErr.message }, 400)
      return json({ ok: true, deleted: rows.length, cloud_failed: failed })
    }

    return json({ error: 'Unknown action' }, 400)
  } catch (e) {
    return json({ error: String((e as Error)?.message ?? e) }, 500)
  }
})