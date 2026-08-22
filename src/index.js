import webpush from "web-push";

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.PWA_ORIGIN || "*",
    "Access-Control-Allow-Headers": "Content-Type, X-Portal-Secret",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };
}

function json(data, status, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(env),
    },
  });
}

function b64urlDecode(text) {
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from([...binary].map((c) => c.charCodeAt(0)));
}

async function verifyAuthToken(token, secret) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { ok: false, reason: "bad_format" };
    }

    const [payloadB64, sigB64] = parts;

    if (!secret) {
      return { ok: false, reason: "missing_worker_secret" };
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );

    const signatureOk = await crypto.subtle.verify(
      "HMAC",
      key,
      b64urlDecode(sigB64),
      new TextEncoder().encode(payloadB64),
    );

    if (!signatureOk) {
      return { ok: false, reason: "bad_signature" };
    }

    let payload;
    try {
      payload = JSON.parse(
        new TextDecoder().decode(b64urlDecode(payloadB64)),
      );
    } catch {
      return { ok: false, reason: "bad_payload" };
    }

    if (!payload.exp) {
      return { ok: false, reason: "missing_exp" };
    }

    if (Date.now() > Number(payload.exp)) {
      return {
        ok: false,
        reason: "expired",
        expiredByMs: Date.now() - Number(payload.exp),
      };
    }

    if (!payload.tipo || !payload.id) {
      return { ok: false, reason: "missing_identity" };
    }

    return { ok: true, payload };
  } catch (err) {
    return {
      ok: false,
      reason: "verify_exception",
      message: String(err?.message || err || ""),
    };
  }
}

async function endpointHash(endpoint) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(endpoint),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 24);
}

async function storeSubscription(env, identity, subscription, preferences) {
  const hash = await endpointHash(subscription.endpoint);
  const key = `sub:${identity.tipo}:${identity.id}:${hash}`;

  await env.SUBSCRIPTIONS.put(
    key,
    JSON.stringify({
      identity,
      subscription,
      preferences: {
        lavanderia: preferences?.lavanderia !== false,
        encomendas: preferences?.encomendas !== false,
        comunicados: preferences?.comunicados !== false,
        solicitacoes: preferences?.solicitacoes !== false
      },
      updatedAt: new Date().toISOString(),
    }),
  );

  return key;
}

async function loadTargets(env, audience) {
  const tipo = String(audience?.tipo || "");
  const id = String(audience?.id || "");

  if (!tipo || !id) return [];

  const prefix =
    id === "*"
      ? `sub:${tipo}:`
      : `sub:${tipo}:${id}:`;

  const items = [];
  let cursor;

  do {
    const page = await env.SUBSCRIPTIONS.list({
      prefix,
      cursor,
      limit: 1000,
    });

    for (const key of page.keys) {
      const raw = await env.SUBSCRIPTIONS.get(key.name);
      if (!raw) continue;

      try {
        const item = JSON.parse(raw);
        items.push({ key: key.name, ...item });
      } catch {}
    }

    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return items;
}

async function sendPush(env, audience, notification) {
  webpush.setVapidDetails(
    env.VAPID_SUBJECT,
    env.VAPID_PUBLIC_KEY,
    env.VAPID_PRIVATE_KEY,
  );

  const targets = await loadTargets(env, audience);
  const categoria = String(notification?.category || "geral");

  let enviados = 0;
  let removidos = 0;
  let falhas = 0;
  let ignoradosPreferencia = 0;
  let duplicados = 0;

  await Promise.all(
    targets.map(async (item) => {
      try {
        if (
          categoria !== "geral" &&
          item.preferences &&
          item.preferences[categoria] === false
        ) {
          ignoradosPreferencia++;
          return;
        }

        const eHash = await endpointHash(item.subscription.endpoint);
        const tag = String(notification?.tag || "");
        const dedupeKey = tag ? `sent:${tag}:${eHash}` : "";

        if (dedupeKey) {
          const jaEnviado = await env.SUBSCRIPTIONS.get(dedupeKey);
          if (jaEnviado) {
            duplicados++;
            return;
          }
        }

        await webpush.sendNotification(
          item.subscription,
          JSON.stringify(notification),
        );

        if (dedupeKey) {
          await env.SUBSCRIPTIONS.put(
            dedupeKey,
            new Date().toISOString(),
            { expirationTtl: 86400 },
          );
        }

        enviados++;
      } catch (err) {
        const statusCode =
          err instanceof webpush.WebPushError
            ? err.statusCode
            : Number(err?.statusCode || 0);

        if (statusCode === 404 || statusCode === 410) {
          await env.SUBSCRIPTIONS.delete(item.key);
          removidos++;
        } else {
          falhas++;
          console.error("Push error", statusCode, err);
        }
      }
    }),
  );

  return {
    ok:true,
    encontrados:targets.length,
    enviados,
    removidos,
    falhas,
    ignoradosPreferencia,
    duplicados,
  };
}

async function updatePreferences(env, identity, preferences) {
  const targets = await loadTargets(env, {
    tipo:identity.tipo,
    id:identity.id,
  });

  let atualizados = 0;

  for (const item of targets) {
    const atualizado = {
      identity:item.identity,
      subscription:item.subscription,
      preferences:{
        lavanderia:preferences?.lavanderia !== false,
        encomendas:preferences?.encomendas !== false,
        comunicados:preferences?.comunicados !== false,
        solicitacoes:preferences?.solicitacoes !== false,
      },
      updatedAt:new Date().toISOString(),
    };

    await env.SUBSCRIPTIONS.put(
      item.key,
      JSON.stringify(atualizado),
    );
    atualizados++;
  }

  return {ok:true, atualizados};
}

function parseDataUrlPhoto(dataUrl) {
  const m = String(dataUrl || "").match(
    /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/i,
  );
  if (!m) return null;

  const binary = atob(m[2]);
  const bytes = Uint8Array.from(
    [...binary].map((c) => c.charCodeAt(0)),
  );

  return {
    contentType:m[1].toLowerCase(),
    bytes,
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(env),
      });
    }

    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return json(
        {
          ok: true,
          service: "portal-vision-push",
          version: "6.7",
        },
        200,
        env,
      );
    }

    if (url.pathname === "/auth-diagnostic" && request.method === "GET") {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(env.PUSH_LINK_SECRET || ""),
      );

      const fingerprint = [...new Uint8Array(digest)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 12);

      return json(
        {
          ok: true,
          pushLinkSecretConfigured: !!env.PUSH_LINK_SECRET,
          pushLinkSecretFingerprint: fingerprint,
        },
        200,
        env,
      );
    }

    if (url.pathname === "/public-key" && request.method === "GET") {
      return json(
        { publicKey: env.VAPID_PUBLIC_KEY },
        200,
        env,
      );
    }

    if (url.pathname === "/subscribe" && request.method === "POST") {
      const body = await request.json();

      const authResult = await verifyAuthToken(
        body.authToken,
        env.PUSH_LINK_SECRET,
      );

      if (!authResult.ok) {
        return json(
          {
            ok: false,
            error: "unauthorized",
            reason: authResult.reason,
            expiredByMs: authResult.expiredByMs || undefined,
          },
          401,
          env,
        );
      }

      const identity = authResult.payload;
      const subscription = body.subscription;

      if (
        !subscription?.endpoint ||
        !subscription?.keys?.p256dh ||
        !subscription?.keys?.auth
      ) {
        return json(
          { ok: false, error: "invalid_subscription" },
          400,
          env,
        );
      }

      await storeSubscription(env, identity, subscription, body.preferences);

      return json(
        {
          ok: true,
          identity: {
            tipo: identity.tipo,
            id: identity.id,
          },
        },
        200,
        env,
      );
    }

    if (url.pathname === "/preferences" && request.method === "POST") {
      const body = await request.json();
      const authResult = await verifyAuthToken(
        body.authToken,
        env.PUSH_LINK_SECRET,
      );

      if (!authResult.ok) {
        return json(
          {ok:false,error:"unauthorized",reason:authResult.reason},
          401,
          env,
        );
      }

      const result = await updatePreferences(
        env,
        authResult.payload,
        body.preferences || {},
      );

      return json(result, 200, env);
    }

    if (url.pathname === "/ticket-photo" && request.method === "POST") {
      const body = await request.json();
      const authResult = await verifyAuthToken(
        body.authToken,
        env.PUSH_LINK_SECRET,
      );

      if (!authResult.ok) {
        return json(
          {ok:false,error:"unauthorized",reason:authResult.reason},
          401,
          env,
        );
      }

      const parsed = parseDataUrlPhoto(body.dataUrl);
      if (!parsed) {
        return json({ok:false,error:"invalid_image"},400,env);
      }

      if (parsed.bytes.byteLength > 1200000) {
        return json({ok:false,error:"image_too_large"},413,env);
      }

      const id =
        crypto.randomUUID().replace(/-/g,"") +
        Date.now().toString(36);

      await env.SUBSCRIPTIONS.put(
        `photo:${id}`,
        parsed.bytes,
        {
          metadata:{
            contentType:parsed.contentType,
            ownerType:authResult.payload.tipo,
            ownerId:authResult.payload.id,
          },
          expirationTtl:60 * 60 * 24 * 365,
        },
      );

      return json(
        {
          ok:true,
          id,
          url:`${url.origin}/photo/${id}`,
        },
        200,
        env,
      );
    }

    if (url.pathname.startsWith("/photo/") && request.method === "GET") {
      const id = url.pathname.slice("/photo/".length);
      if (!/^[a-zA-Z0-9]+$/.test(id)) {
        return new Response("Not found",{status:404});
      }

      const item = await env.SUBSCRIPTIONS.getWithMetadata(
        `photo:${id}`,
        {type:"arrayBuffer"},
      );

      if (!item.value) {
        return new Response("Not found",{status:404});
      }

      return new Response(item.value,{
        status:200,
        headers:{
          "Content-Type":item.metadata?.contentType || "image/jpeg",
          "Cache-Control":"public, max-age=86400",
          "Access-Control-Allow-Origin":env.PWA_ORIGIN || "*",
        },
      });
    }

    if (url.pathname === "/send" && request.method === "POST") {
      if (
        request.headers.get("X-Portal-Secret") !==
        env.PUSH_API_SECRET
      ) {
        return json({ ok: false, error: "unauthorized" }, 401, env);
      }

      const body = await request.json();

      if (!body?.audience || !body?.notification) {
        return json({ ok: false, error: "invalid_payload" }, 400, env);
      }

      const result = await sendPush(
        env,
        body.audience,
        body.notification,
      );

      return json(result, 200, env);
    }

    return json({ ok: false, error: "not_found" }, 404, env);
  },
};
