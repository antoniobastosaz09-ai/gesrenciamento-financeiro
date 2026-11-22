// api/server.js
// API Express compatível com Vercel (serverless) e execução local.
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error("Configuração ausente: defina SUPABASE_URL e SUPABASE_ANON_KEY.");
}
try {
  new URL(SUPABASE_URL);
} catch {
  throw new Error("SUPABASE_URL não é uma URL válida.");
}

const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors({
  origin: corsOrigin ? corsOrigin.split(",").map(v => v.trim()) : true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Cliente administrativo NÃO é usado. Todas as operações respeitam o JWT e RLS.
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function publicSupabaseError(error) {
  const status = Number(error?.status || error?.statusCode || 0);
  const message = String(error?.message || "");
  if (status === 429 || /rate limit|too many requests/i.test(message)) {
    return new HttpError(429, "Muitas solicitações. Aguarde alguns minutos antes de tentar novamente.");
  }
  if (/invalid login credentials/i.test(message)) return new HttpError(401, "E-mail ou senha incorretos.");
  if (/email not confirmed/i.test(message)) return new HttpError(403, "Confirme seu e-mail antes de entrar.");
  if (/already registered|user already registered/i.test(message)) return new HttpError(409, "Este e-mail já está cadastrado.");
  if (/password should be at least|weak password/i.test(message)) return new HttpError(400, "A senha não atende aos requisitos mínimos.");
  if (/fetch failed|failed to fetch|network/i.test(message)) {
    console.error("Falha de rede ao acessar Supabase:", error);
    return new HttpError(503, "Não foi possível conectar ao serviço de autenticação. Verifique a configuração e tente novamente.");
  }
  console.error("Erro Supabase:", { message, status, code: error?.code });
  return new HttpError(status >= 400 && status < 500 ? status : 502, "Não foi possível concluir a operação. Verifique os dados e tente novamente.");
}

async function runSupabase(promise) {
  try {
    const result = await promise;
    if (result.error) throw publicSupabaseError(result.error);
    return result.data;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    console.error("Erro de comunicação com Supabase:", error);
    const msg = String(error?.message || "");
    if (/fetch failed|network|timeout/i.test(msg)) {
      throw new HttpError(503, "Falha de comunicação com o Supabase. Confira SUPABASE_URL, a chave pública e a disponibilidade do serviço.");
    }
    throw new HttpError(502, "Erro ao comunicar com o serviço de dados.");
  }
}

function requiredString(value, field, max = 150) {
  if (typeof value !== "string" || !value.trim()) throw new HttpError(400, `${field} é obrigatório.`);
  if (value.trim().length > max) throw new HttpError(400, `${field} deve ter no máximo ${max} caracteres.`);
  return value.trim();
}

function validEmail(value) {
  const email = requiredString(value, "E-mail", 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Informe um e-mail válido.");
  return email;
}

function validateTransaction(body, partial = false) {
  const data = {};
  if (!partial || body.descricao !== undefined) data.descricao = requiredString(body.descricao, "Descrição", 150);
  if (!partial || body.valor !== undefined) {
    const value = Number(body.valor);
    if (!Number.isFinite(value) || value <= 0 || value > 9999999999) throw new HttpError(400, "Informe um valor maior que zero.");
    data.valor = Math.round(value * 100) / 100;
  }
  if (!partial || body.tipo !== undefined) {
    if (!["receita", "despesa"].includes(body.tipo)) throw new HttpError(400, "Tipo deve ser receita ou despesa.");
    data.tipo = body.tipo;
  }
  if (!partial || body.categoria !== undefined) data.categoria = requiredString(body.categoria, "Categoria", 100);
  if (!partial || body.data !== undefined) {
    if (typeof body.data !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(body.data) || Number.isNaN(Date.parse(body.data + "T00:00:00Z"))) {
      throw new HttpError(400, "Informe uma data válida.");
    }
    data.data = body.data;
  }
  if (body.forma_pagamento !== undefined) {
    if (body.forma_pagamento !== null && typeof body.forma_pagamento !== "string") throw new HttpError(400, "Forma de pagamento inválida.");
    data.forma_pagamento = body.forma_pagamento?.trim().slice(0, 50) || null;
  } else if (!partial) data.forma_pagamento = null;
  return data;
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) throw new HttpError(401, "Faça login para continuar.");
    const { user } = await runSupabase(supabase.auth.getUser(token));
    if (!user) throw new HttpError(401, "Sessão inválida. Entre novamente.");
    req.user = user;
    req.userToken = token;
    next();
  } catch (error) { next(error); }
}

function userClient(token) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// Autenticação
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const email = validEmail(req.body.email);
    const password = requiredString(req.body.password, "Senha", 128);
    if (password.length < 8) throw new HttpError(400, "A senha deve ter pelo menos 8 caracteres.");
    const data = await runSupabase(supabase.auth.signUp({ email, password }));
    res.status(201).json({ user: data.user, session: data.session, message: data.session ? "Cadastro realizado." : "Cadastro realizado. Verifique seu e-mail para confirmar a conta." });
  } catch (e) { next(e); }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = validEmail(req.body.email);
    const password = requiredString(req.body.password, "Senha", 128);
    const data = await runSupabase(supabase.auth.signInWithPassword({ email, password }));
    res.json({ user: data.user, session: data.session });
  } catch (e) { next(e); }
});

app.post("/api/auth/logout", authRequired, async (req, res, next) => {
  try {
    await runSupabase(userClient(req.userToken).auth.signOut());
    res.json({ message: "Você saiu da sua conta." });
  } catch (e) { next(e); }
});

app.post("/api/auth/forgot-password", async (req, res, next) => {
  try {
    const email = validEmail(req.body.email);
    const redirectTo = process.env.PASSWORD_RESET_REDIRECT || `${req.headers.origin || ""}/`;
    const data = await runSupabase(supabase.auth.resetPasswordForEmail(email, { redirectTo }));
    res.json({ message: "Se o endereço estiver cadastrado, você receberá as instruções de recuperação.", data });
  } catch (e) { next(e); }
});

app.post("/api/auth/reset-password", authRequired, async (req, res, next) => {
  try {
    const password = requiredString(req.body.password, "Nova senha", 128);
    if (password.length < 8) throw new HttpError(400, "A nova senha deve ter pelo menos 8 caracteres.");
    const data = await runSupabase(userClient(req.userToken).auth.updateUser({ password }));
    res.json({ user: data.user, message: "Senha redefinida com sucesso." });
  } catch (e) { next(e); }
});

app.post("/api/auth/refresh", async (req, res, next) => {
  try {
    const refresh_token = requiredString(req.body.refresh_token, "Token de renovação", 2048);
    const data = await runSupabase(supabase.auth.refreshSession({ refresh_token }));
    res.json({ user: data.user, session: data.session });
  } catch (e) { next(e); }
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email } });
});

// Transações: RLS é aplicada porque o JWT do usuário acompanha cada consulta.
app.get("/api/transacoes", authRequired, async (req, res, next) => {
  try {
    const db = userClient(req.userToken);
    let query = db.from("transacoes").select("*").order("data", { ascending: false }).order("created_at", { ascending: false });
    if (req.query.tipo && ["receita", "despesa"].includes(req.query.tipo)) query = query.eq("tipo", req.query.tipo);
    if (req.query.categoria) query = query.eq("categoria", String(req.query.categoria).slice(0, 100));
    if (req.query.inicio) query = query.gte("data", String(req.query.inicio));
    if (req.query.fim) query = query.lte("data", String(req.query.fim));
    if (req.query.busca) query = query.ilike("descricao", `%${String(req.query.busca).replace(/[%_,]/g, "")}%`);
    if (req.query.ordem === "valor") query = query.order("valor", { ascending: req.query.direcao === "asc" });
    const data = await runSupabase(query);
    res.json({ transacoes: data || [] });
  } catch (e) { next(e); }
});

app.post("/api/transacoes", authRequired, async (req, res, next) => {
  try {
    const payload = { ...validateTransaction(req.body), user_id: req.user.id };
    const data = await runSupabase(userClient(req.userToken).from("transacoes").insert(payload).select().single());
    res.status(201).json({ transacao: data });
  } catch (e) { next(e); }
});

app.put("/api/transacoes/:id", authRequired, async (req, res, next) => {
  try {
    const payload = validateTransaction(req.body, true);
    if (!Object.keys(payload).length) throw new HttpError(400, "Informe ao menos um campo para atualizar.");
    payload.updated_at = new Date().toISOString();
    const data = await runSupabase(userClient(req.userToken).from("transacoes").update(payload).eq("id", req.params.id).select().single());
    res.json({ transacao: data });
  } catch (e) { next(e); }
});

app.delete("/api/transacoes/:id", authRequired, async (req, res, next) => {
  try {
    const data = await runSupabase(userClient(req.userToken).from("transacoes").delete().eq("id", req.params.id).select("id").maybeSingle());
    if (!data) throw new HttpError(404, "Transação não encontrada.");
    res.json({ message: "Transação excluída." });
  } catch (e) { next(e); }
});

app.get("/api/dashboard", authRequired, async (req, res, next) => {
  try {
    const rows = await runSupabase(userClient(req.userToken).from("transacoes").select("id,valor,tipo,categoria,data"));
    const transactions = rows || [];
    const receitas = transactions.filter(t => t.tipo === "receita").reduce((s, t) => s + Number(t.valor), 0);
    const despesas = transactions.filter(t => t.tipo === "despesa").reduce((s, t) => s + Number(t.valor), 0);
    const porMes = {};
    const porCategoria = {};
    transactions.forEach(t => {
      const month = String(t.data).slice(0, 7);
      porMes[month] ||= { mes: month, receitas: 0, despesas: 0 };
      porMes[month][t.tipo === "receita" ? "receitas" : "despesas"] += Number(t.valor);
      if (t.tipo === "despesa") porCategoria[t.categoria] = (porCategoria[t.categoria] || 0) + Number(t.valor);
    });
    res.json({
      resumo: { receitas, despesas, saldo: receitas - despesas, quantidade: transactions.length },
      mensal: Object.values(porMes).sort((a, b) => a.mes.localeCompare(b.mes)).slice(-6),
      categorias: Object.entries(porCategoria).map(([categoria, valor]) => ({ categoria, valor })).sort((a, b) => b.valor - a.valor),
    });
  } catch (e) { next(e); }
});

// 404 e tratamento centralizado de erros.
app.use((req, res, next) => next(new HttpError(404, "Rota não encontrada.")));
app.use((error, req, res, next) => {
  const status = error.status || 500;
  if (status >= 500) console.error("Erro na API:", error);
  res.status(status).json({ error: status === 500 ? "Erro interno do servidor." : error.message });
});

// Vercel importa/exporta o app; localmente pode iniciar um servidor.
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`API disponível em http://localhost:${port}`));
}
module.exports = app;
