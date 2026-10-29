import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';

const root = process.cwd();
const port = Number(process.env.PORT || 4173);
const dataDir = path.join(root, 'data');
const usersFile = path.join(dataDir, 'users.json');
const outboxFile = path.join(dataDir, 'outbox.json');
const sessions = new Map();
const resetRequests = new Map();
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000;
let accountDb = null;
const TERMS_VERSION = '2026-10-28';
const VERIFICATION_TTL_MS = 10 * 60 * 1000;
const favorites = ['Denver Broncos', 'Denver Nuggets', 'Los Angeles Angels', 'Anaheim Ducks'];
const teamLeague = Object.fromEntries(Object.entries({
  NFL: 'Arizona Cardinals|Atlanta Falcons|Baltimore Ravens|Buffalo Bills|Carolina Panthers|Chicago Bears|Cincinnati Bengals|Cleveland Browns|Dallas Cowboys|Denver Broncos|Detroit Lions|Green Bay Packers|Houston Texans|Indianapolis Colts|Jacksonville Jaguars|Kansas City Chiefs|Las Vegas Raiders|Los Angeles Chargers|Los Angeles Rams|Miami Dolphins|Minnesota Vikings|New England Patriots|New Orleans Saints|New York Giants|New York Jets|Philadelphia Eagles|Pittsburgh Steelers|San Francisco 49ers|Seattle Seahawks|Tampa Bay Buccaneers|Tennessee Titans|Washington Commanders'.split('|'),
  NBA: 'Atlanta Hawks|Boston Celtics|Brooklyn Nets|Charlotte Hornets|Chicago Bulls|Cleveland Cavaliers|Dallas Mavericks|Denver Nuggets|Detroit Pistons|Golden State Warriors|Houston Rockets|Indiana Pacers|Los Angeles Clippers|Los Angeles Lakers|Memphis Grizzlies|Miami Heat|Milwaukee Bucks|Minnesota Timberwolves|New Orleans Pelicans|New York Knicks|Oklahoma City Thunder|Orlando Magic|Philadelphia 76ers|Phoenix Suns|Portland Trail Blazers|Sacramento Kings|San Antonio Spurs|Toronto Raptors|Utah Jazz|Washington Wizards'.split('|'),
  MLB: 'Arizona Diamondbacks|Atlanta Braves|Baltimore Orioles|Boston Red Sox|Chicago Cubs|Chicago White Sox|Cincinnati Reds|Cleveland Guardians|Colorado Rockies|Detroit Tigers|Houston Astros|Kansas City Royals|Los Angeles Angels|Los Angeles Dodgers|Miami Marlins|Milwaukee Brewers|Minnesota Twins|New York Mets|New York Yankees|Oakland Athletics|Philadelphia Phillies|Pittsburgh Pirates|San Diego Padres|San Francisco Giants|Seattle Mariners|St. Louis Cardinals|Tampa Bay Rays|Texas Rangers|Toronto Blue Jays|Washington Nationals'.split('|'),
  NHL: 'Anaheim Ducks|Boston Bruins|Buffalo Sabres|Calgary Flames|Carolina Hurricanes|Chicago Blackhawks|Colorado Avalanche|Columbus Blue Jackets|Dallas Stars|Detroit Red Wings|Edmonton Oilers|Florida Panthers|Los Angeles Kings|Minnesota Wild|Montreal Canadiens|Nashville Predators|New Jersey Devils|New York Islanders|New York Rangers|Ottawa Senators|Philadelphia Flyers|Pittsburgh Penguins|San Jose Sharks|Seattle Kraken|St. Louis Blues|Tampa Bay Lightning|Toronto Maple Leafs|Utah Mammoth|Vancouver Canucks|Vegas Golden Knights|Washington Capitals|Winnipeg Jets'.split('|')
}).flatMap(([league, teams]) => teams.map(team => [team, league])));
const fallback = {
  'National Headlines': [['Sports news and live updates', 'ESPN', 'https://www.espn.com/'], ['Today’s top sports stories', 'CBS Sports', 'https://www.cbssports.com/']],
  'Denver Broncos': [['Broncos team news and analysis', 'Mile High Report', 'https://www.milehighreport.com/denver-broncos-news/'], ['Broncos latest coverage', 'DenverBroncos.com', 'https://www.denverbroncos.com/news']],
  'Denver Nuggets': [['Nuggets news and analysis', 'DNVR Sports', 'https://thednvr.com/nuggets/'], ['Nuggets latest coverage', 'NBA.com', 'https://www.nba.com/nuggets/news']],
  'Los Angeles Angels': [['Angels news and analysis', 'MLB.com', 'https://www.mlb.com/angels/news'], ['Angels latest coverage', 'The Athletic', 'https://www.nytimes.com/athletic/mlb/team/angels/']],
  'Anaheim Ducks': [['Ducks news and analysis', 'NHL.com', 'https://www.nhl.com/ducks/news'], ['Ducks latest coverage', 'The Athletic', 'https://www.nytimes.com/athletic/nhl/team/ducks/']]
};

async function readJson(file, fallbackValue) { try { return JSON.parse(await readFile(file, 'utf8')); } catch { return fallbackValue; } }
async function writeJson(file, value) { await mkdir(dataDir, { recursive: true }); await writeFile(file, JSON.stringify(value, null, 2)); }
function userFromRow(row) { return { id: row.id, name: row.name, email: row.email, passwordHash: row.password_hash, updates: row.updates, teams: row.teams, createdAt: new Date(row.created_at).toISOString(), emailVerified: row.email_verified === true, verificationCodeHash: row.verification_code_hash, verificationExpiresAt: row.verification_expires_at ? new Date(row.verification_expires_at).toISOString() : null, verificationAttempts: Number(row.verification_attempts || 0), termsAcceptedAt: row.terms_accepted_at ? new Date(row.terms_accepted_at).toISOString() : null, termsVersion: row.terms_version || null, passwordResetTokenHash: row.password_reset_token_hash || null, passwordResetExpiresAt: row.password_reset_expires_at ? new Date(row.password_reset_expires_at).toISOString() : null }; }
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, updates: user.updates, teams: user.teams }; }
function digestToken(token) { return createHash('sha256').update(String(token)).digest('hex'); }
async function createSession(userId) { const token = randomBytes(32).toString('hex'), expires = new Date(Date.now() + SESSION_TTL_MS).toISOString(); if (accountDb) await accountDb.query('INSERT INTO fanoptic_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token_hash) DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at', [digestToken(token), userId, expires]); else sessions.set(token, userId); return token; }
async function sessionUserId(token) { if (!token) return null; if (accountDb) { const result = await accountDb.query('SELECT user_id FROM fanoptic_sessions WHERE token_hash = $1 AND expires_at > NOW() LIMIT 1', [digestToken(token)]); return result.rows[0]?.user_id || null; } return sessions.get(token) || null; }
async function revokeUserSessions(userId) { if (accountDb) await accountDb.query('DELETE FROM fanoptic_sessions WHERE user_id = $1', [userId]); for (const [token, id] of sessions) if (id === userId) sessions.delete(token); }
async function revokeSession(token) { if (accountDb) await accountDb.query('DELETE FROM fanoptic_sessions WHERE token_hash = $1', [digestToken(token)]); else sessions.delete(token); }
async function initializeAccountStore() {
  if (!process.env.DATABASE_URL) { console.warn('DATABASE_URL is not set; account storage is using the temporary JSON fallback.'); return; }
  const { Pool } = await import('pg');
  accountDb = new Pool({ connectionString: process.env.DATABASE_URL, max: 5, connectionTimeoutMillis: 10000, idleTimeoutMillis: 30000 });
  await accountDb.query("CREATE TABLE IF NOT EXISTS fanoptic_users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, updates BOOLEAN NOT NULL DEFAULT FALSE, teams JSONB NOT NULL DEFAULT '[]'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), email_verified BOOLEAN NOT NULL DEFAULT FALSE, verification_code_hash TEXT, verification_expires_at TIMESTAMPTZ, verification_attempts INTEGER NOT NULL DEFAULT 0, terms_accepted_at TIMESTAMPTZ, terms_version TEXT)");
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS verification_code_hash TEXT');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS verification_attempts INTEGER NOT NULL DEFAULT 0');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS terms_version TEXT');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS password_reset_token_hash TEXT');
  await accountDb.query('ALTER TABLE fanoptic_users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMPTZ');
  await accountDb.query('CREATE TABLE IF NOT EXISTS fanoptic_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES fanoptic_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL)');
  await accountDb.query('CREATE INDEX IF NOT EXISTS fanoptic_sessions_user_id_idx ON fanoptic_sessions(user_id)');
  await accountDb.query('SELECT 1');
  console.log('Account storage connected to PostgreSQL.');
}
async function findUserByEmail(email) { if (accountDb) { const result = await accountDb.query('SELECT * FROM fanoptic_users WHERE email = $1 LIMIT 1', [email]); return result.rows[0] ? userFromRow(result.rows[0]) : null; } return (await readJson(usersFile, [])).find(user => user.email === email) || null; }
async function findUserById(id) { if (accountDb) { const result = await accountDb.query('SELECT * FROM fanoptic_users WHERE id = $1 LIMIT 1', [id]); return result.rows[0] ? userFromRow(result.rows[0]) : null; } return (await readJson(usersFile, [])).find(user => user.id === id) || null; }
async function saveUser(user) {
  if (accountDb) {
    try { await accountDb.query('INSERT INTO fanoptic_users (id, name, email, password_hash, updates, teams, created_at, email_verified, verification_code_hash, verification_expires_at, verification_attempts, terms_accepted_at, terms_version) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13)', [user.id, user.name, user.email, user.passwordHash, user.updates, JSON.stringify(user.teams), user.createdAt, user.emailVerified, user.verificationCodeHash, user.verificationExpiresAt, user.verificationAttempts, user.termsAcceptedAt, user.termsVersion]); return true; }
    catch (error) { if (error.code === '23505') return false; throw error; }
  }
  const users = await readJson(usersFile, []);
  if (users.some(item => item.email === user.email)) return false;
  users.push(user); await writeJson(usersFile, users); return true;
}
async function setPendingVerification(email, codeHash, expiresAt) {
  if (accountDb) { await accountDb.query('UPDATE fanoptic_users SET email_verified = FALSE, verification_code_hash = $2, verification_expires_at = $3, verification_attempts = 0 WHERE email = $1', [email, codeHash, expiresAt]); return; }
  const users = await readJson(usersFile, []), user = users.find(item => item.email === email); if (!user) return;
  user.emailVerified = false; user.verificationCodeHash = codeHash; user.verificationExpiresAt = expiresAt; user.verificationAttempts = 0; await writeJson(usersFile, users);
}
async function addVerificationAttempt(email) {
  if (accountDb) { await accountDb.query('UPDATE fanoptic_users SET verification_attempts = verification_attempts + 1 WHERE email = $1', [email]); return; }
  const users = await readJson(usersFile, []), user = users.find(item => item.email === email); if (!user) return;
  user.verificationAttempts = Number(user.verificationAttempts || 0) + 1; await writeJson(usersFile, users);
}
async function markEmailVerified(email) {
  if (accountDb) { await accountDb.query('UPDATE fanoptic_users SET email_verified = TRUE, verification_code_hash = NULL, verification_expires_at = NULL, verification_attempts = 0 WHERE email = $1', [email]); return; }
  const users = await readJson(usersFile, []), user = users.find(item => item.email === email); if (!user) return;
  user.emailVerified = true; user.verificationCodeHash = null; user.verificationExpiresAt = null; user.verificationAttempts = 0; await writeJson(usersFile, users);
}

async function updateUserRecord(id, patch) {
  if (accountDb) { const fields = [], values = [id]; if (patch.name !== undefined) { values.push(patch.name); fields.push('name = $' + values.length); } if (patch.teams !== undefined) { values.push(JSON.stringify(patch.teams)); fields.push('teams = $' + values.length + '::jsonb'); } if (patch.passwordHash !== undefined) { values.push(patch.passwordHash); fields.push('password_hash = $' + values.length); } if (patch.passwordResetTokenHash !== undefined) { values.push(patch.passwordResetTokenHash); fields.push('password_reset_token_hash = $' + values.length); } if (patch.passwordResetExpiresAt !== undefined) { values.push(patch.passwordResetExpiresAt); fields.push('password_reset_expires_at = $' + values.length); } if (!fields.length) return; await accountDb.query('UPDATE fanoptic_users SET ' + fields.join(', ') + ' WHERE id = $1', values); return; }
  const users = await readJson(usersFile, []), user = users.find(item => item.id === id); if (!user) return; Object.assign(user, patch); await writeJson(usersFile, users);
}
async function findUserByResetToken(token) { const tokenHash = digestToken(token); if (accountDb) { const result = await accountDb.query('SELECT * FROM fanoptic_users WHERE password_reset_token_hash = $1 AND password_reset_expires_at > NOW() LIMIT 1', [tokenHash]); return result.rows[0] ? userFromRow(result.rows[0]) : null; } return (await readJson(usersFile, [])).find(user => user.passwordResetTokenHash === tokenHash && user.passwordResetExpiresAt && new Date(user.passwordResetExpiresAt).getTime() > Date.now()) || null; }
function hash(password, salt = randomBytes(16).toString('hex')) { return salt + ':' + scryptSync(password, salt, 64).toString('hex'); }
function matches(password, stored) { const [salt, hex] = String(stored).split(':'); if (!salt || !hex) return false; const a = Buffer.from(hex, 'hex'), b = scryptSync(password, salt, 64); return a.length === b.length && timingSafeEqual(a, b); }
async function body(req) { let text = ''; for await (const chunk of req) text += chunk; return JSON.parse(text || '{}'); }
function send(res, status, data, type = 'application/json') { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'access-control-allow-origin': '*' }); res.end(type === 'application/json' ? JSON.stringify(data) : data); }

const blockedArticleLanguage = /[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]/u;
const blockedStreamPattern = /\b(?:live\s*)?(?:stream(?:ing)?|tv\s+channel)\b|\b(?:watch|view)\s+(?:live|online|free)\b|\bfull\s+(?:match|game)\b|\b(?:4k|1080p|720p)\b|\billegal\s+stream\b/i;
function normalizedArticleText(value) { return String(value || '').normalize('NFKC').toLowerCase().replace(/[\u200b-\u200f\ufeff]/g, '').replace(/[^a-z0-9]+/g, ' ').trim(); }
function isAllowedArticle(item) { const original = [item.title, item.source, item.link].filter(Boolean).join(' '); const normalized = normalizedArticleText(original); const source = normalizedArticleText(item.source); return !blockedArticleLanguage.test(original) && !blockedStreamPattern.test(normalized) && !source.includes('vantage data centers'); }
function classifySourceName(value) { const s = normalizedArticleText(value); if (['mlb com','nba com','nfl com','nhl com','angels com','denver broncos com','chargers com','therams com'].some(x => s.includes(x))) return 'Official'; if (['orange county register','oc register','los angeles times','la times','denver post','mercury news','san francisco chronicle','knbr','new york post','tampa bay times','boston globe','seattle times','chicago tribune'].some(x => s.includes(x))) return 'Local / beat'; if (['sb nation','fansided','substack','blogspot','the hockey writers','mile high report','true blue la','halos heaven','anaheim calling','dnvr sports'].some(x => s.includes(x))) return 'Independent'; if (['espn','cbs sports','yahoo sports','associated press','ap news','usa today','fox sports','the athletic','sports illustrated','bleacher report'].some(x => s.includes(x))) return 'National'; return 'Other'; } function parseRss(xml, team, league) {
  const strip = s => String(s).replaceAll('<![CDATA[', '').replaceAll(']]>', '').trim();
  const cutoff = Date.now() - 3 * 24 * 60 * 60 * 1000;
  return xml.split('<item>').slice(1).map(part => {
    const b = part.split('</item>')[0];
    const get = t => { const i = b.indexOf('<' + t); if (i < 0) return ''; const openEnd = b.indexOf('>', i), j = b.indexOf('</' + t + '>', openEnd); return openEnd < 0 || j < 0 ? '' : b.slice(openEnd + 1, j); };
    return { team, league, title: strip(get('title')), link: strip(get('link')), source: strip(get('source')) || 'Publisher', sourceType: classifySourceName(strip(get('source')) || 'Publisher'), author: strip(get('dc:creator') || get('author') || get('creator')), date: strip(get('pubDate')) };
  }).filter(x => { const published = Date.parse(x.date); return x.title && x.link && Number.isFinite(published) && published <= Date.now() && published >= cutoff && isAllowedArticle(x); })
    .sort((a, b) => Date.parse(b.date) - Date.parse(a.date)).slice(0, 8);
}
async function articlesFor(team) {
  const league = teamLeague[team] || 'National';
  if (team === 'National Headlines') {
    const queries = [['NFL', '49ers team news site:knbr.com'], ['NFL', 'Cowboys team news'], ['NFL', 'Chiefs team news'], ['NBA', 'Los Angeles Lakers basketball team news'], ['NBA', 'Golden State Warriors basketball team news'], ['NBA', 'Boston Celtics basketball team news'], ['MLB', 'Los Angeles Dodgers baseball team news'], ['MLB', 'New York Yankees baseball team news'], ['MLB', 'Chicago Cubs baseball team news'], ['NHL', 'Toronto Maple Leafs hockey team news'], ['NHL', 'Montreal Canadiens hockey team news'], ['NHL', 'New York Rangers hockey team news']];
    const batches = await Promise.all(queries.map(async pair => { try { const r = await fetch('https://news.google.com/rss/search?q=' + encodeURIComponent(pair[1] + ' when:3d') + '&hl=en-US&gl=US&ceid=US:en'); return r.ok ? parseRss(await r.text(), 'National Headlines', pair[0]) : []; } catch { return []; } }));
    const all = batches.flat(), seen = new Set(), varied = all.filter(a => { if (seen.has(a.source)) return false; seen.add(a.source); return true; }), rest = all.filter(a => !varied.includes(a));
    varied.sort((a, b) => Date.parse(b.date) - Date.parse(a.date)); rest.sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
    return [...varied, ...rest].slice(0, 20);
  }
  try { const sport = leagueSearchTerms[league] || ''; const query = [team, sport, 'team news'].filter(Boolean).join(' ') + ' when:3d'; const r = await fetch('https://news.google.com/rss/search?q=' + encodeURIComponent(query) + '&hl=en-US&gl=US&ceid=US:en'); if (r.ok) return parseRss(await r.text(), team, league).filter(item => articleMatchesTeam(item, team)); } catch {}
  return [];
}

const scoreFeeds = { NFL: ['football', 'nfl'], NBA: ['basketball', 'nba'], MLB: ['baseball', 'mlb'], NHL: ['hockey', 'nhl'] };
function ordinal(n) { const v = Number(n) || 0, mod10 = v % 10, mod100 = v % 100; return v + (mod10 === 1 && mod100 !== 11 ? 'ST' : mod10 === 2 && mod100 !== 12 ? 'ND' : mod10 === 3 && mod100 !== 13 ? 'RD' : 'TH'); }
function normalizeScore(event, league, favoriteTeams = []) {
  const competition = event.competitions?.[0] || {};
  const teams = (competition.competitors || []).map(c => ({ name: c.team?.displayName || c.team?.name || c.name || 'Team', score: c.score ?? '', homeAway: c.homeAway }));
  const away = teams.find(t => t.homeAway === 'away') || teams[0] || { name: 'Away', score: '' }, home = teams.find(t => t.homeAway === 'home') || teams[1] || { name: 'Home', score: '' };
  const state = event.status?.type?.state || 'pre', detail = event.status?.type?.shortDetail || event.status?.type?.detail || '', period = Number(event.status?.period || 0), clock = event.status?.displayClock || '';
  const date = event.date ? new Date(event.date) : new Date();
  const day = date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'America/New_York' }).toUpperCase();
  const time = date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZone: 'America/New_York', timeZoneName: 'short' });
  let phase = 'SCHEDULED';
  if (state === 'post') phase = 'FINAL';
  else if (state === 'in') {
    if (league === 'MLB') { const inning = detail.match(/(Top|Bottom)\s+\d+(?:st|nd|rd|th)/i)?.[0]; phase = inning ? inning.toUpperCase() : (period ? ordinal(period) + ' INNING' : 'LIVE'); }
    else if (league === 'NHL') phase = ordinal(period) + ' PERIOD' + (clock ? ' • ' + clock : '');
    else if (league === 'NFL' || league === 'NBA') phase = ordinal(period) + ' QTR' + (clock ? ' • ' + clock : '');
    else phase = 'LIVE';
  }
  return { live: state === 'in', favorite: favoriteTeams.includes(away.name) || favoriteTeams.includes(home.name), league, away: away.name, home: home.name, day, time, phase, awayScore: String(away.score || ''), homeScore: String(home.score || ''), updated: new Date().toISOString(), timestamp: date.getTime() };
}
async function liveScores(favoriteTeams = []) {
  const batches = await Promise.all(Object.entries(scoreFeeds).map(async ([league, [sport, leagueKey]]) => {
    const base = 'https://site.api.espn.com/apis/site/v2/sports/' + sport + '/' + leagueKey + '/scoreboard';
    const dates = Array.from({ length: 8 }, (_, i) => { const d = new Date(Date.now() + i * 86400000); return d.toISOString().slice(0, 10).replaceAll('-', ''); });
    const urls = [base + '?limit=100', ...dates.slice(1).map(day => base + '?dates=' + day + '&limit=100')];
    const results = await Promise.all(urls.map(async url => { try { const r = await fetch(url); if (!r.ok) return []; const data = await r.json(); return (data.events || []).map(e => Object.assign(normalizeScore(e, league, favoriteTeams), { id: e.id })); } catch { return []; } }));
    const seen = new Set(); return results.flat().filter(g => g.id && !seen.has(g.id) && (seen.add(g.id), true));
  }));
  const rank = g => g.live ? 0 : g.phase === 'SCHEDULED' ? 1 : 2;
  return batches.flat().sort((a, b) => rank(a) - rank(b) || Number(b.favorite) - Number(a.favorite) || Number(a.timestamp) - Number(b.timestamp));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function welcomeMessage(name, cheer) {
  return `Hi ${name},\n\nWelcome to FanOptic, and thank you for joining. \n\nI started FanOptic because being a sports fan shouldn’t mean sorting through endless headlines. You should be able to open one place and quickly find the stories, reporters, and updates connected to the teams you care about. \n\nFanOptic is based in San Francisco and was created to make it easier for fans to stay close to their favorite teams. It’s free to use, and it will stay that way. \n\nThank you for being part of FanOptic’s growth. We’re grateful you’re here and excited for what’s next. \n\nGo ${cheer}! \n\n—Rene\n\nFounder, FanOptic\n\nSan Francisco, CA`;
} function pickCheer(teams) {

  const allowed = (Array.isArray(teams) ? teams : []).filter(t => !['Las Vegas Raiders', 'Los Angeles Dodgers', 'Kansas City Chiefs', 'Los Angeles Chargers'].includes(t));
  return allowed.length ? allowed[Math.floor(Math.random() * allowed.length)] : 'sports';
}
async function sendProviderEmail({ to, subject, text, html }) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM || process.env.EMAIL_FROM;
  if (!key || !from) {
    console.error('[email] sender configuration missing', { missing: !key ? 'RESEND_API_KEY' : 'RESEND_FROM' });
    return { sent: false, reason: 'sender_configuration_missing' };
  }
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to, subject, text, html })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const code = String(data.name || data.code || 'provider_rejected').slice(0, 80);
      console.error('[email] Resend rejected request', { status: response.status, code });
      return { sent: false, status: response.status, reason: 'provider_rejected' };
    }
    console.log('[email] Resend accepted request', { status: response.status, id: data.id || null });
    return { sent: true, status: response.status, id: data.id || null };
  } catch (error) {
    console.error('[email] provider request failed', { name: error?.name || 'Error' });
    return { sent: false, reason: 'provider_request_failed' };
  }
}
async function sendVerificationEmail({ to, name, code }) {
  const safeName = escapeHtml(name);
  const text = 'Hi ' + name + ', your FanOptic verification code is ' + code + '. It expires in 10 minutes. If you did not request this, you can ignore this email. Terms: https://fanoptic-sportsdesk.com/terms.html Privacy: https://fanoptic-sportsdesk.com/privacy.html';
  const html = '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;color:#10251d"><h1 style="color:#9b7624">FANOPTIC</h1><p>Hi ' + safeName + ',</p><p>Enter this verification code to finish creating your account:</p><p style="font-size:28px;font-weight:bold;letter-spacing:7px">' + code + '</p><p>This code expires in 10 minutes. If you did not request it, ignore this email.</p><p><a href="https://fanoptic-sportsdesk.com/terms.html">Terms of Service</a> · <a href="https://fanoptic-sportsdesk.com/privacy.html">Privacy Policy</a></p></div>';
  return sendProviderEmail({ to, subject: 'Your FanOptic verification code', text, html });
}
async function sendPasswordResetEmail({ to, name, token }) {
  const link = 'https://fanoptic-sportsdesk.com/reset-password.html?token=' + encodeURIComponent(token), safeName = escapeHtml(name), safeLink = escapeHtml(link);
  const text = 'Hi ' + name + ', use this link to reset your FanOptic password: ' + link + '\n\nThe link expires in one hour. If you did not request a reset, you can ignore this email.';
  const html = '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;color:#10251d"><h1 style="color:#9b7624">FANOPTIC</h1><p>Hi ' + safeName + ',</p><p>Use this link to choose a new FanOptic password:</p><p><a style="display:inline-block;padding:12px 18px;background:#d7a84b;color:#182019;text-decoration:none;font-weight:bold" href="' + safeLink + '">Reset password</a></p><p>This link expires in one hour. If you did not request a reset, ignore this email.</p></div>';
  return sendProviderEmail({ to, subject: 'Reset your FanOptic password', text, html });
}
async function sendWelcomeEmail({ to, name, teams }) {
  const cheer = pickCheer(teams), text = welcomeMessage(name, cheer), safeName = escapeHtml(name), safeCheer = escapeHtml(cheer);
  const html = '<!doctype html><html><body style="margin:0;padding:0;background-color:#f3ead7;">' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f3ead7;"><tr><td align="center" style="padding:32px 16px;">' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;background-color:#10251d;border:1px solid #d7a84b;border-radius:14px;">' +
    '<tr><td style="padding:32px 36px 22px;border-bottom:1px solid #42634f;"><div style="font-family:Georgia,Times New Roman,serif;font-size:30px;font-weight:700;letter-spacing:5px;color:#d7a84b;">FANOPTIC</div><div style="margin-top:8px;font-family:Arial,sans-serif;font-size:11px;letter-spacing:2px;color:#d9dfd5;">PERSONALIZED SPORTS COVERAGE</div></td></tr>' +
    '<tr><td style="padding:30px 36px 34px;font-family:Arial,sans-serif;font-size:16px;line-height:1.7;color:#f3ead7;">' +
    '<p style="margin:0 0 18px;">Hi ' + safeName + ',</p>' +
    '<p style="margin:0 0 18px;">Welcome to FanOptic, and thank you for joining.</p>' +
    '<p style="margin:0 0 18px;">I started FanOptic because being a sports fan shouldn’t mean sorting through endless headlines. You should be able to open one place and quickly find the stories, reporters, and updates connected to the teams you care about.</p>' +
    '<p style="margin:0 0 18px;">FanOptic is based in San Francisco and was created to make it easier for fans to stay close to their favorite teams. It’s free to use, and it will stay that way.</p>' +
    '<p style="margin:0 0 22px;">Thank you for being part of FanOptic’s growth. We’re grateful you’re here and excited for what’s next.</p>' +
    '<p style="margin:0 0 22px;">Go <strong style="color:#d7a84b;">' + safeCheer + '</strong>!</p>' +
    '<p style="margin:0;">—Rene<br><strong>Founder, FanOptic</strong><br>San Francisco, CA</p></td></tr>' +
    '<tr><td style="padding:16px 36px;border-top:1px solid #42634f;font-family:Arial,sans-serif;font-size:11px;letter-spacing:1px;color:#c4cec2;">FANOPTIC · PERSONALIZED SPORTS COVERAGE</td></tr></table></td></tr></table></body></html>';
  return sendProviderEmail({ to, subject: 'Welcome to FanOptic!', text, html });
}
async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'POST' && url.pathname === '/api/signup') {
    const b = await body(req), name = String(b.name || '').trim(), email = String(b.email || '').trim().toLowerCase(), password = String(b.password || '');
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) return send(res, 400, { error: 'Enter a valid email, your name, and a password with at least 8 characters.' });
    if (b.termsAccepted !== true) return send(res, 400, { error: 'Accept the Terms of Service and acknowledge the Privacy Policy to create an account.' });
    if (await findUserByEmail(email)) return send(res, 409, { error: 'An account with that email already exists.' });
    const now = new Date(), code = String(randomInt(100000, 1000000)), expiresAt = new Date(now.getTime() + VERIFICATION_TTL_MS).toISOString();
    const user = { id: randomBytes(16).toString('hex'), name, email, passwordHash: hash(password), updates: Boolean(b.updates), teams: Array.isArray(b.teams) && b.teams.length ? b.teams : favorites, createdAt: now.toISOString(), emailVerified: false, verificationCodeHash: hash('fanoptic-code:' + code), verificationExpiresAt: expiresAt, verificationAttempts: 0, termsAcceptedAt: now.toISOString(), termsVersion: TERMS_VERSION };
    if (!(await saveUser(user))) return send(res, 409, { error: 'An account with that email already exists.' });
    const emailStatus = await sendVerificationEmail({ to: email, name, code });
    return send(res, emailStatus.sent ? 201 : 503, { requiresVerification: true, emailStatus, error: emailStatus.sent ? undefined : 'Your signup is saved, but the verification email could not be sent. Check the message and use Resend code to try again.' });
  }
  if (req.method === 'POST' && url.pathname === '/api/resend-verification') {
    const b = await body(req), email = String(b.email || '').trim().toLowerCase(), password = String(b.password || ''), user = await findUserByEmail(email);
    if (!user || user.emailVerified || !matches(password, user.passwordHash)) return send(res, 200, { ok: true });
    const lastSentAt = user.verificationExpiresAt ? new Date(user.verificationExpiresAt).getTime() - VERIFICATION_TTL_MS : 0;
    if (Date.now() - lastSentAt < 60000) return send(res, 429, { error: 'Wait one minute before requesting another code.' });
    const code = String(randomInt(100000, 1000000)), expiresAt = new Date(Date.now() + VERIFICATION_TTL_MS).toISOString();
    await setPendingVerification(email, hash('fanoptic-code:' + code), expiresAt);
    const emailStatus = await sendVerificationEmail({ to: email, name: user.name, code });
    return send(res, emailStatus.sent ? 200 : 503, emailStatus.sent ? { ok: true } : { error: 'The verification email could not be sent. Try again in a minute.', emailStatus });
  }
  if (req.method === 'POST' && url.pathname === '/api/verify-email') {
    const b = await body(req), email = String(b.email || '').trim().toLowerCase(), code = String(b.code || '').trim(), user = await findUserByEmail(email);
    if (!/^\d{6}$/.test(code) || !user || user.emailVerified || !user.verificationCodeHash) return send(res, 400, { error: 'That code is invalid or expired. Request a new one and try again.' });
    if (Number(user.verificationAttempts || 0) >= 5) return send(res, 429, { error: 'Too many attempts. Request a new code and try again.' });
    if (!user.verificationExpiresAt || new Date(user.verificationExpiresAt).getTime() < Date.now()) return send(res, 400, { error: 'That code has expired. Request a new one and try again.' });
    if (!matches('fanoptic-code:' + code, user.verificationCodeHash)) { await addVerificationAttempt(email); return send(res, 400, { error: 'That code is incorrect. Check it and try again.' }); }
    await markEmailVerified(email);
    const verifiedUser = await findUserByEmail(email), token = randomBytes(32).toString('hex');
    const sessionToken = await createSession(verifiedUser.id);
    const emailStatus = await sendWelcomeEmail({ to: verifiedUser.email, name: verifiedUser.name, teams: verifiedUser.teams });
    return send(res, 200, { user: publicUser(verifiedUser), token: sessionToken, emailStatus });
  }
  if (req.method === 'POST' && url.pathname === '/api/login') {
    const b = await body(req), email = String(b.email || '').trim().toLowerCase(), user = await findUserByEmail(email);
    if (!user || !matches(String(b.password || ''), user.passwordHash)) return send(res, 401, { error: 'Email or password is incorrect.' });
    if (!user.emailVerified) return send(res, 403, { error: 'Verify your email before logging in.', requiresVerification: true });
    const token = await createSession(user.id);
    return send(res, 200, { user: publicUser(user), token });
  }
  if (req.method === 'GET' && url.pathname === '/api/me') {
    const auth = String(req.headers.authorization || ''), token = auth.startsWith('Bearer ') ? auth.slice(7) : auth, id = await sessionUserId(token), user = id ? await findUserById(id) : null;
    return send(res, user ? 200 : 401, user ? { user: publicUser(user) } : { error: 'Not signed in' });
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') { const auth = String(req.headers.authorization || ''), token = auth.startsWith('Bearer ') ? auth.slice(7) : auth; if (token) await revokeSession(token); return send(res, 200, { ok: true }); }
  if (req.method === 'PATCH' && url.pathname === '/api/account') {
    const auth = String(req.headers.authorization || ''), token = auth.startsWith('Bearer ') ? auth.slice(7) : auth, id = await sessionUserId(token), user = id ? await findUserById(id) : null;
    if (!user) return send(res, 401, { error: 'Please log in again to manage your account.' });
    const b = await body(req), name = String(b.name || '').trim(), teams = Array.isArray(b.teams) ? [...new Set(b.teams.filter(t => typeof t === 'string' && teamLeague[t]))] : null;
    if (!name || name.length > 80 || !teams || !teams.length) return send(res, 400, { error: 'Enter a name and choose at least one valid team.' });
    await updateUserRecord(id, { name, teams }); const updatedUser = await findUserById(id); return send(res, 200, { user: publicUser(updatedUser) });
  }
  if (req.method === 'POST' && url.pathname === '/api/account/password') {
    const auth = String(req.headers.authorization || ''), token = auth.startsWith('Bearer ') ? auth.slice(7) : auth, id = await sessionUserId(token), user = id ? await findUserById(id) : null;
    if (!user) return send(res, 401, { error: 'Please log in again to manage your account.' });
    const b = await body(req), currentPassword = String(b.currentPassword || ''), newPassword = String(b.newPassword || '');
    if (!matches(currentPassword, user.passwordHash)) return send(res, 400, { error: 'Current password is incorrect.' });
    if (newPassword.length < 8) return send(res, 400, { error: 'Your new password must be at least 8 characters.' });
    await updateUserRecord(id, { passwordHash: hash(newPassword), passwordResetTokenHash: null, passwordResetExpiresAt: null }); return send(res, 200, { ok: true });
  }
  if (req.method === 'DELETE' && url.pathname === '/api/account') {
    const auth = String(req.headers.authorization || ''), token = auth.startsWith('Bearer ') ? auth.slice(7) : auth, id = await sessionUserId(token), user = id ? await findUserById(id) : null;
    if (!user) return send(res, 401, { error: 'Please log in again to manage your account.' });
    const b = await body(req); if (!matches(String(b.password || ''), user.passwordHash)) return send(res, 400, { error: 'Enter your current password to delete this account.' });
    if (accountDb) await accountDb.query('DELETE FROM fanoptic_users WHERE id = $1', [id]); else { const users = await readJson(usersFile, []); await writeJson(usersFile, users.filter(item => item.id !== id)); }
    await revokeUserSessions(id); return send(res, 200, { ok: true });
  }
  if (req.method === 'POST' && url.pathname === '/api/password-reset/request') {
    const b = await body(req), email = String(b.email || '').trim().toLowerCase(), last = resetRequests.get(email) || 0;
    if (Date.now() - last < 60000) return send(res, 200, { ok: true }); resetRequests.set(email, Date.now());
    const user = await findUserByEmail(email); if (user) { const token = randomBytes(32).toString('hex'), expires = new Date(Date.now() + PASSWORD_RESET_TTL_MS).toISOString(); await updateUserRecord(user.id, { passwordResetTokenHash: digestToken(token), passwordResetExpiresAt: expires }); const status = await sendPasswordResetEmail({ to: user.email, name: user.name, token }); if (!status.sent) console.error('[password-reset] email could not be sent'); }
    return send(res, 200, { ok: true, message: 'If an account matches that email, a password reset link will be sent.' });
  }
  if (req.method === 'POST' && url.pathname === '/api/password-reset/complete') {
    const b = await body(req), token = String(b.token || ''), password = String(b.password || ''), user = token ? await findUserByResetToken(token) : null;
    if (password.length < 8) return send(res, 400, { error: 'Your new password must be at least 8 characters.' });
    if (!user) return send(res, 400, { error: 'This reset link is invalid or expired. Request another one.' });
    await updateUserRecord(user.id, { passwordHash: hash(password), passwordResetTokenHash: null, passwordResetExpiresAt: null }); await revokeUserSessions(user.id);
    return send(res, 200, { ok: true, message: 'Password updated. You can now log in.' });
  }
  if (req.method === 'GET' && url.pathname === '/api/articles') {
    const isDiscovery = url.searchParams.get('mode') === 'discover'; const teams = isDiscovery ? ['National Headlines'] : (url.searchParams.get('teams') || favorites.join(',')).split(',').map(x => x.trim()).filter(Boolean); const articles = (await Promise.all(teams.map(articlesFor))).flat();
    return send(res, 200, { updatedAt: new Date().toISOString(), articles });
  }
  if (req.method === 'GET' && url.pathname === '/api/scores') {
    const favoriteTeams = (url.searchParams.get('teams') || '').split(',').map(team => team.trim()).filter(Boolean);
    const games = await liveScores(favoriteTeams); return send(res, 200, { updatedAt: new Date().toISOString(), source: 'ESPN', games });
  }
  if (req.method === 'POST' && url.pathname === '/api/analytics') {
    const file = path.join(dataDir, 'analytics.json'), events = await readJson(file, []), b = await body(req);
    events.push({ event: b.event || 'unknown', metadata: b.metadata || {}, createdAt: new Date().toISOString() }); await writeJson(file, events);
    return send(res, 204, '', 'text/plain');
  }
  if (req.method === 'GET' && url.pathname === '/api/admin/analytics') {
    if ((url.searchParams.get('key') || '') !== (process.env.ADMIN_KEY || 'fanoptic-dev')) return send(res, 401, { error: 'Unauthorized' });
    const events = await readJson(path.join(dataDir, 'analytics.json'), []), count = e => events.filter(x => x.event === e).length;
    return send(res, 200, { totalEvents: events.length, accountsCreated: count('account_created'), articleClicks: count('article_clicked'), searches: count('search_used'), recent: events.slice(-25).reverse() });
  }
  let file = url.pathname === '/' ? 'index.html' : url.pathname === '/admin' ? 'admin.html' : url.pathname.startsWith('/') ? url.pathname.slice(1) : url.pathname;
  if (!file.includes('..')) { try { return send(res, 200, await readFile(path.join(root, 'public', file)), file.endsWith('.html') ? 'text/html' : 'text/plain'); } catch {} }
  send(res, 404, { error: 'Not found' });
}
await initializeAccountStore();
http.createServer((req, res) => handler(req, res).catch(() => send(res, 500, { error: 'Server error' }))).listen(port, () => console.log('FanOptic running on ' + port));
