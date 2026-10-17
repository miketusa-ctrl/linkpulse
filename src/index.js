import html from '../public/index.html';
import docs from '../public/docs.html';
import js from '../public/app.js.txt';
import css from '../public/style.css';
import action from '../examples/linkpulse-check.yml';
import { createApp } from './app.js';

export { IpQuota } from './lib/ratelimit.js'; // SQLite-backed Durable Object (free plan): per-IP hourly counter

const handle = createApp({ html, docs, js, css, action });
export default { fetch: (req, env, ctx) => handle(req, env, ctx) };
