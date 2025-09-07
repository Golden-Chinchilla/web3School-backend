// worker.ts - Cloudflare Worker (ethers.js v6 + personal_sign 验签)
import { ethers } from 'ethers';

export interface Env {
	COURSES: KVNamespace;
	ERC1155_ADDRESS: string;
	RPC_URL: string;
	SECRET: string;
}

type CourseMeta = {
	courseId: number;
	title: string;
	description: string;
	videoUrl: string;
	author: `0x${string}`;
	price: string;                 // wei (string)
	tokenAddress: `0x${string}`;   // ERC20 地址
	createdAt: number;
	status: 'active' | 'inactive';
};

const json = (data: unknown, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: { 'content-type': 'application/json' },
	});

function withCORS(res: Response) {
	const r = new Response(res.body, res);
	r.headers.set('Access-Control-Allow-Origin', '*');
	r.headers.set('Access-Control-Allow-Headers', 'content-type,authorization');
	r.headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
	return r;
}

async function signToken(secret: string, payload: object) {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
	const body = btoa(JSON.stringify(payload));
	const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
	const sig = btoa(String.fromCharCode(...new Uint8Array(mac)));
	return `${body}.${sig}`;
}
async function verifyToken(secret: string, token: string) {
	const [body, sig] = token.split('.');
	if (!body || !sig) return null;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
	const ok = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), encoder.encode(body));
	if (!ok) return null;
	return JSON.parse(atob(body));
}

// message 解析
function parseSignedMessage(msg: string) {
	const lines = msg.split('\n').map(s => s.trim());
	if (lines[0] !== 'web3u:play') return null;
	const kv: Record<string, string> = {};
	for (let i = 1; i < lines.length; i++) {
		const [k, v] = lines[i].split('=');
		if (k && v) kv[k] = v;
	}
	if (!kv.addr || !kv.courseId || !kv.ts || !kv.nonce) return null;
	return {
		addr: ethers.getAddress(kv.addr as `0x${string}`),
		courseId: Number(kv.courseId),
		ts: Number(kv.ts),
		nonce: kv.nonce,
	};
}

const ERC1155_ABI = ['function balanceOf(address account, uint256 id) view returns (uint256)'];
async function check1155Holding(env: Env, owner: `0x${string}`, courseId: number) {
	const provider = new ethers.JsonRpcProvider(env.RPC_URL);
	const erc1155 = new ethers.Contract(env.ERC1155_ADDRESS, ERC1155_ABI, provider);
	const bal: bigint = await erc1155.balanceOf(owner, courseId);
	return bal > 0n;
}
async function verifyPersonalSign(message: string, signature: `0x${string}`): Promise<string> {
	const recovered = ethers.verifyMessage(message, signature);
	return ethers.getAddress(recovered);
}

export default {
	async fetch(request: Request, env: Env) {
		const url = new URL(request.url);
		const { pathname, searchParams } = url;

		if (request.method === 'OPTIONS') {
			return withCORS(new Response(null, { status: 204 }));
		}

		// ===== 课程列表（修复：正确读取 courses:all 索引）=====
		if (request.method === 'GET' && pathname === '/api/courses') {
			const listRaw = await env.COURSES.get('courses:all');
			const ids: number[] = listRaw ? JSON.parse(listRaw) : [];
			const metas: CourseMeta[] = [];
			for (const id of ids) {
				const v = await env.COURSES.get(`course:${id}`);
				if (v) metas.push(JSON.parse(v));
			}
			return withCORS(json({ items: metas }));
		}

		// ===== 课程详情 =====
		if (request.method === 'GET' && pathname.startsWith('/api/courses/')) {
			const id = Number(pathname.split('/').pop());
			const v = await env.COURSES.get(`course:${id}`);
			if (!v) return withCORS(json({ error: 'NOT_FOUND' }, 404));
			return withCORS(json(JSON.parse(v)));
		}

		// ===== 写课程元数据到 KV =====
		if (request.method === 'POST' && pathname === '/api/courses') {
			const meta = (await request.json()) as CourseMeta;
			if (!meta || typeof meta.courseId !== 'number') {
				return withCORS(json({ error: 'BAD_INPUT' }, 400));
			}
			if (!meta.author || !meta.price || !meta.tokenAddress || !meta.videoUrl) {
				return withCORS(json({ error: 'MISSING_FIELDS' }, 400));
			}
			await env.COURSES.put(`course:${meta.courseId}`, JSON.stringify(meta));
			const listRaw = await env.COURSES.get('courses:all');
			const ids: number[] = listRaw ? JSON.parse(listRaw) : [];
			if (!ids.includes(meta.courseId)) {
				ids.unshift(meta.courseId);
				if (ids.length > 200) ids.pop();
				await env.COURSES.put('courses:all', JSON.stringify(ids));
			}
			return withCORS(json({ ok: true }));
		}

		// ===== 签名鉴权 -> 下发播放令牌 =====
		if (request.method === 'POST' && pathname === '/api/auth/issue-play-token') {
			const { courseId, address, message, signature } = await request.json<any>();
			if (!courseId || !address || !message || !signature) {
				return withCORS(json({ error: 'BAD_INPUT' }, 400));
			}
			const parsed = parseSignedMessage(message);
			if (!parsed) return withCORS(json({ error: 'MESSAGE_BAD_FORMAT' }, 400));

			let recovered: `0x${string}`;
			try {
				const r = await verifyPersonalSign(message, signature);
				recovered = ethers.getAddress(r) as `0x${string}`;
			} catch {
				return withCORS(json({ error: 'SIGNATURE_INVALID' }, 401));
			}
			const expectedAddr = ethers.getAddress(address as `0x${string}`);
			if (recovered !== expectedAddr || parsed.addr !== expectedAddr) {
				return withCORS(json({ error: 'ADDRESS_MISMATCH' }, 401));
			}

			const now = Date.now();
			const skew = Math.abs(now - parsed.ts);
			if (skew > 2 * 60 * 1000) {
				return withCORS(json({ error: 'TIMESTAMP_SKEW' }, 400));
			}
			const nonceKey = `nonce:${parsed.nonce}`;
			const seen = await env.COURSES.get(nonceKey);
			if (seen) return withCORS(json({ error: 'NONCE_REUSED' }, 400));
			await env.COURSES.put(nonceKey, '1', { expirationTtl: 10 * 60 });

			if (parsed.courseId !== courseId) {
				return withCORS(json({ error: 'COURSE_MISMATCH' }, 400));
			}
			const hasPass = await check1155Holding(env, expectedAddr, courseId);
			if (!hasPass) return withCORS(json({ error: 'NO_ACCESS' }, 403));

			const exp = Math.floor(now / 1000) + 5 * 60;
			const token = await signToken(env.SECRET, { sub: expectedAddr, courseId, exp });

			return withCORS(json({ token, exp }));
		}

		// ===== 受控代理播放 =====
		if (request.method === 'GET' && pathname === '/api/play') {
			const courseId = Number(searchParams.get('courseId'));
			const token = searchParams.get('token') || '';
			const payload = await verifyToken(env.SECRET, token);
			if (!payload) return withCORS(json({ error: 'TOKEN_BAD' }, 401));
			if (payload.courseId !== courseId) return withCORS(json({ error: 'TOKEN_MISMATCH' }, 401));
			if ((payload.exp as number) < Math.floor(Date.now() / 1000)) {
				return withCORS(json({ error: 'TOKEN_EXPIRED' }, 401));
			}
			const v = await env.COURSES.get(`course:${courseId}`);
			if (!v) return withCORS(json({ error: 'NOT_FOUND' }, 404));
			const meta = JSON.parse(v) as CourseMeta;

			const upstream = await fetch(meta.videoUrl, { method: 'GET' });
			const res = new Response(upstream.body, {
				status: upstream.status,
				headers: {
					'content-type': upstream.headers.get('content-type') || 'video/mp4',
					'cache-control': 'no-store',
				},
			});
			return withCORS(res);
		}

		return withCORS(json({ error: 'NOT_FOUND' }, 404));
	},
};
